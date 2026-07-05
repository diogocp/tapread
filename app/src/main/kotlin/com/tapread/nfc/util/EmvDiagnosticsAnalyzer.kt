package com.tapread.nfc.util

import com.tapread.nfc.model.AflEntry
import com.tapread.nfc.model.AipFlag
import com.tapread.nfc.model.ApduEntry
import com.tapread.nfc.model.DolItem
import com.tapread.nfc.model.EmvDiagnostics
import com.tapread.nfc.model.GenerateAcAvailability
import com.tapread.nfc.model.GpoDynamicTag
import com.tapread.nfc.model.GpoFormat
import com.tapread.nfc.model.RecordRef
import com.tapread.nfc.model.SupplementalRead
import com.tapread.nfc.model.TagPresence

/**
 * Pure (Android-free) analyzer that turns a captured APDU log into structured
 * [EmvDiagnostics]. Its job is to distinguish "the card does not support X" from
 * "the app never read the record that would prove X".
 *
 * Everything here is deterministic and unit-testable except the injected
 * [analyze] `supplementalReader`, which performs the read-only READ RECORDs for any
 * AFL records the underlying library skipped. Tests pass a stub for it.
 *
 * All TLV helpers mirror the private helpers in
 * [com.tapread.nfc.nfc.EmvReader] so behaviour matches exactly.
 */
object EmvDiagnosticsAnalyzer {

    private val VISA_GPO_TAGS = listOf("9F26", "9F27", "9F36", "9F4B", "9F10", "9F6C", "9F6E")

    // ── Public entry point ──

    /**
     * Runs the full diagnostic analysis. The [supplementalReader] is invoked once per
     * missing AFL record and MUST return before this function completes, guaranteeing
     * that read-only supplemental reads happen before any cryptogram command the caller
     * issues afterwards.
     *
     * @param logEntries snapshot of the APDU log AFTER the library read but BEFORE any
     *                   supplemental reads (their responses are appended via the reader).
     */
    fun analyze(
        logEntries: List<ApduEntry>,
        selectedAid: String?,
        activeProbing: Boolean,
        supplementalReader: (RecordRef) -> SupplementalRead
    ): EmvDiagnostics {
        val notes = mutableListOf<String>()

        val gpoHex = logEntries.lastOrNull { it.label == "GET PROCESSING OPTIONS" }
            ?.let { HexUtil.toHex(it.response) }
        val gpoFormat = if (gpoHex != null) detectGpoFormat(gpoHex) else GpoFormat.UNKNOWN
        when {
            gpoHex == null -> notes.add("No GET PROCESSING OPTIONS response found in the APDU log")
            gpoFormat == GpoFormat.UNKNOWN ->
                notes.add("Unrecognized GPO response format (top-level tag is neither 80 nor 77)")
        }

        // AIP
        val aipHex = gpoHex?.let { extractAip(it) }
        val aipFlags = decodeAipFlags(aipHex)
        val supportsCda = aipHex?.let {
            it.length >= 2 && ((it.substring(0, 2).toIntOrNull(16) ?: 0) and 0x02 != 0)
        }

        // AFL
        val aflHex = gpoHex?.let { extractAfl(it) }
        val aflEntries = aflHex?.let { decodeAfl(it) } ?: emptyList()
        if (aflHex != null && aflHex.replace(" ", "").length % 8 != 0) {
            notes.add("AFL length is not a multiple of 4 bytes — trailing bytes ignored")
        }
        for (e in aflEntries) {
            if (e.sfi == 0 || e.sfi == 31) {
                notes.add("AFL entry has an invalid SFI (${e.sfi}, raw ${e.rawHex})")
            }
            if (e.firstRecord == 0 || e.lastRecord < e.firstRecord) {
                notes.add("AFL entry has an invalid record range (${e.firstRecord}..${e.lastRecord}, raw ${e.rawHex})")
            }
        }

        // AFL traversal verification
        val expected = expectedRecords(aflEntries)
        val readByLibrary = recordsReadByLibrary(logEntries)
        val missing = expected.filter { it !in readByLibrary }
        val supplemental = missing.map { supplementalReader(it) }
        for (s in supplemental) {
            if (!s.success) {
                notes.add("Could not read SFI ${s.ref.sfi} record ${s.ref.record}: SW=${s.statusWordHex ?: "none"}")
            }
        }
        val allRead = missing.isEmpty() ||
            missing.all { ref -> supplemental.any { it.ref == ref && it.success } }

        // Presence flags across the full pool (log responses + supplemental responses)
        val pool = buildPool(logEntries, supplemental)
        val presence = TagPresence(
            cdol1 = tagPresentInPool(pool, "8C"),
            cdol2 = tagPresentInPool(pool, "8D"),
            sdad = tagPresentInPool(pool, "9F4B"),
            iccPkCert = tagPresentInPool(pool, "9F46"),
            iccPkExp = tagPresentInPool(pool, "9F47"),
            iccPkRem = tagPresentInPool(pool, "9F48"),
            ddol = tagPresentInPool(pool, "9F49"),
            ac = tagPresentInPool(pool, "9F26"),
            atc = tagPresentInPool(pool, "9F36"),
            psn = tagPresentInPool(pool, "5F34")
        )

        // PDOL (9F38) from the SELECT-AID FCI
        val pdolHex = extractPdol(logEntries)
        val pdolItems = pdolHex?.let { parseDol(it) } ?: emptyList()

        // Scheme + Visa/qVSDC GPO inspection
        val scheme = selectedAid?.let { schemeFromAid(it) }
        val isVisa = scheme.equals("Visa", ignoreCase = true)
        val gpoDynamicTags = if (isVisa) inspectVisaGpo(gpoHex) else emptyList()
        if (isVisa && gpoFormat == GpoFormat.FORMAT_1) {
            notes.add("Visa card returned GPO Format 1 (AIP+AFL only) — no qVSDC dynamic data in GPO; card is on the READ RECORD path")
        }

        // Verdict
        val verdict = generateAcVerdict(supportsCda, presence.cdol1, isVisa)

        if (!activeProbing) {
            notes.add("Active EMV probing disabled — GENERATE AC and INTERNAL AUTHENTICATE not sent")
        }

        return EmvDiagnostics(
            selectedAid = selectedAid,
            scheme = scheme,
            gpoFormat = gpoFormat,
            aipHex = aipHex,
            aipFlags = aipFlags,
            pdolPresent = pdolHex != null,
            pdolItems = pdolItems,
            aflPresent = aflHex != null,
            aflEntries = aflEntries,
            expectedRecords = expected,
            recordsReadByLibrary = readByLibrary.toList(),
            missingRecords = missing,
            supplementalReads = supplemental,
            allAflRecordsRead = allRead,
            presence = presence,
            isVisaPath = isVisa,
            gpoDynamicTags = gpoDynamicTags,
            generateAcAvailability = verdict,
            notes = notes
        )
    }

    // ── GPO format / AIP / AFL extraction (Format 1 vs Format 2) ──

    /** Top-level tag of a GPO response: 80 = Format 1, 77 = Format 2. */
    fun detectGpoFormat(gpoResponseHex: String): GpoFormat {
        val clean = stripSw(gpoResponseHex)
        return when (firstTag(clean)) {
            "80" -> GpoFormat.FORMAT_1
            "77" -> GpoFormat.FORMAT_2
            else -> GpoFormat.UNKNOWN
        }
    }

    /**
     * Extract the AFL hex from a GPO response.
     * Format 1 (primitive tag 80): value = AIP(2 bytes) || AFL(rest) — sliced positionally,
     *   NOT searched, because tag 80 is primitive and contains no inner TLV.
     * Format 2 (constructed tag 77): AFL is the value of tag 94.
     */
    fun extractAfl(gpoResponseHex: String): String? {
        val clean = stripSw(gpoResponseHex)
        return if (firstTag(clean) == "80") {
            val v = topLevelValueOf(clean, "80") ?: return null
            if (v.length < 4) return null
            v.substring(4).ifEmpty { null }
        } else {
            findTagValueInTlv(clean, "94")
        }
    }

    /** Extract the 2-byte AIP (4 hex chars) from a GPO response, handling both formats. */
    fun extractAip(gpoResponseHex: String): String? {
        val clean = stripSw(gpoResponseHex)
        if (firstTag(clean) == "80") {
            topLevelValueOf(clean, "80")?.let { if (it.length >= 4) return it.substring(0, 4) }
        } else {
            findTagValueInTlv(clean, "82")?.let { if (it.length >= 4) return it.substring(0, 4) }
        }
        return null
    }

    /** Decode AFL hex into 4-byte entries; trailing partial groups are ignored. */
    fun decodeAfl(aflHex: String): List<AflEntry> {
        val clean = aflHex.replace(" ", "").uppercase()
        val entries = mutableListOf<AflEntry>()
        var i = 0
        while (i + 8 <= clean.length) {
            val b0 = clean.substring(i, i + 2).toIntOrNull(16) ?: break
            val b1 = clean.substring(i + 2, i + 4).toIntOrNull(16) ?: break
            val b2 = clean.substring(i + 4, i + 6).toIntOrNull(16) ?: break
            val b3 = clean.substring(i + 6, i + 8).toIntOrNull(16) ?: break
            entries.add(
                AflEntry(
                    sfi = b0 shr 3,
                    firstRecord = b1,
                    lastRecord = b2,
                    sdaRecordCount = b3,
                    rawHex = clean.substring(i, i + 8)
                )
            )
            i += 8
        }
        return entries
    }

    /** Flatten AFL entries into the exact expected READ RECORD set. */
    fun expectedRecords(entries: List<AflEntry>): List<RecordRef> {
        val out = mutableListOf<RecordRef>()
        for (e in entries) {
            if (e.firstRecord == 0 || e.lastRecord < e.firstRecord) continue
            for (r in e.firstRecord..e.lastRecord) out.add(RecordRef(e.sfi, r))
        }
        return out
    }

    /** Which (sfi,record) pairs the library actually READ RECORD'd (SFI-referenced reads only). */
    fun recordsReadByLibrary(logEntries: List<ApduEntry>): Set<RecordRef> {
        val set = mutableSetOf<RecordRef>()
        for (entry in logEntries) {
            if (entry.label != "READ RECORD") continue
            val cmd = entry.command
            if (cmd.size < 4) continue
            val p1 = cmd[2].toInt() and 0xFF
            val p2 = cmd[3].toInt() and 0xFF
            if (p2 and 0x07 != 0x04) continue      // only short-file-id referenced reads
            val sfi = (p2 shr 3) and 0x1F
            set.add(RecordRef(sfi, p1))
        }
        return set
    }

    // ── Presence scan ──

    /** Full response pool = all log responses + supplemental read responses (with SW). */
    fun buildPool(logEntries: List<ApduEntry>, supplemental: List<SupplementalRead>): List<String> {
        val pool = mutableListOf<String>()
        for (e in logEntries) if (e.response.size >= 2) pool.add(HexUtil.toHex(e.response))
        for (s in supplemental) s.responseHex?.let { pool.add(it) }
        return pool
    }

    /** True if [tag] appears anywhere in the pool (SW stripped, recurses constructed tags). */
    fun tagPresentInPool(pool: List<String>, tag: String): Boolean {
        val want = tag.uppercase()
        return pool.any { findTagValue(it, want) != null }
    }

    // ── PDOL (9F38) ──

    /** PDOL hex from the last SELECT-AID FCI response that carries tag 9F38. */
    fun extractPdol(logEntries: List<ApduEntry>): String? {
        return logEntries.filter { it.label == "SELECT" }.asReversed()
            .firstNotNullOfOrNull { findTagValue(HexUtil.toHex(it.response), "9F38") }
    }

    /** Parse a DOL (tag-length pairs) into named items. */
    fun parseDol(dolHex: String): List<DolItem> {
        val clean = dolHex.replace(" ", "").uppercase()
        val out = mutableListOf<DolItem>()
        var pos = 0
        while (pos + 4 <= clean.length) {
            val (tag, next) = readTag(clean, pos) ?: break
            if (next + 2 > clean.length) break
            val len = clean.substring(next, next + 2).toIntOrNull(16) ?: break
            out.add(DolItem(tag, len, TlvParser.tagName(tag)))
            pos = next + 2
        }
        return out
    }

    // ── Visa / qVSDC GPO inspection ──

    /**
     * Which qVSDC dynamic tags appear in the GPO response itself.
     * For Format 1 (primitive tag 80) these are never individually encoded, so all
     * report false — that is correct: qVSDC dynamic data is delivered in Format 2 (tag 77).
     */
    fun inspectVisaGpo(gpoResponseHex: String?): List<GpoDynamicTag> {
        if (gpoResponseHex == null) return emptyList()
        val clean = stripSw(gpoResponseHex)
        return VISA_GPO_TAGS.map { tag ->
            GpoDynamicTag(
                tag = tag,
                name = TlvParser.tagName(tag),
                present = findTagValueInTlv(clean, tag) != null
            )
        }
    }

    // ── AIP flag decode (both bytes, all documented bits) ──

    fun decodeAipFlags(aipHex: String?): List<AipFlag> {
        if (aipHex == null || aipHex.length < 4) return emptyList()
        val b1 = aipHex.substring(0, 2).toIntOrNull(16) ?: return emptyList()
        val b2 = aipHex.substring(2, 4).toIntOrNull(16) ?: return emptyList()
        return listOf(
            AipFlag("SDA supported", 1, 0x80, b1 and 0x80 != 0),
            AipFlag("DDA supported", 1, 0x40, b1 and 0x40 != 0),
            AipFlag("Cardholder verification supported", 1, 0x20, b1 and 0x20 != 0),
            AipFlag("Terminal risk management", 1, 0x10, b1 and 0x10 != 0),
            AipFlag("Issuer authentication supported", 1, 0x08, b1 and 0x08 != 0),
            AipFlag("CDA supported", 1, 0x02, b1 and 0x02 != 0),
            AipFlag("EMV mode supported (contactless)", 2, 0x80, b2 and 0x80 != 0),
            AipFlag("Relay resistance / mobile (contactless)", 2, 0x01, b2 and 0x01 != 0)
        )
    }

    // ── GENERATE AC availability verdict ──

    fun generateAcVerdict(
        supportsCda: Boolean?,
        cdol1Present: Boolean,
        isVisaPath: Boolean
    ): GenerateAcAvailability {
        return when {
            cdol1Present -> GenerateAcAvailability(
                available = true,
                reason = "CDOL1 present; generic GENERATE AC (INS 0xAE) can be constructed",
                nextStep = null
            )
            supportsCda == true -> GenerateAcAvailability(
                available = false,
                reason = "cannot build GENERATE AC without CDOL1",
                nextStep = "inspect scheme-specific contactless path or try Visa/qVSDC"
            )
            else -> GenerateAcAvailability(
                available = false,
                reason = "CDOL1 (tag 8C) not found in any record",
                nextStep = if (isVisaPath)
                    "Visa qVSDC delivers its cryptogram (9F26) in the GPO response; no generic GENERATE AC path"
                else
                    "inspect scheme-specific contactless path or try Visa/qVSDC"
            )
        }
    }

    // ── Scheme detection (ported from EmvReader.schemeFromAid) ──

    fun schemeFromAid(aid: String): String? {
        val u = aid.uppercase()
        return when {
            u.startsWith("A000000004") -> "Mastercard"
            u.startsWith("A000000003") -> "Visa"
            u.startsWith("A000000025") -> "Amex"
            u.startsWith("A000000065") -> "JCB"
            u.startsWith("A000000333") -> "UnionPay"
            u.startsWith("A000000152") -> "Discover"
            u.startsWith("A000000615") -> "Mastercard"
            else -> null
        }
    }

    // ── TLV helpers (mirror EmvReader's private helpers) ──

    /** Drop the trailing 2-byte status word if present. */
    private fun stripSw(hexResponse: String): String {
        val clean = hexResponse.replace(" ", "").uppercase()
        return if (clean.length >= 4) clean.dropLast(4) else clean
    }

    private fun firstTag(hex: String): String? = readTag(hex, 0)?.first

    /** Value of a tag found at the TOP level only (no recursion into constructed tags). */
    private fun topLevelValueOf(hex: String, wantTag: String): String? {
        var pos = 0
        while (pos + 4 <= hex.length) {
            val (tag, next) = readTag(hex, pos) ?: break
            val (length, valueStart) = readLength(hex, next) ?: break
            val valueEnd = valueStart + length * 2
            if (valueEnd > hex.length) break
            if (tag == wantTag) return hex.substring(valueStart, valueEnd)
            pos = valueEnd
        }
        return null
    }

    private fun findTagValue(hexResponse: String, tagHex: String): String? {
        return findTagValueInTlv(stripSw(hexResponse), tagHex.uppercase())
    }

    private fun findTagValueInTlv(hex: String, tagHex: String): String? {
        var pos = 0
        while (pos + 4 <= hex.length) {
            val (tag, nextPos) = readTag(hex, pos) ?: break
            val (length, valueStart) = readLength(hex, nextPos) ?: break
            val valueEnd = valueStart + length * 2
            if (valueEnd > hex.length) break

            val value = hex.substring(valueStart, valueEnd)
            if (tag == tagHex) return value
            if (isConstructedTag(tag)) {
                findTagValueInTlv(value, tagHex)?.let { return it }
            }
            pos = valueEnd
        }
        return null
    }

    private fun readTag(hex: String, start: Int): Pair<String, Int>? {
        if (start + 2 > hex.length) return null
        val firstByte = hex.substring(start, start + 2).toIntOrNull(16) ?: return null
        if ((firstByte and 0x1F) != 0x1F) {
            return hex.substring(start, start + 2) to (start + 2)
        }
        var pos = start + 2
        while (pos + 2 <= hex.length) {
            val nextByte = hex.substring(pos, pos + 2).toIntOrNull(16) ?: return null
            pos += 2
            if (nextByte and 0x80 == 0) {
                return hex.substring(start, pos) to pos
            }
        }
        return null
    }

    private fun readLength(hex: String, start: Int): Pair<Int, Int>? {
        if (start + 2 > hex.length) return null
        val lenByte = hex.substring(start, start + 2).toIntOrNull(16) ?: return null
        return when {
            lenByte and 0x80 == 0 -> lenByte to (start + 2)
            lenByte == 0x81 -> {
                if (start + 4 > hex.length) null
                else (hex.substring(start + 2, start + 4).toIntOrNull(16) ?: return null) to (start + 4)
            }
            lenByte == 0x82 -> {
                if (start + 6 > hex.length) null
                else (hex.substring(start + 2, start + 6).toIntOrNull(16) ?: return null) to (start + 6)
            }
            else -> null
        }
    }

    private fun isConstructedTag(tag: String): Boolean {
        return tag.length >= 2 && (((tag.substring(0, 2).toIntOrNull(16) ?: 0) and 0x20) != 0)
    }
}
