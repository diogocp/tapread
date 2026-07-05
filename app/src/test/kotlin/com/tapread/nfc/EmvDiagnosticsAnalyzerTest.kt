package com.tapread.nfc

import com.tapread.nfc.model.ApduEntry
import com.tapread.nfc.model.GpoFormat
import com.tapread.nfc.model.RecordRef
import com.tapread.nfc.model.SupplementalRead
import com.tapread.nfc.util.EmvDiagnosticsAnalyzer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class EmvDiagnosticsAnalyzerTest {

    private fun bytes(hex: String): ByteArray =
        hex.replace(" ", "").chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun entry(cmdHex: String, respHex: String, label: String) =
        ApduEntry(bytes(cmdHex), bytes(respHex), label)

    // ── GPO format detection ──

    @Test fun detectsFormat1() {
        assertEquals(GpoFormat.FORMAT_1, EmvDiagnosticsAnalyzer.detectGpoFormat("80061B80080101009000"))
    }

    @Test fun detectsFormat2() {
        assertEquals(GpoFormat.FORMAT_2, EmvDiagnosticsAnalyzer.detectGpoFormat("770E82021B8094080801010010010301" + "9000"))
    }

    @Test fun detectsUnknownFormat() {
        assertEquals(GpoFormat.UNKNOWN, EmvDiagnosticsAnalyzer.detectGpoFormat("6F0184009000"))
    }

    // ── AIP / AFL extraction, Format 1 vs Format 2 ──

    @Test fun format1_extractsAipAndAfl_positionally() {
        val gpo = "80061B80080101009000"
        assertEquals("1B80", EmvDiagnosticsAnalyzer.extractAip(gpo))
        assertEquals("08010100", EmvDiagnosticsAnalyzer.extractAfl(gpo))
    }

    @Test fun format2_extractsAipAndAfl_viaTlv() {
        val gpo = "770E82027C0094080801010010010301" + "9000"
        assertEquals("7C00", EmvDiagnosticsAnalyzer.extractAip(gpo))
        assertEquals("0801010010010301", EmvDiagnosticsAnalyzer.extractAfl(gpo))
    }

    @Test fun format1_emptyAfl_returnsNull() {
        // 80 02 1B80 9000 — AIP only, no AFL
        assertEquals("1B80", EmvDiagnosticsAnalyzer.extractAip("80021B809000"))
        assertNull(EmvDiagnosticsAnalyzer.extractAfl("80021B809000"))
    }

    // ── AFL decode + expected records ──

    @Test fun decodeAfl_twoEntries() {
        val entries = EmvDiagnosticsAnalyzer.decodeAfl("0801010010010301")
        assertEquals(2, entries.size)
        assertEquals(1, entries[0].sfi)
        assertEquals(1, entries[0].firstRecord)
        assertEquals(1, entries[0].lastRecord)
        assertEquals(0, entries[0].sdaRecordCount)
        assertEquals("08010100", entries[0].rawHex)
        assertEquals(2, entries[1].sfi)
        assertEquals(1, entries[1].firstRecord)
        assertEquals(3, entries[1].lastRecord)
        assertEquals(1, entries[1].sdaRecordCount)
    }

    @Test fun decodeAfl_ignoresTrailingPartialGroup() {
        // 4 bytes + 2 stray bytes → only one full entry
        assertEquals(1, EmvDiagnosticsAnalyzer.decodeAfl("080101001001").size)
    }

    @Test fun expectedRecords_flattensRanges() {
        val entries = EmvDiagnosticsAnalyzer.decodeAfl("0801010010010301")
        val expected = EmvDiagnosticsAnalyzer.expectedRecords(entries)
        assertEquals(
            listOf(RecordRef(1, 1), RecordRef(2, 1), RecordRef(2, 2), RecordRef(2, 3)),
            expected
        )
    }

    @Test fun recordRef_computesReadRecordParams() {
        val ref = RecordRef(sfi = 1, record = 1)
        assertEquals(1, ref.p1())
        assertEquals(0x0C, ref.p2())   // (1 shl 3) or 0x04
    }

    // ── recordsReadByLibrary from command bytes ──

    @Test fun recordsReadByLibrary_parsesSfiReferencedReads() {
        val log = listOf(
            entry("00B2010C00", "70009000", "READ RECORD"),   // SFI 1 rec 1 (P2 0x0C)
            entry("00B2011400", "70009000", "READ RECORD"),   // SFI 2 rec 1 (P2 0x14)
            entry("00A40400", "6F009000", "SELECT")           // ignored
        )
        val read = EmvDiagnosticsAnalyzer.recordsReadByLibrary(log)
        assertTrue(read.contains(RecordRef(1, 1)))
        assertTrue(read.contains(RecordRef(2, 1)))
        assertEquals(2, read.size)
    }

    // ── PDOL parsing ──

    @Test fun parseDol_readsTagLengthPairs() {
        val items = EmvDiagnosticsAnalyzer.parseDol("9F66049F02069F1A02")
        assertEquals(3, items.size)
        assertEquals("9F66", items[0].tag); assertEquals(4, items[0].length)
        assertEquals("9F02", items[1].tag); assertEquals(6, items[1].length)
        assertEquals("9F1A", items[2].tag); assertEquals(2, items[2].length)
    }

    @Test fun extractPdol_findsNestedTagInFci() {
        val fci = "6F148407A0000000031010A5099F38069F66049F02069000"
        val log = listOf(entry("00A40400", fci, "SELECT"))
        assertEquals("9F66049F0206", EmvDiagnosticsAnalyzer.extractPdol(log))
    }

    // ── Presence scan ──

    @Test fun tagPresentInPool_recursesConstructedAndStripsSw() {
        val record = "70045F3401019000"   // 70 { 5F34 01 01 }, SW 9000
        assertTrue(EmvDiagnosticsAnalyzer.tagPresentInPool(listOf(record), "5F34"))
        assertFalse(EmvDiagnosticsAnalyzer.tagPresentInPool(listOf(record), "8C"))
    }

    // ── Visa qVSDC GPO inspection ──

    @Test fun inspectVisaGpo_format1_allAbsent() {
        val result = EmvDiagnosticsAnalyzer.inspectVisaGpo("80061B80080101009000")
        assertTrue(result.all { !it.present })
    }

    @Test fun inspectVisaGpo_format2_findsPresentTags() {
        // 77 { 9F26 08 .... }  → AC present, CID absent
        val gpo = "770B9F26080102030405060708" + "9000"
        val result = EmvDiagnosticsAnalyzer.inspectVisaGpo(gpo)
        assertTrue(result.first { it.tag == "9F26" }.present)
        assertFalse(result.first { it.tag == "9F27" }.present)
    }

    // ── AIP flags + verdict ──

    @Test fun decodeAipFlags_1B80() {
        val flags = EmvDiagnosticsAnalyzer.decodeAipFlags("1B80").associate { it.label to it.set }
        assertFalse(flags["SDA supported"]!!)
        assertFalse(flags["DDA supported"]!!)
        assertTrue(flags["CDA supported"]!!)
        assertTrue(flags["EMV mode supported (contactless)"]!!)
    }

    @Test fun verdict_cdaAdvertisedNoCdol1() {
        val v = EmvDiagnosticsAnalyzer.generateAcVerdict(supportsCda = true, cdol1Present = false, isVisaPath = false)
        assertFalse(v.available)
        assertTrue(v.reason!!.contains("CDOL1"))
        assertTrue(v.nextStep!!.contains("Visa"))
    }

    @Test fun verdict_cdol1Present_available() {
        val v = EmvDiagnosticsAnalyzer.generateAcVerdict(supportsCda = false, cdol1Present = true, isVisaPath = false)
        assertTrue(v.available)
    }

    // ── End-to-end analyze() with a stub supplemental reader ──

    @Test fun analyze_reportsMissingRecordsAndDisabledProbing() {
        val fci = "6F148407A0000000031010A5099F38069F66049F02069000"
        val gpo = "770E82021B8094080801010010010301" + "9000"   // AIP 1B80, AFL 4 records
        val record11 = "70045F3401019000"                        // library read only SFI 1 rec 1
        val log = listOf(
            entry("00A404000E325041592E5359532E444446303100", "6F009000", "SELECT"),  // PPSE
            entry("00A4040007A000000003101000", fci, "SELECT"),                        // SELECT AID (Visa)
            entry("80A8000002830000", gpo, "GET PROCESSING OPTIONS"),
            entry("00B2010C00", record11, "READ RECORD")                              // SFI 1 rec 1
        )

        val diag = EmvDiagnosticsAnalyzer.analyze(
            logEntries = log,
            selectedAid = "A0000000031010",
            activeProbing = false,
            supplementalReader = { ref -> SupplementalRead(ref, "6A83", false, null) }
        )

        assertEquals(GpoFormat.FORMAT_2, diag.gpoFormat)
        assertEquals("Visa", diag.scheme)
        assertTrue(diag.isVisaPath)
        assertTrue(diag.pdolPresent)
        assertEquals(2, diag.pdolItems.size)
        assertEquals(2, diag.aflEntries.size)
        assertEquals(4, diag.expectedRecords.size)
        // Only (1,1) was read by the "library"; (2,1),(2,2),(2,3) are missing
        assertEquals(3, diag.missingRecords.size)
        assertTrue(diag.missingRecords.contains(RecordRef(2, 1)))
        assertFalse(diag.allAflRecordsRead)   // stub reader failed every supplemental read
        assertEquals(3, diag.supplementalReads.size)
        assertTrue(diag.presence.psn)          // 5F34 in record
        assertFalse(diag.presence.cdol1)       // no 8C anywhere
        assertFalse(diag.generateAcAvailability.available)
        assertTrue(diag.notes.any { it.contains("Active EMV probing disabled") })
        assertTrue(diag.notes.any { it.contains("Could not read SFI 2") })
    }

    @Test fun analyze_noGpo_isSafe() {
        val log = listOf(entry("00A40400", "6F009000", "SELECT"))
        val diag = EmvDiagnosticsAnalyzer.analyze(
            logEntries = log,
            selectedAid = null,
            activeProbing = false,
            supplementalReader = { ref -> SupplementalRead(ref, null, false, null) }
        )
        assertEquals(GpoFormat.UNKNOWN, diag.gpoFormat)
        assertFalse(diag.aflPresent)
        assertTrue(diag.allAflRecordsRead)     // vacuously — no expected records
        assertTrue(diag.notes.any { it.contains("No GET PROCESSING OPTIONS") })
    }
}
