package com.tapread.nfc.model

import java.util.Date

data class CardData(
    val pan: String?,
    val expiry: Date?,
    val holderName: String?,
    val scheme: String?,
    val aid: String?,
    val aidLabel: String?,
    val track1: String?,
    val track2: String?,
    val atr: String?,
    val atrDescription: String?,
    val applicationCount: Int = 1,
    val allAids: List<AidInfo> = emptyList(),
    val transactions: List<TransactionInfo> = emptyList(),
    // Extended fields
    val serviceCode: String? = null,
    val panSequenceNumber: String? = null,
    val effectiveDate: String? = null,
    val issuerCountryCode: String? = null,
    val currencyCode: String? = null,
    val applicationLabel: String? = null,
    val contactlessStatus: ContactlessStatus = ContactlessStatus.ACTIVE,
    val contactlessStatusDetail: String? = null,
    val aipHex: String? = null,
    val supportsCda: Boolean? = null,
    val cdaExecuted: Boolean? = null,
    val generateAcResult: GenerateAcResult? = null,
    val generateAcStatusWord: String? = null,
    val generateAcDebug: String? = null,
    val cdol1Present: Boolean? = null,
    // DDA / INTERNAL AUTHENTICATE
    val supportsDda: Boolean? = null,
    val internalAuthAttempted: Boolean = false,
    val internalAuthResult: InternalAuthResult? = null,
    val internalAuthStatusWord: String? = null,
    val internalAuthDebug: String? = null,
    // CPLC
    val cplcData: String? = null,
    // Wallet/tokenization
    val walletType: String? = null,       // "Apple Pay", "Google Pay", "Samsung Pay", etc.
    val isTokenized: Boolean = false,     // True if DPAN detected
    // ATC counters read via GET DATA (read-only — does NOT increment the ATC)
    val atc: String? = null,              // 9F36 Application Transaction Counter (current)
    val lastOnlineAtc: String? = null,    // 9F13 Last Online ATC Register
    // Structured EMV diagnostics (AIP/PDOL/AFL decode, full-AFL-read verification, verdict)
    val emvDiagnostics: EmvDiagnostics? = null
) {
    val last4: String get() = pan?.takeLast(4) ?: "????"

    val maskedPan: String get() {
        val p = pan ?: return "••••  ••••  ••••  ••••"
        if (p.length < 8) return p
        val first4 = p.take(4)
        val last4 = p.takeLast(4)
        return "$first4  ••••  ••••  $last4"
    }

    val formattedPan: String get() {
        val p = pan ?: return "••••  ••••  ••••  ••••"
        return p.chunked(4).joinToString("  ")
    }

    val formattedExpiry: String get() {
        val d = expiry ?: return "--/--"
        @Suppress("DEPRECATION")
        val month = String.format("%02d", d.month + 1)
        @Suppress("DEPRECATION")
        val year = String.format("%02d", d.year % 100)
        return "$month/$year"
    }
}

data class AidInfo(
    val aid: String,
    val label: String?,
    val priority: Int?
)

data class TransactionInfo(
    val date: Date?,
    val amount: String?,
    val currency: String?,
    val country: String?,
    val cryptogram: String?,
    val atc: String?,
    val transactionType: String?,
    val time: String? = null,           // Transaction time HH:mm:ss
    val cryptogramType: String? = null  // ARQC, TC, AAC
)

data class GenerateAcResult(
    val cryptogramType: String,
    val cryptogramHex: String?,
    val cidHex: String?,
    val cdaSignatureIncluded: Boolean,   // true when the card returned an SDAD (tag 9F4B)
    val atcHex: String?,
    val rawResponseHex: String?,
    val cdaRequested: Boolean = false,   // whether P1 asked for a CDA signature (0x10 bit)
    val sdadHex: String? = null,         // Signed Dynamic Application Data (9F4B) — CDA evidence
    val unHex: String? = null,           // Unpredictable Number (9F37) sent — needed to verify the SDAD
    val cdaVerification: CdaVerification? = null
)

/**
 * Result of offline CDA verification: recover the Issuer public key from the scheme CA key,
 * recover the ICC public key from the Issuer key, then recover the SDAD (9F4B) with the ICC key
 * and check its hash binds the terminal's Unpredictable Number (proves a fresh, CA-chained
 * signature). The SDAD's internal transaction-data hash is extracted but not recomputed.
 */
data class CdaVerification(
    val attempted: Boolean,
    val overallVerified: Boolean,
    val steps: List<CdaStep> = emptyList(),
    val caRidHex: String? = null,
    val caIndexHex: String? = null,
    val recoveredAcHex: String? = null,          // AC recovered from inside the SDAD
    val iccDynamicNumberHex: String? = null,
    val transactionDataHashHex: String? = null,  // extracted from SDAD, not recomputed
    val summary: String? = null
)

data class CdaStep(
    val name: String,
    val status: CdaStepStatus,
    val detail: String? = null
)

enum class CdaStepStatus { PASS, FAIL, SKIPPED, INFO }

data class InternalAuthResult(
    val challengeHex: String,
    val sdadHex: String?,
    val statusWordHex: String?,
    val rawResponseHex: String?
)

enum class ContactlessStatus {
    ACTIVE,          // Normal read
    DISABLED,        // PPSE returned 6A82 (app removed/disabled)
    BLOCKED,         // PPSE returned 6985 (conditions not satisfied)
    NOT_PAYMENT_CARD // Tag responds but no PPSE
}

// ── Structured EMV diagnostics ──

/**
 * Structured EMV diagnostics for the selected application. Produced by
 * [com.tapread.nfc.util.EmvDiagnosticsAnalyzer.analyze] from the captured APDU log
 * (plus any supplemental READ RECORDs). Its purpose is to distinguish
 * "the card does not support this" from "the app never read the record that proves it".
 */
data class EmvDiagnostics(
    val selectedAid: String?,
    val scheme: String?,
    val gpoFormat: GpoFormat,
    // AIP (both bytes, all documented bits)
    val aipHex: String?,
    val aipFlags: List<AipFlag> = emptyList(),
    // PDOL (9F38) from the SELECT-AID FCI
    val pdolPresent: Boolean = false,
    val pdolItems: List<DolItem> = emptyList(),
    // AFL (94) decoded
    val aflPresent: Boolean = false,
    val aflEntries: List<AflEntry> = emptyList(),
    // AFL traversal verification
    val expectedRecords: List<RecordRef> = emptyList(),
    val recordsReadByLibrary: List<RecordRef> = emptyList(),
    val missingRecords: List<RecordRef> = emptyList(),
    val supplementalReads: List<SupplementalRead> = emptyList(),
    val allAflRecordsRead: Boolean = true,
    // Presence flags across the full response pool
    val presence: TagPresence,
    // Visa / qVSDC: which dynamic tags appear in the GPO response itself
    val isVisaPath: Boolean = false,
    val gpoDynamicTags: List<GpoDynamicTag> = emptyList(),
    // GENERATE AC availability verdict
    val generateAcAvailability: GenerateAcAvailability,
    // Human-readable notes accumulated during analysis
    val notes: List<String> = emptyList()
)

enum class GpoFormat { FORMAT_1, FORMAT_2, UNKNOWN }

data class AipFlag(
    val label: String,
    val byteIndex: Int,   // 1 or 2
    val mask: Int,        // e.g. 0x80
    val set: Boolean
)

data class DolItem(
    val tag: String,      // e.g. "9F02"
    val length: Int,      // bytes
    val name: String      // human name, or "Unknown"
)

data class AflEntry(
    val sfi: Int,             // b0 shr 3
    val firstRecord: Int,     // b1
    val lastRecord: Int,      // b2
    val sdaRecordCount: Int,  // b3
    val rawHex: String        // the 4-byte entry, e.g. "08010100"
)

data class RecordRef(val sfi: Int, val record: Int) {
    fun p1(): Int = record
    fun p2(): Int = (sfi shl 3) or 0x04
}

data class SupplementalRead(
    val ref: RecordRef,
    val statusWordHex: String?,   // e.g. "9000", "6A83"
    val success: Boolean,
    val responseHex: String?      // full response incl. SW, or null on error
)

data class TagPresence(
    val cdol1: Boolean,   // 8C
    val cdol2: Boolean,   // 8D
    val sdad: Boolean,    // 9F4B
    val iccPkCert: Boolean,   // 9F46
    val iccPkExp: Boolean,    // 9F47
    val iccPkRem: Boolean,    // 9F48
    val ddol: Boolean,    // 9F49
    val ac: Boolean,      // 9F26
    val atc: Boolean,     // 9F36
    val psn: Boolean      // 5F34
)

data class GpoDynamicTag(
    val tag: String,      // 9F26,9F27,9F36,9F4B,9F10,9F6C,9F6E
    val name: String,
    val present: Boolean
)

data class GenerateAcAvailability(
    val available: Boolean,
    val reason: String?,   // why (not) available
    val nextStep: String?  // guidance text
)
