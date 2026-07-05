package com.tapread.nfc.ui.detail

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import com.google.android.material.snackbar.Snackbar
import com.tapread.nfc.R
import com.tapread.nfc.databinding.FragmentCardDetailBinding
import com.tapread.nfc.model.CardData
import com.tapread.nfc.model.CdaStepStatus
import com.tapread.nfc.model.CdaVerification
import com.tapread.nfc.model.ContactlessStatus
import com.tapread.nfc.model.EmvDiagnostics
import com.tapread.nfc.model.GpoFormat
import com.tapread.nfc.ui.CardsViewModel
import com.tapread.nfc.util.HapticUtil

class CardDetailFragment : Fragment() {

    private var _binding: FragmentCardDetailBinding? = null
    private val binding get() = _binding!!
    private val viewModel: CardsViewModel by activityViewModels()

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = FragmentCardDetailBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        viewModel.selectedScan.observe(viewLifecycleOwner) { scan ->
            scan?.card?.let { card -> renderCard(card, scan!!.apduLog) }
        }
    }

    private fun renderCard(card: CardData, apduLog: List<com.tapread.nfc.model.ApduEntry>) {
        val maskEnabled = viewModel.maskPan

        // Card face
        binding.textCardPan.text = if (maskEnabled) card.maskedPan else card.formattedPan
        binding.textCardExpiry.text = card.formattedExpiry
        binding.textCardHolder.text = card.holderName ?: "NOT SUPPLIED"
        binding.textCardScheme.text = card.scheme ?: "Unknown"

        // Scheme gradient + brand logo
        val scheme = card.scheme?.lowercase() ?: ""
        when {
            scheme.contains("mastercard") -> {
                binding.cardFaceBackground.setBackgroundResource(R.drawable.bg_card_face_mc)
                binding.imgBrandLogo.setImageResource(R.drawable.ic_mastercard)
                binding.imgBrandLogo.visibility = View.VISIBLE
            }
            scheme.contains("visa") -> {
                binding.cardFaceBackground.setBackgroundResource(R.drawable.bg_card_face_visa)
                binding.imgBrandLogo.setImageResource(R.drawable.ic_visa)
                binding.imgBrandLogo.visibility = View.VISIBLE
            }
            else -> {
                binding.cardFaceBackground.setBackgroundResource(R.drawable.bg_card_face)
                binding.imgBrandLogo.visibility = View.GONE
            }
        }

        // Copy PAN button
        binding.btnCopyPan.visibility = if (card.pan != null) View.VISIBLE else View.GONE
        binding.btnCopyPan.setOnClickListener {
            HapticUtil.tick(it)
            copyToClipboard("Card Number", card.pan ?: "")
        }

        // BIN lookup button
        binding.btnBinLookup.visibility = if (card.pan != null && card.pan.length >= 6) View.VISIBLE else View.GONE
        binding.btnBinLookup.setOnClickListener {
            HapticUtil.tick(it)
            val bin = card.pan?.take(8) ?: card.pan?.take(6) ?: ""
            val url = "https://bincheck.io/details/$bin"
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
        }

        // Contactless warning
        if (card.contactlessStatus != ContactlessStatus.ACTIVE) {
            binding.textContactlessWarning.visibility = View.VISIBLE
            binding.textContactlessWarning.text = card.contactlessStatusDetail
                ?: "NFC is locked on your card or card not activated"
            binding.textContactlessWarning.setBackgroundColor(
                ContextCompat.getColor(requireContext(), R.color.status_warn)
            )
        } else {
            binding.textContactlessWarning.visibility = View.GONE
        }

        // Extended details
        val panDisplay = if (maskEnabled) card.maskedPan else card.formattedPan
        val sb = StringBuilder()

        sb.appendLine("Application number :  ${card.applicationCount}")
        sb.appendLine()

        sb.appendLine("─── Track 1 ──────────────────────")
        sb.appendLine("Expire date    :  ${card.formattedExpiry}")
        sb.appendLine("Card number    :  $panDisplay")
        sb.appendLine("Holder name    :  ${card.holderName ?: "NOT SUPPLIED"}")
        if (card.track1 != null) sb.appendLine("Track 1 raw    :  ${card.track1}")
        sb.appendLine()

        sb.appendLine("─── Track 2 ──────────────────────")
        sb.appendLine("Card number    :  $panDisplay")
        sb.appendLine("Expire date    :  ${card.formattedExpiry}")
        if (card.track2 != null) {
            sb.appendLine("Track 2 raw    :  ${card.track2}")
            // Parse service code from Track 2 (after 'D' separator + expiry)
            val t2clean = card.track2.replace(" ", "")
            val dIdx = t2clean.indexOf("D", ignoreCase = true)
            if (dIdx > 0 && dIdx + 8 <= t2clean.length) {
                val serviceCode = t2clean.substring(dIdx + 5, dIdx + 8)
                if (serviceCode.all { it.isDigit() }) {
                    sb.appendLine("Service code   :  $serviceCode")
                    sb.appendLine("Decoded        :")
                    val decoded = com.tapread.nfc.util.TlvParser.decodeServiceCode(serviceCode)
                    for (line in decoded.split("\n")) {
                        sb.appendLine("  $line")
                    }
                }
            }
        }
        sb.appendLine()

        sb.appendLine("─── AIDs ─────────────────────────")
        if (card.allAids.isNotEmpty()) {
            for (aid in card.allAids) {
                val label = aid.label ?: "Unknown"
                val priority = aid.priority?.let { "Priority %02d".format(it) } ?: ""
                sb.appendLine("${aid.aid}  $label  $priority")
            }
        } else sb.appendLine("No AIDs found")
        sb.appendLine()

        if (!card.aipHex.isNullOrBlank() || card.generateAcResult != null || card.supportsCda != null || card.supportsDda != null) {
            sb.appendLine("─── Offline Authentication ──────")
            if (!card.aipHex.isNullOrBlank()) {
                val aipHex = card.aipHex.uppercase()
                sb.appendLine("AIP            :  $aipHex")
                sb.appendLine("  SDA supported:  ${yesNo(aipFlagSet(aipHex, 0x80))}")
                sb.appendLine("  DDA supported:  ${yesNo(aipFlagSet(aipHex, 0x40))}")
                sb.appendLine("  CDA supported:  ${yesNo(card.supportsCda == true)}")
            } else {
                sb.appendLine("AIP            :  N/A")
                sb.appendLine("  CDA supported:  ${yesNo(card.supportsCda == true)}")
            }
            sb.appendLine()

            sb.appendLine("─── GENERATE AC Result ──────────")
            val generateAc = card.generateAcResult
            sb.appendLine("CDOL1 found     :  ${yesNo(card.cdol1Present == true)}")
            if (generateAc != null) {
                sb.appendLine("Cryptogram type:  ${generateAc.cryptogramType}")
                sb.appendLine("Cryptogram (AC):  ${generateAc.cryptogramHex ?: "N/A"}")
                sb.appendLine("CID            :  ${generateAc.cidHex ?: "N/A"}")
                sb.appendLine("CDA requested  :  ${yesNo(generateAc.cdaRequested)}")
                sb.appendLine("CDA signature  :  ${yesNo(generateAc.cdaSignatureIncluded)}")
                if (generateAc.sdadHex != null) {
                    sb.appendLine("SDAD (9F4B)    :  ${generateAc.sdadHex}")
                } else if (generateAc.cdaRequested) {
                    sb.appendLine("SDAD (9F4B)    :  Not returned (card produced ${generateAc.cryptogramType} without a CDA signature)")
                }
                sb.appendLine("ATC            :  ${generateAc.atcHex ?: "N/A"}")
                sb.appendLine("Status word    :  ${formatStatusWord(card.generateAcStatusWord)}")
                generateAc.cdaVerification?.let { appendCdaVerification(sb, it) }
            } else {
                sb.appendLine("GENERATE AC    :  Not available")
                if (!card.generateAcStatusWord.isNullOrBlank()) {
                    sb.appendLine("Status word    :  ${formatStatusWord(card.generateAcStatusWord)}")
                }
                if (!card.generateAcDebug.isNullOrBlank()) {
                    sb.appendLine("Reason         :  ${card.generateAcDebug}")
                }
                if (card.cdol1Present == true) {
                    sb.appendLine("See APDU Log   :  Check the GENERATE AC exchange")
                }
            }
            sb.appendLine()

            if (card.supportsDda != null) {
                sb.appendLine("─── INTERNAL AUTHENTICATE (DDA) ─")
                sb.appendLine("DDA supported  :  ${yesNo(card.supportsDda == true)}")
                val internalAuth = card.internalAuthResult
                if (internalAuth != null) {
                    sb.appendLine("DDA attempted  :  Yes")
                    sb.appendLine("Challenge sent :  ${internalAuth.challengeHex}")
                    sb.appendLine("SDAD received  :  ${internalAuth.sdadHex ?: "N/A"}")
                    sb.appendLine("Status word    :  ${formatStatusWord(internalAuth.statusWordHex)}")
                } else {
                    sb.appendLine("DDA attempted  :  ${yesNo(card.internalAuthAttempted)}")
                    if (!card.internalAuthStatusWord.isNullOrBlank()) {
                        sb.appendLine("Status word    :  ${formatStatusWord(card.internalAuthStatusWord)}")
                    }
                    if (!card.internalAuthDebug.isNullOrBlank()) {
                        sb.appendLine("Reason         :  ${card.internalAuthDebug}")
                    }
                }
                sb.appendLine()
            }
        }

        // EMV Diagnostics (AIP/PDOL/AFL decode, full-AFL-read verification, verdict)
        card.emvDiagnostics?.let { appendDiagnostics(sb, it) }

        // CVM List — extract tag 8E from APDU log
        val cvmHex = extractTagFromApdu(apduLog, "8E")
        if (cvmHex != null) {
            sb.appendLine("─── CVM (Verification Methods) ───")
            sb.appendLine(com.tapread.nfc.util.TlvParser.decodeCvmList(cvmHex))
            sb.appendLine()
        }

        sb.appendLine("─── Chip (ATR/ATS) ───────────────")
        sb.appendLine("ATS bytes  :  ${card.atr ?: "N/A"}")
        if (!card.atrDescription.isNullOrBlank()) {
            sb.appendLine("Card issuer  :  ${card.atrDescription}")
            sb.appendLine("(possible)")
        }

        if (!card.cplcData.isNullOrBlank()) {
            sb.appendLine()
            sb.appendLine("─── CPLC (Card Production) ───────")
            sb.append(card.cplcData)
        }

        sb.appendLine()
        sb.appendLine()
        sb.appendLine("─── Wallet Detection ─────────────")
        if (card.isTokenized) {
            sb.appendLine("Type     :  📱 ${card.walletType ?: "Tokenized"}")
            sb.appendLine("Card     :  DPAN (Device PAN)")
        } else {
            sb.appendLine("Type     :  Physical Card")
        }

        sb.appendLine()
        sb.appendLine("─── NFC Status ───────────────────")
        when (card.contactlessStatus) {
            ContactlessStatus.ACTIVE -> sb.appendLine("Status  :  ✅ Contactless Active")
            ContactlessStatus.DISABLED -> sb.appendLine("Status  :  ⚠️ NFC Locked / Not Activated")
            ContactlessStatus.BLOCKED -> sb.appendLine("Status  :  ⚠️ Blocked by Issuer")
            ContactlessStatus.NOT_PAYMENT_CARD -> sb.appendLine("Status  :  ℹ️ Not a Payment Card")
        }

        binding.textExtendedDetails.text = sb.toString()

        // Copy extended details button
        binding.btnCopyDetails.setOnClickListener {
            HapticUtil.tick(it)
            copyToClipboard("Card Details", sb.toString())
        }
    }

    private fun copyToClipboard(label: String, text: String) {
        val clipboard = requireContext().getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText(label, text))
        Snackbar.make(requireView(), "$label copied to clipboard", Snackbar.LENGTH_SHORT).show()
    }

    private fun yesNo(value: Boolean): String = if (value) "Yes" else "No"

    /** Render the structured EMV diagnostics block into the monospace details text. */
    private fun appendDiagnostics(sb: StringBuilder, diag: EmvDiagnostics) {
        sb.appendLine("─── EMV Diagnostics ──────────────")
        sb.appendLine("Selected AID   :  ${diag.selectedAid ?: "N/A"}${diag.scheme?.let { "  ($it)" } ?: ""}")
        sb.appendLine("GPO format     :  ${gpoFormatLabel(diag.gpoFormat)}")
        sb.appendLine()

        if (!diag.aipHex.isNullOrBlank()) {
            sb.appendLine("AIP            :  ${diag.aipHex.uppercase()}")
            for (f in diag.aipFlags) {
                sb.appendLine("  ${f.label.padEnd(38)}: ${yesNo(f.set)}")
            }
            sb.appendLine()
        }

        sb.appendLine("PDOL (9F38)    :  ${if (diag.pdolPresent) "Present" else "Not present"}")
        for (item in diag.pdolItems) {
            sb.appendLine("  ${item.tag.padEnd(6)} ${item.length.toString().padStart(2)}  ${item.name}")
        }
        sb.appendLine()

        sb.appendLine("AFL (94)       :  ${if (diag.aflPresent) "Present" else "Not present"}")
        for (e in diag.aflEntries) {
            sb.appendLine("  SFI ${e.sfi}  rec ${e.firstRecord}..${e.lastRecord}  SDA-recs ${e.sdaRecordCount}  [${e.rawHex}]")
        }
        if (diag.aflPresent) {
            sb.appendLine("  Expected records : ${diag.expectedRecords.size}   Read by library : ${diag.recordsReadByLibrary.size}")
            sb.appendLine("  All AFL records read : ${yesNo(diag.allAflRecordsRead)}")
            for (s in diag.supplementalReads) {
                val outcome = if (s.success) "read OK" else "failed"
                sb.appendLine("    supplemental SFI ${s.ref.sfi} rec ${s.ref.record} → ${s.statusWordHex ?: "—"} ($outcome)")
            }
        }
        sb.appendLine()

        sb.appendLine("Tag presence (full record pool):")
        val p = diag.presence
        sb.appendLine("  8C   CDOL1 : ${yesNo(p.cdol1)}      8D   CDOL2 : ${yesNo(p.cdol2)}")
        sb.appendLine("  9F4B SDAD  : ${yesNo(p.sdad)}      9F49 DDOL  : ${yesNo(p.ddol)}")
        sb.appendLine("  9F46/47/48 ICC PK : ${yesNo(p.iccPkCert)}/${yesNo(p.iccPkExp)}/${yesNo(p.iccPkRem)}")
        sb.appendLine("  9F26 AC    : ${yesNo(p.ac)}      9F36 ATC   : ${yesNo(p.atc)}      5F34 PSN : ${yesNo(p.psn)}")
        sb.appendLine()

        if (diag.isVisaPath) {
            sb.appendLine("Visa/qVSDC GPO dynamic data:")
            for (t in diag.gpoDynamicTags) {
                sb.appendLine("  ${t.tag.padEnd(6)} ${t.name.padEnd(34)}: ${yesNo(t.present)}")
            }
            sb.appendLine()
        }

        val v = diag.generateAcAvailability
        sb.appendLine("Generic GENERATE AC: ${if (v.available) "Available" else "Not available"}")
        v.reason?.let { sb.appendLine("  Reason : $it") }
        v.nextStep?.let { sb.appendLine("  Next   : $it") }

        if (diag.notes.isNotEmpty()) {
            sb.appendLine()
            sb.appendLine("Notes:")
            for (n in diag.notes) sb.appendLine("  • $n")
        }
        sb.appendLine()
    }

    /** Render the offline CDA verification result. */
    private fun appendCdaVerification(sb: StringBuilder, v: CdaVerification) {
        sb.appendLine()
        sb.appendLine("─── CDA Verification ────────────")
        if (!v.attempted) {
            sb.appendLine(v.summary ?: "Not attempted")
            return
        }
        sb.appendLine("Result         :  ${if (v.overallVerified) "✅ VERIFIED" else "❌ Not verified"}")
        for (step in v.steps) {
            val glyph = when (step.status) {
                CdaStepStatus.PASS -> "✅"
                CdaStepStatus.FAIL -> "❌"
                CdaStepStatus.SKIPPED -> "⚠️"
                CdaStepStatus.INFO -> "ℹ️"
            }
            sb.appendLine("  $glyph ${step.name}")
            if (!step.detail.isNullOrBlank()) sb.appendLine("       ${step.detail}")
        }
        if (v.recoveredAcHex != null) sb.appendLine("Recovered AC   :  ${v.recoveredAcHex}")
        if (v.iccDynamicNumberHex != null) sb.appendLine("ICC dyn number :  ${v.iccDynamicNumberHex}")
        if (v.transactionDataHashHex != null) sb.appendLine("Txn data hash  :  ${v.transactionDataHashHex}")
        if (!v.summary.isNullOrBlank()) sb.appendLine("Summary        :  ${v.summary}")
    }

    private fun gpoFormatLabel(f: GpoFormat): String = when (f) {
        GpoFormat.FORMAT_1 -> "Format 1 (tag 80)"
        GpoFormat.FORMAT_2 -> "Format 2 (tag 77)"
        GpoFormat.UNKNOWN -> "Unknown"
    }

    private fun formatStatusWord(swHex: String?): String {
        val clean = swHex?.replace(" ", "")?.uppercase().orEmpty()
        return if (clean.length == 4) "${clean.substring(0, 2)} ${clean.substring(2, 4)}" else "N/A"
    }

    private fun aipFlagSet(aipHex: String, mask: Int): Boolean {
        if (aipHex.length < 2) return false
        val byte1 = aipHex.substring(0, 2).toIntOrNull(16) ?: return false
        return byte1 and mask != 0
    }

    /** Extract a specific EMV tag value from the APDU log responses */
    private fun extractTagFromApdu(
        apduLog: List<com.tapread.nfc.model.ApduEntry>,
        tagHex: String
    ): String? {
        val tag = tagHex.uppercase()
        for (entry in apduLog) {
            if (entry.response.size < 6) continue
            val hex = com.tapread.nfc.util.HexUtil.toHex(entry.response).uppercase()
            val pos = hex.indexOf(tag)
            if (pos < 0) continue
            // Read length after tag
            val lenStart = pos + tag.length
            if (lenStart + 2 > hex.length) continue
            val lenByte = hex.substring(lenStart, lenStart + 2).toIntOrNull(16) ?: continue
            val valStart = lenStart + 2
            val valEnd = valStart + lenByte * 2
            if (valEnd <= hex.length) {
                return hex.substring(valStart, valEnd)
            }
        }
        return null
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
