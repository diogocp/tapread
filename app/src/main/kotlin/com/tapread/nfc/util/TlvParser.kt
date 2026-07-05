package com.tapread.nfc.util

/**
 * BER-TLV parser for EMV APDU responses.
 * Parses raw bytes into a tree of tag-length-value nodes.
 */
object TlvParser {

    data class TlvNode(
        val tag: String,
        val tagName: String,
        val length: Int,
        val value: String,
        val children: List<TlvNode> = emptyList(),
        val depth: Int = 0
    )

    /** Parse a hex response string into TLV nodes, stripping a trailing status word. */
    fun parse(hexResponse: String): List<TlvNode> = parseNodes(stripStatusWord(hexResponse), 0)

    private fun parseNodes(hex: String, depth: Int): List<TlvNode> {
        val nodes = mutableListOf<TlvNode>()
        var pos = 0
        while (pos + 2 <= hex.length) {
            val (tag, afterTag) = readTag(hex, pos) ?: break
            val (length, valueStart) = readLength(hex, afterTag) ?: break
            val valueEnd = valueStart + length * 2
            if (valueEnd > hex.length) break
            val value = hex.substring(valueStart, valueEnd)
            val children = if (isConstructed(tag) && value.isNotEmpty()) {
                parseNodes(value, depth + 1)
            } else emptyList()
            nodes.add(TlvNode(tag, EMV_TAGS[tag] ?: "Unknown", length, value, children, depth))
            pos = valueEnd
        }
        return nodes
    }

    // ── Robust BER-TLV primitives + queries (single source of truth) ──

    private fun normalize(hex: String): String = hex.replace(" ", "").replace(":", "").uppercase()

    /** Drop a trailing 2-byte status word (SW1SW2) if present. */
    fun stripStatusWord(hex: String): String {
        val clean = normalize(hex)
        return if (clean.length >= 4) clean.dropLast(4) else clean
    }

    /** True if the tag's first byte marks a constructed data object (bit 6 / 0x20 set). */
    fun isConstructed(tag: String): Boolean =
        tag.length >= 2 && ((tag.substring(0, 2).toIntOrNull(16) ?: 0) and 0x20) != 0

    /** Read a BER tag starting at [start]; returns (tag, indexAfterTag) or null. */
    fun readTag(hex: String, start: Int): Pair<String, Int>? {
        if (start + 2 > hex.length) return null
        val first = hex.substring(start, start + 2).toIntOrNull(16) ?: return null
        if ((first and 0x1F) != 0x1F) return hex.substring(start, start + 2) to (start + 2)
        var pos = start + 2
        while (pos + 2 <= hex.length) {
            val b = hex.substring(pos, pos + 2).toIntOrNull(16) ?: return null
            pos += 2
            if (b and 0x80 == 0) return hex.substring(start, pos) to pos
        }
        return null
    }

    /**
     * Read a BER definite-form length starting at [start]; returns (length, valueStart) or null.
     * Handles short form and long form 0x81..0x84; rejects indefinite (0x80) and absurd lengths.
     */
    fun readLength(hex: String, start: Int): Pair<Int, Int>? {
        if (start + 2 > hex.length) return null
        val first = hex.substring(start, start + 2).toIntOrNull(16) ?: return null
        if (first and 0x80 == 0) return first to (start + 2)      // short form
        val numBytes = first and 0x7F                             // long form: count of length bytes
        if (numBytes == 0 || numBytes > 4) return null            // 0x80 indefinite / too large → reject
        val lenStart = start + 2
        val lenEnd = lenStart + numBytes * 2
        if (lenEnd > hex.length) return null
        val len = hex.substring(lenStart, lenEnd).toIntOrNull(16) ?: return null
        // Reject lengths that would overflow `valueStart + len * 2` (Int) in the walkers,
        // which would otherwise defeat the bounds check and throw on substring.
        if (len < 0 || len > Int.MAX_VALUE / 2) return null
        return len to lenEnd
    }

    /** First top-level tag of a response (status word stripped), or null. */
    fun firstTag(hex: String): String? = readTag(stripStatusWord(hex), 0)?.first

    /** Value (hex) of [tag], searched recursively through constructed objects. SW stripped. */
    fun findValue(hex: String, tag: String): String? = search(stripStatusWord(hex), tag.uppercase())

    /** Value (hex) of [tag] found only at the top level (no recursion). SW stripped. */
    fun topLevelValue(hex: String, tag: String): String? {
        val want = tag.uppercase()
        val data = stripStatusWord(hex)
        var pos = 0
        while (pos + 2 <= data.length) {
            val (t, afterTag) = readTag(data, pos) ?: break
            val (len, valStart) = readLength(data, afterTag) ?: break
            val valEnd = valStart + len * 2
            if (valEnd > data.length) break
            if (t.equals(want, true)) return data.substring(valStart, valEnd)
            pos = valEnd
        }
        return null
    }

    private fun search(data: String, want: String): String? {
        var pos = 0
        while (pos + 2 <= data.length) {
            val (tag, afterTag) = readTag(data, pos) ?: break
            val (len, valStart) = readLength(data, afterTag) ?: break
            val valEnd = valStart + len * 2
            if (valEnd > data.length) break
            val value = data.substring(valStart, valEnd)
            if (tag.equals(want, true)) return value
            if (isConstructed(tag)) search(value, want)?.let { return it }
            pos = valEnd
        }
        return null
    }

    /** Format TLV tree as indented text */
    fun formatTree(nodes: List<TlvNode>, indent: Int = 0): String {
        val sb = StringBuilder()
        for (node in nodes) {
            val prefix = "    ".repeat(indent)
            val valuePreview = if (node.value.length > 40)
                node.value.take(40) + "..." else node.value
            val ascii = tryAscii(node.value)
            val asciiStr = if (ascii != null) " (=$ascii)" else ""

            sb.appendLine("$prefix${node.tag} ${"%02X".format(node.length)} -- ${node.tagName}")
            if (node.children.isEmpty()) {
                sb.appendLine("$prefix    ${formatHexSpaced(valuePreview)}$asciiStr")
            } else {
                sb.append(formatTree(node.children, indent + 1))
            }
        }
        return sb.toString()
    }

    private fun formatHexSpaced(hex: String): String {
        return hex.chunked(2).joinToString(" ")
    }

    private fun tryAscii(hex: String): String? {
        if (hex.length < 2 || hex.length > 64) return null
        val bytes = try {
            hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        } catch (_: Exception) { return null }
        val str = String(bytes, Charsets.US_ASCII)
        return if (str.all { it in ' '..'~' }) str else null
    }

    /** Decode service code (3 digits from Track 2) */
    fun decodeServiceCode(code: String): String {
        if (code.length < 3) return code
        val d1 = when (code[0]) {
            '1' -> "International interchange"
            '2' -> "International + IC chip"
            '5' -> "National interchange"
            '6' -> "National + IC chip"
            '7' -> "Private use"
            else -> "Position 1: ${code[0]}"
        }
        val d2 = when (code[1]) {
            '0' -> "Normal"
            '2' -> "Issuer to be contacted via online"
            '4' -> "Issuer to be contacted via online (unless explicit bilateral)"
            else -> "Position 2: ${code[1]}"
        }
        val d3 = when (code[2]) {
            '0' -> "No restrictions, PIN required"
            '1' -> "No restrictions"
            '2' -> "Goods and services only"
            '3' -> "ATM only, PIN required"
            '4' -> "Cash only"
            '5' -> "Goods and services only, PIN required"
            '6' -> "No restrictions, PIN prompting"
            '7' -> "Goods and services only, PIN prompting"
            else -> "Position 3: ${code[2]}"
        }
        return "$d1\n$d2\n$d3"
    }

    /** Decode CVM (Cardholder Verification Method) list */
    fun decodeCvmList(hex: String): String {
        if (hex.length < 8) return "Raw: $hex"
        val sb = StringBuilder()
        // First 8 chars = amount X, next 8 = amount Y
        var pos = 16 // skip the two amount fields
        var ruleNum = 1
        while (pos + 4 <= hex.length) {
            val cvmCode = hex.substring(pos, pos + 2).toInt(16)
            val condCode = hex.substring(pos + 2, pos + 4).toInt(16)
            val method = when (cvmCode and 0x3F) {
                0x00 -> "Fail CVM processing"
                0x01 -> "Plaintext PIN by ICC"
                0x02 -> "Enciphered PIN online"
                0x03 -> "Plaintext PIN by ICC + signature"
                0x04 -> "Enciphered PIN by ICC"
                0x05 -> "Enciphered PIN by ICC + signature"
                0x1E -> "Signature"
                0x1F -> "No CVM required"
                0x20 -> "CDCVM (on-device CVM)"
                else -> "Method 0x${"%02X".format(cvmCode and 0x3F)}"
            }
            val condition = when (condCode) {
                0x00 -> "Always"
                0x01 -> "If unattended cash"
                0x02 -> "If not unattended cash or manual"
                0x03 -> "If terminal supports CVM"
                0x06 -> "If amount under X"
                0x07 -> "If amount over X"
                0x08 -> "If amount under Y"
                0x09 -> "If amount over Y"
                else -> "Condition 0x${"%02X".format(condCode)}"
            }
            val failAction = if (cvmCode and 0x40 != 0) " [apply next if fail]" else " [fail if unsuccessful]"
            sb.appendLine("  $ruleNum. $method — $condition$failAction")
            pos += 4
            ruleNum++
        }
        return sb.toString().trimEnd()
    }

    /** Decode AIP (Application Interchange Profile) */
    fun decodeAip(hex: String): String {
        val clean = hex.replace(" ", "").uppercase()
        if (clean.length < 4) return "Raw: $hex"

        val byte1 = clean.substring(0, 2).toIntOrNull(16) ?: return "Raw: $hex"
        val byte2 = clean.substring(2, 4).toIntOrNull(16) ?: return "Raw: $hex"

        val lines = listOf(
            "SDA supported: ${yesNo(byte1 and 0x80 != 0)}",
            "DDA supported: ${yesNo(byte1 and 0x40 != 0)}",
            "Cardholder verification supported: ${yesNo(byte1 and 0x20 != 0)}",
            "Terminal risk management: ${yesNo(byte1 and 0x10 != 0)}",
            "Issuer authentication supported: ${yesNo(byte1 and 0x08 != 0)}",
            "CDA supported: ${yesNo(byte1 and 0x02 != 0)}",
            "EMV mode supported (contactless): ${yesNo(byte2 and 0x80 != 0)}"
        )

        return lines.joinToString("\n")
    }

    private fun yesNo(value: Boolean): String = if (value) "Yes" else "No"

    /** Human-readable name for an EMV tag (single-sources [EMV_TAGS]). */
    fun tagName(tag: String): String = EMV_TAGS[tag.uppercase()] ?: "Unknown"

    // EMV tag dictionary
    private val EMV_TAGS = mapOf(
        "6F" to "FCI Template",
        "84" to "Dedicated File (DF) Name",
        "A5" to "FCI Proprietary Template",
        "BF0C" to "FCI Issuer Discretionary Data",
        "61" to "Application Template",
        "4F" to "Application Identifier (AID)",
        "50" to "Application Label",
        "87" to "Application Priority Indicator",
        "9F12" to "Application Preferred Name",
        "9F11" to "Issuer Code Table Index",
        "9F38" to "PDOL (Processing Data Object List)",
        "70" to "EMV Record Template",
        "77" to "Response Template Format 2",
        "80" to "Response Template Format 1",
        "82" to "Application Interchange Profile",
        "94" to "Application File Locator",
        "57" to "Track 2 Equivalent Data",
        "5A" to "Application PAN",
        "5F20" to "Cardholder Name",
        "5F24" to "Application Expiration Date",
        "5F25" to "Application Effective Date",
        "5F28" to "Issuer Country Code",
        "5F2A" to "Transaction Currency Code",
        "5F2D" to "Language Preference",
        "5F34" to "PAN Sequence Number",
        "8C" to "CDOL1 (Card Risk Mgmt DOL 1)",
        "8D" to "CDOL2 (Card Risk Mgmt DOL 2)",
        "8E" to "CVM List",
        "9F02" to "Amount Authorized",
        "9F03" to "Amount Other",
        "9F07" to "Application Usage Control",
        "9F08" to "App Version Number",
        "9F09" to "Terminal App Version",
        "9F0D" to "Issuer Action Code - Default",
        "9F0E" to "Issuer Action Code - Denial",
        "9F0F" to "Issuer Action Code - Online",
        "9F10" to "Issuer Application Data",
        "95" to "Terminal Verification Results",
        "9F1A" to "Terminal Country Code",
        "9F1F" to "Track 1 Discretionary Data",
        "9F21" to "Transaction Time",
        "9F26" to "Application Cryptogram",
        "9F27" to "Cryptogram Information Data",
        "9F33" to "Terminal Capabilities",
        "9F34" to "CVM Results",
        "9F35" to "Terminal Type",
        "9F36" to "Application Transaction Counter",
        "9F37" to "Unpredictable Number",
        "9F42" to "Application Currency Code",
        "9F44" to "Application Currency Exponent",
        "9F45" to "Data Authentication Code",
        "9F46" to "ICC Public Key Certificate",
        "9F47" to "ICC Public Key Exponent",
        "9F48" to "ICC Public Key Remainder",
        "9F49" to "DDOL",
        "9F66" to "Terminal Transaction Qualifiers",
        "9F4A" to "Static Data Authentication Tag List",
        "9F4D" to "Log Entry",
        "9F4F" to "Log Format",
        "9F6C" to "Card Transaction Qualifiers",
        "9F6E" to "Form Factor Indicator",
        "9F7C" to "Customer Exclusive Data",
        "9A" to "Transaction Date",
        "9C" to "Transaction Type",
        "56" to "Track 1 Data"
    )
}
