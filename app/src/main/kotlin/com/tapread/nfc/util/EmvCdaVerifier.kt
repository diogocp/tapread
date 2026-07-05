package com.tapread.nfc.util

import com.tapread.nfc.model.CdaStep
import com.tapread.nfc.model.CdaStepStatus
import com.tapread.nfc.model.CdaVerification
import java.math.BigInteger
import java.security.MessageDigest

/**
 * Offline CDA (Combined DDA / Application Cryptogram) verification.
 *
 * Chain of trust:
 *   CA public key (by RID + index)  →  recover Issuer public key (90 / 92 / 9F32)
 *                                   →  recover ICC public key (9F46 / 9F47 / 9F48)
 *                                   →  recover SDAD (9F4B) with the ICC key
 *
 * The SDAD hash check binds the terminal's Unpredictable Number (9F37), which proves the
 * signature is fresh (anti-replay) and was produced by the CA-chained ICC key. This is the
 * substantive proof that the token can produce locally verifiable dynamic authentication.
 *
 * [verifyCertChain] runs only the CA→Issuer→ICC recovery (no signature, no card command → does
 * NOT touch the ATC). It proves the card presents genuine CA-chained key material, but is
 * static/replayable — liveness needs a fresh signature (DDA or CDA).
 *
 * Deliberate scope limits (reported honestly, not faked):
 *  - The ICC public-key certificate's static-data integrity hash requires kernel-specific
 *    "static data to be authenticated" assembly; it is reported as INFO/skipped. The ICC key's
 *    authenticity still rests on the issuer-signed certificate recovering to a valid structure.
 *  - The Transaction Data Hash Code inside the SDAD is extracted but not recomputed.
 *
 * Pure: uses only java.math.BigInteger and SHA-1, so it is unit-testable off-device.
 */
object EmvCdaVerifier {

    /** Tags gathered from the read for verification. Missing values yield SKIPPED steps. */
    data class CertTags(
        val aid: String?,            // for RID (first 5 bytes)
        val caIndexHex: String?,     // 8F
        val issuerCertHex: String?,  // 90
        val issuerRemHex: String?,   // 92 (optional)
        val issuerExpHex: String?,   // 9F32
        val iccCertHex: String?,     // 9F46
        val iccExpHex: String?,      // 9F47
        val iccRemHex: String?,      // 9F48 (optional)
        val sdadHex: String?,        // 9F4B
        val unHex: String?           // 9F37 sent in the GENERATE AC
    )

    /** Full CDA verification: cert chain + a fresh SDAD signature binding the Unpredictable Number. */
    fun verify(tags: CertTags, caKeys: List<CaPublicKey>): CdaVerification {
        val steps = mutableListOf<CdaStep>()

        if (tags.sdadHex.isNullOrBlank()) {
            return CdaVerification(
                attempted = false,
                overallVerified = false,
                summary = "No SDAD (9F4B) available to verify — request CDA in GENERATE AC first."
            )
        }

        val chain = recoverIccKey(tags, caKeys, steps)
        val rid = chain.rid
        val caIndex = chain.caIndex
        val iccMod = chain.iccModulus
        val iccExp = chain.iccExp
        if (iccMod == null || iccExp == null) {
            return done(steps, rid, caIndex, chain.stopSummary ?: "Certificate chain incomplete.")
        }

        // ── recover & verify the SDAD ──
        val sdad = hexToBytes(tags.sdadHex)
        val rec = try {
            modPowFixed(sdad, iccExp, iccMod)
        } catch (e: Exception) {
            steps.add(CdaStep("SDAD signature", CdaStepStatus.FAIL, "Recovery error: ${e.message}"))
            return done(steps, rid, caIndex, "SDAD recovery failed.")
        }
        val nic = iccMod.size
        if (rec.size != nic || u(rec[0]) != 0x6A || u(rec[1]) != 0x05 || u(rec[nic - 1]) != 0xBC) {
            steps.add(CdaStep("SDAD signature", CdaStepStatus.FAIL,
                "Recovered SDAD structure invalid (header/format/trailer)"))
            return done(steps, rid, caIndex, "SDAD recovery produced an invalid structure.")
        }
        // rec: [0]=6A [1]=05 [2]=hashAlg [3]=LDD [4..4+LDD-1]=ICC Dynamic Data
        //      [pad ... ] [nic-21..nic-2]=hash [nic-1]=BC
        val ldd = u(rec[3])
        if (4 + ldd > nic - 21) {
            steps.add(CdaStep("SDAD signature", CdaStepStatus.FAIL, "Malformed ICC Dynamic Data length"))
            return done(steps, rid, caIndex, "SDAD parsing failed.")
        }
        val iccDynData = rec.copyOfRange(4, 4 + ldd)

        // Extract ICC Dynamic Number, recovered AC, transaction data hash from ICC Dynamic Data.
        var recoveredAcHex: String? = null
        var iccDynNumHex: String? = null
        var txnHashHex: String? = null
        if (iccDynData.isNotEmpty()) {
            val dynLen = u(iccDynData[0])
            if (1 + dynLen <= iccDynData.size) {
                iccDynNumHex = HexUtil.toHex(iccDynData.copyOfRange(1, 1 + dynLen))
                val pos = 1 + dynLen
                // CDA payload: CID(1) + AC(8) + Transaction Data Hash Code(20)
                if (iccDynData.size - pos >= 29) {
                    recoveredAcHex = HexUtil.toHex(iccDynData.copyOfRange(pos + 1, pos + 9))
                    txnHashHex = HexUtil.toHex(iccDynData.copyOfRange(pos + 9, pos + 29))
                }
            }
        }

        if (tags.unHex.isNullOrBlank()) {
            steps.add(CdaStep("SDAD signature", CdaStepStatus.SKIPPED,
                "Recovered a valid SDAD structure, but the Unpredictable Number sent is unknown — cannot check freshness hash"))
            return done(steps, rid, caIndex,
                "SDAD recovered but freshness not verified (UN unavailable).",
                recoveredAcHex, iccDynNumHex, txnHashHex)
        }
        val un = hexToBytes(tags.unHex)
        val hashInSdad = rec.copyOfRange(nic - 21, nic - 1)
        val hashInput = rec.copyOfRange(1, nic - 21) + un   // format(05) .. pad, then UN
        val calc = sha1(hashInput)
        if (!calc.contentEquals(hashInSdad)) {
            steps.add(CdaStep("SDAD signature", CdaStepStatus.FAIL,
                "SDAD hash mismatch — signature does not bind the Unpredictable Number sent"))
            return done(steps, rid, caIndex, "SDAD hash verification FAILED.",
                recoveredAcHex, iccDynNumHex, txnHashHex)
        }
        steps.add(CdaStep("SDAD signature", CdaStepStatus.PASS,
            "Valid RSA signature by the ICC key, hash binds the Unpredictable Number (fresh)"))
        steps.add(CdaStep("Transaction data hash", CdaStepStatus.INFO,
            "Extracted from SDAD; not recomputed (kernel-specific input)"))

        return CdaVerification(
            attempted = true,
            overallVerified = true,
            steps = steps,
            caRidHex = rid,
            caIndexHex = caIndex,
            recoveredAcHex = recoveredAcHex,
            iccDynamicNumberHex = iccDynNumHex,
            transactionDataHashHex = txnHashHex,
            summary = "CDA verified: CA-chained ICC key produced a fresh signature binding your Unpredictable Number."
        )
    }

    /**
     * Static certificate-chain verification — recovers CA→Issuer→ICC public keys from the read
     * records only. No card command, no signature, so it does NOT touch the ATC. Proves the card
     * presents genuine CA-chained key material, but is REPLAYABLE (a clone with copied
     * certificates would also pass); liveness requires a fresh signature (DDA or CDA).
     */
    fun verifyCertChain(tags: CertTags, caKeys: List<CaPublicKey>): CdaVerification {
        val steps = mutableListOf<CdaStep>()
        val chain = recoverIccKey(tags, caKeys, steps)
        if (chain.iccModulus == null) {
            return done(steps, chain.rid, chain.caIndex, chain.stopSummary ?: "Certificate chain incomplete.")
        }
        return CdaVerification(
            attempted = true,
            overallVerified = true,
            steps = steps,
            caRidHex = chain.rid,
            caIndexHex = chain.caIndex,
            summary = "Certificate chain valid (STATIC, no ATC): the card presents a genuine CA-chained " +
                "ICC public key. This does NOT prove the card holds the matching private key — a clone with " +
                "copied certificates would also pass. Liveness requires a fresh signature (DDA or CDA)."
        )
    }

    // ── internals ──

    private class ChainOutcome(
        val iccModulus: ByteArray?,   // non-null only on full success
        val iccExp: ByteArray?,
        val rid: String?,
        val caIndex: String?,
        val stopSummary: String?      // reason the chain did not complete (null on success)
    )

    private data class RecoveredKey(
        val formatOk: Boolean,
        val hashOk: Boolean,
        val modulus: ByteArray
    )

    /**
     * Recover CA→Issuer→ICC public keys, appending a step per stage. Returns the ICC modulus +
     * exponent on success; on any failure iccModulus is null and stopSummary explains why. Pure —
     * no card commands (works entirely from the read records + configured CA keys).
     */
    private fun recoverIccKey(tags: CertTags, caKeys: List<CaPublicKey>, steps: MutableList<CdaStep>): ChainOutcome {
        val rid = tags.aid?.replace(" ", "")?.uppercase()?.takeIf { it.length >= 10 }?.substring(0, 10)
        val caIndex = tags.caIndexHex?.replace(" ", "")?.uppercase()

        // ── Step 1: CA public key ──
        if (rid == null || caIndex.isNullOrBlank()) {
            steps.add(CdaStep("CA public key", CdaStepStatus.SKIPPED,
                "Missing RID (from AID) or CA Public Key Index (tag 8F)"))
            return ChainOutcome(null, null, rid, caIndex, "Cannot verify: CA key selection data missing.")
        }
        // A scheme may publish more than one key under the same (RID, index); try each.
        val candidates = CaPublicKeyStore.findAll(caKeys, rid, caIndex)
        if (candidates.isEmpty()) {
            steps.add(CdaStep("CA public key", CdaStepStatus.SKIPPED,
                "No CA public key configured for RID $rid index $caIndex — add it to ca_public_keys.json"))
            return ChainOutcome(null, null, rid, caIndex, "Cannot verify: CA public key for RID $rid index $caIndex not configured.")
        }
        // Drop candidates with invalid hex or a checksum mismatch (mistyped modulus/exponent).
        val usable = candidates.filter { key ->
            hexToBytes(key.modulusHex).isNotEmpty() && hexToBytes(key.exponentHex).isNotEmpty() &&
                CaPublicKeyStore.verifyChecksum(key) != CaPublicKeyStore.ChecksumResult.MISMATCH
        }
        if (usable.isEmpty()) {
            steps.add(CdaStep("CA public key", CdaStepStatus.FAIL,
                "Configured CA key(s) for RID $rid index $caIndex are invalid or fail their checksum (modulus/exponent likely mistyped)"))
            return ChainOutcome(null, null, rid, caIndex, "Configured CA public key is invalid.")
        }

        // ── Step 2: recover Issuer public key (try each candidate CA key) ──
        if (tags.issuerCertHex.isNullOrBlank() || tags.issuerExpHex.isNullOrBlank()) {
            steps.add(CdaStep("CA public key", CdaStepStatus.PASS,
                "RID $rid index $caIndex (${usable.size} candidate key(s))"))
            steps.add(CdaStep("Issuer public key", CdaStepStatus.SKIPPED,
                "Issuer PK certificate (90) or exponent (9F32) not found in records"))
            return ChainOutcome(null, null, rid, caIndex, "Cannot verify: issuer certificate data missing.")
        }
        val issuerCert = hexToBytes(tags.issuerCertHex)
        val issuerRem = tags.issuerRemHex?.let { hexToBytes(it) } ?: ByteArray(0)
        val issuerExp = hexToBytes(tags.issuerExpHex)

        var chosenKey: CaPublicKey? = null
        var chosenIssuer: RecoveredKey? = null
        for (key in usable) {
            val r = try {
                recoverCertKey(
                    cert = issuerCert,
                    caOrIssuerMod = hexToBytes(key.modulusHex), caOrIssuerExp = hexToBytes(key.exponentHex),
                    expectedFormat = 0x02,    // 6A,fmt,id(4),date(2),serial(3),hashAlg,pkAlg,pkLen,expLen
                    headerFixedLen = 15,
                    pkLenIndex = 13,
                    remainder = issuerRem, keyExponent = issuerExp,
                    staticData = null
                )
            } catch (_: Exception) { null } ?: continue
            if (r.formatOk && r.hashOk) { chosenKey = key; chosenIssuer = r; break }
        }
        val caKey = chosenKey
        val issuer = chosenIssuer
        if (caKey == null || issuer == null) {
            steps.add(CdaStep("CA public key", CdaStepStatus.PASS,
                "RID $rid index $caIndex (${usable.size} candidate key(s))"))
            steps.add(CdaStep("Issuer public key", CdaStepStatus.FAIL,
                "None of the ${usable.size} candidate CA key(s) for RID $rid index $caIndex authenticated the issuer certificate (wrong key/index or bad certificate)"))
            return ChainOutcome(null, null, rid, caIndex, "Issuer public key recovery failed under all configured CA keys.")
        }
        val chkNote = if (CaPublicKeyStore.verifyChecksum(caKey) == CaPublicKeyStore.ChecksumResult.MATCH) ", checksum OK" else ""
        val candNote = if (usable.size > 1) " (chose 1 of ${usable.size} candidates)" else ""
        steps.add(CdaStep("CA public key", CdaStepStatus.PASS,
            "RID $rid index $caIndex, modulus ${hexToBytes(caKey.modulusHex).size * 8} bits$chkNote$candNote"))
        steps.add(CdaStep("Issuer public key", CdaStepStatus.PASS,
            "Recovered & hash-verified, modulus ${issuer.modulus.size * 8} bits"))

        // ── Step 3: recover ICC public key (format-verified; static-data hash out of scope) ──
        if (tags.iccCertHex.isNullOrBlank() || tags.iccExpHex.isNullOrBlank()) {
            steps.add(CdaStep("ICC public key", CdaStepStatus.SKIPPED,
                "ICC PK certificate (9F46) or exponent (9F47) not found in records"))
            return ChainOutcome(null, null, rid, caIndex, "Cannot verify: ICC certificate data missing.")
        }
        val iccRem = tags.iccRemHex?.let { hexToBytes(it) } ?: ByteArray(0)
        val iccExp = hexToBytes(tags.iccExpHex)
        val icc = try {
            recoverCertKey(
                cert = hexToBytes(tags.iccCertHex),
                caOrIssuerMod = issuer.modulus, caOrIssuerExp = issuerExp,
                expectedFormat = 0x04,    // 6A,fmt,PAN(10),date(2),serial(3),hashAlg,pkAlg,pkLen,expLen
                headerFixedLen = 21,
                pkLenIndex = 19,
                remainder = iccRem, keyExponent = iccExp,
                staticData = null         // not recomputed
            )
        } catch (e: Exception) {
            steps.add(CdaStep("ICC public key", CdaStepStatus.FAIL, "Recovery error: ${e.message}"))
            return ChainOutcome(null, null, rid, caIndex, "ICC public key recovery failed.")
        }
        if (!icc.formatOk) {
            steps.add(CdaStep("ICC public key", CdaStepStatus.FAIL,
                "Recovered structure invalid — issuer key did not authenticate the ICC certificate"))
            return ChainOutcome(null, null, rid, caIndex, "ICC public key recovery failed.")
        }
        steps.add(CdaStep("ICC public key", CdaStepStatus.PASS,
            "Recovered from issuer-signed certificate, modulus ${icc.modulus.size * 8} bits"))
        steps.add(CdaStep("ICC certificate integrity", CdaStepStatus.INFO,
            "Static-data hash not recomputed (kernel-specific); ICC key authenticity rests on the issuer signature"))

        return ChainOutcome(icc.modulus, iccExp, rid, caIndex, null)
    }

    /**
     * Recover a public-key certificate (Issuer or ICC) and validate it.
     * @param headerFixedLen number of leading bytes before the leftmost PK bytes begin
     * @param pkLenIndex index of the recovered "PK length" byte
     * @param staticData appended to the hash input for ICC certs; null skips that (hashOk left true only if format ok)
     */
    private fun recoverCertKey(
        cert: ByteArray,
        caOrIssuerMod: ByteArray,
        caOrIssuerExp: ByteArray,
        expectedFormat: Int,
        headerFixedLen: Int,
        pkLenIndex: Int,
        remainder: ByteArray,
        keyExponent: ByteArray,
        staticData: ByteArray?
    ): RecoveredKey {
        val n = caOrIssuerMod.size
        val rec = modPowFixed(cert, caOrIssuerExp, caOrIssuerMod)
        val formatOk = rec.size == n && u(rec[0]) == 0x6A &&
            u(rec[1]) == expectedFormat && u(rec[n - 1]) == 0xBC
        if (!formatOk) return RecoveredKey(false, false, ByteArray(0))

        val pkLen = u(rec[pkLenIndex])
        // leftmost PK bytes = modulus length − fixed header − 20-byte hash − 1-byte trailer.
        // Issuer cert: header 15 → n−36. ICC cert: header 21 → n−42.
        val leftmostLen = n - headerFixedLen - 21
        if (leftmostLen < 0) {
            return RecoveredKey(false, false, ByteArray(0))
        }
        val leftmost = rec.copyOfRange(headerFixedLen, headerFixedLen + leftmostLen)
        val modFull = leftmost + remainder
        val modulus = if (pkLen in 1..modFull.size) modFull.copyOfRange(0, pkLen) else modFull

        // Hash check: SHA-1 over (recovered format byte .. end of leftmost) || remainder || exponent [|| static]
        val hashInCert = rec.copyOfRange(n - 21, n - 1)
        var hashInput = rec.copyOfRange(1, headerFixedLen + leftmostLen) + remainder + keyExponent
        if (staticData != null) hashInput += staticData
        val hashOk = if (staticData == null && expectedFormat == 0x04) {
            // ICC cert: static data intentionally not assembled → don't assert hash here.
            true
        } else {
            sha1(hashInput).contentEquals(hashInCert)
        }
        return RecoveredKey(true, hashOk, modulus)
    }

    /** RSA "recovery": C^e mod N, returned as a fixed-length (modulus size) big-endian byte array. */
    private fun modPowFixed(data: ByteArray, exp: ByteArray, mod: ByteArray): ByteArray {
        val c = BigInteger(1, data)
        val e = BigInteger(1, exp)
        val n = BigInteger(1, mod)
        val r = c.modPow(e, n)
        var out = r.toByteArray()
        if (out.size > mod.size) out = out.copyOfRange(out.size - mod.size, out.size) // drop sign byte
        if (out.size < mod.size) {
            val padded = ByteArray(mod.size)
            System.arraycopy(out, 0, padded, mod.size - out.size, out.size)
            out = padded
        }
        return out
    }

    private fun sha1(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-1").digest(data)

    private fun u(b: Byte): Int = b.toInt() and 0xFF

    private fun hexToBytes(hex: String): ByteArray {
        val clean = hex.replace(" ", "").uppercase()
        if (clean.isEmpty() || clean.length % 2 != 0) return ByteArray(0)
        return try {
            ByteArray(clean.length / 2) { clean.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        } catch (_: Exception) {
            ByteArray(0)   // malformed hex → empty, so verify() reports FAIL rather than crashing
        }
    }

    private fun done(
        steps: List<CdaStep>,
        rid: String?,
        caIndex: String?,
        summary: String,
        acHex: String? = null,
        dynNumHex: String? = null,
        txnHashHex: String? = null
    ) = CdaVerification(
        attempted = true,
        overallVerified = false,
        steps = steps,
        caRidHex = rid,
        caIndexHex = caIndex,
        recoveredAcHex = acHex,
        iccDynamicNumberHex = dynNumHex,
        transactionDataHashHex = txnHashHex,
        summary = summary
    )
}
