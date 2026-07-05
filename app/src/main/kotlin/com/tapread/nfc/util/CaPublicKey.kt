package com.tapread.nfc.util

import com.google.gson.Gson
import java.security.MessageDigest

/**
 * A scheme Certification Authority (CA) public key, identified by RID (first 5 bytes of the
 * AID) plus the CA Public Key Index (EMV tag 8F). These are published by the payment schemes
 * and must be supplied by the user via the `ca_public_keys.json` asset — they are intentionally
 * NOT hardcoded, since an unverifiable modulus constant would be a silent verification failure.
 *
 * [checksumHex], if supplied, is the SHA-1 check value published alongside the key and lets
 * TapRead detect a mistyped modulus/exponent (see [CaPublicKeyStore.verifyChecksum]).
 */
data class CaPublicKey(
    val rid: String,          // 10 hex chars (5 bytes)
    val index: String,        // 2 hex chars (1 byte)
    val modulusHex: String,
    val exponentHex: String,
    val checksumHex: String? = null   // published SHA-1 check value (optional)
)

object CaPublicKeyStore {

    enum class ChecksumResult { MATCH, MISMATCH, ABSENT }

    private data class KeyDto(
        val rid: String? = null,
        val index: String? = null,
        val modulus: String? = null,
        val exponent: String? = null,
        val checksum: String? = null,
        val hash: String? = null          // accept "hash" as an alias for "checksum"
    )

    private data class FileDto(val keys: List<KeyDto>? = null)

    /** Parse the CA public key list from the JSON asset text. Pure; returns empty on any error. */
    fun parse(json: String): List<CaPublicKey> {
        return try {
            val file = Gson().fromJson(json, FileDto::class.java) ?: return emptyList()
            file.keys.orEmpty().mapNotNull { dto ->
                val rid = dto.rid?.let { clean(it) }
                val index = dto.index?.let { clean(it) }
                val modulus = dto.modulus?.let { clean(it) }
                val exponent = dto.exponent?.let { clean(it) }
                val checksum = (dto.checksum ?: dto.hash)?.let { clean(it) }?.takeIf { it.isNotBlank() }
                if (rid.isNullOrBlank() || index.isNullOrBlank() ||
                    modulus.isNullOrBlank() || exponent.isNullOrBlank()
                ) null
                else CaPublicKey(rid, index, modulus, exponent, checksum)
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    fun find(keys: List<CaPublicKey>, rid: String, index: String): CaPublicKey? {
        val r = clean(rid)
        val i = clean(index)
        return keys.firstOrNull { it.rid.equals(r, true) && it.index.equals(i, true) }
    }

    /**
     * The EMV CA public key check value: SHA-1 over RID(5) ‖ CA Index(1) ‖ Modulus ‖ Exponent,
     * as uppercase hex. This is the value the schemes publish next to each key.
     */
    fun expectedChecksum(key: CaPublicKey): String {
        val data = hexToBytes(key.rid) + hexToBytes(key.index) +
            hexToBytes(key.modulusHex) + hexToBytes(key.exponentHex)
        return HexUtil.toHex(MessageDigest.getInstance("SHA-1").digest(data)).uppercase()
    }

    /** Compare a key's supplied checksum against the computed one. ABSENT if none was supplied. */
    fun verifyChecksum(key: CaPublicKey): ChecksumResult {
        val provided = key.checksumHex?.let { clean(it) }?.takeIf { it.isNotBlank() }
            ?: return ChecksumResult.ABSENT
        return if (provided.equals(expectedChecksum(key), true)) ChecksumResult.MATCH
        else ChecksumResult.MISMATCH
    }

    private fun clean(s: String): String = s.replace(" ", "").replace(":", "").uppercase()

    private fun hexToBytes(hex: String): ByteArray {
        val c = clean(hex)
        if (c.isEmpty() || c.length % 2 != 0) return ByteArray(0)
        return try {
            ByteArray(c.length / 2) { c.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        } catch (_: Exception) {
            ByteArray(0)
        }
    }
}
