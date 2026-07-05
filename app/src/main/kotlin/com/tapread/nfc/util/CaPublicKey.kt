package com.tapread.nfc.util

import com.google.gson.Gson

/**
 * A scheme Certification Authority (CA) public key, identified by RID (first 5 bytes of the
 * AID) plus the CA Public Key Index (EMV tag 8F). These are published by the payment schemes
 * and must be supplied by the user via the `ca_public_keys.json` asset — they are intentionally
 * NOT hardcoded, since an unverifiable modulus constant would be a silent verification failure.
 */
data class CaPublicKey(
    val rid: String,          // 10 hex chars (5 bytes)
    val index: String,        // 2 hex chars (1 byte)
    val modulusHex: String,
    val exponentHex: String
)

object CaPublicKeyStore {

    private data class KeyDto(
        val rid: String? = null,
        val index: String? = null,
        val modulus: String? = null,
        val exponent: String? = null
    )

    private data class FileDto(val keys: List<KeyDto>? = null)

    /** Parse the CA public key list from the JSON asset text. Pure; returns empty on any error. */
    fun parse(json: String): List<CaPublicKey> {
        return try {
            val file = Gson().fromJson(json, FileDto::class.java) ?: return emptyList()
            file.keys.orEmpty().mapNotNull { dto ->
                val rid = dto.rid?.replace(" ", "")?.uppercase()
                val index = dto.index?.replace(" ", "")?.uppercase()
                val modulus = dto.modulus?.replace(" ", "")?.uppercase()
                val exponent = dto.exponent?.replace(" ", "")?.uppercase()
                if (rid.isNullOrBlank() || index.isNullOrBlank() ||
                    modulus.isNullOrBlank() || exponent.isNullOrBlank()
                ) null
                else CaPublicKey(rid, index, modulus, exponent)
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    fun find(keys: List<CaPublicKey>, rid: String, index: String): CaPublicKey? {
        val r = rid.replace(" ", "").uppercase()
        val i = index.replace(" ", "").uppercase()
        return keys.firstOrNull { it.rid.equals(r, true) && it.index.equals(i, true) }
    }
}
