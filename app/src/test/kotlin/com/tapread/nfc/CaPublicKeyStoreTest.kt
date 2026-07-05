package com.tapread.nfc

import com.tapread.nfc.util.CaPublicKey
import com.tapread.nfc.util.CaPublicKeyStore
import com.tapread.nfc.util.HexUtil
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.security.MessageDigest

class CaPublicKeyStoreTest {

    private val rid = "A000000003"
    private val index = "92"
    private val modulus = "0102030405060708"
    private val exponent = "03"

    /** Independent SHA-1 over RID(5) ‖ index(1) ‖ modulus ‖ exponent. */
    private fun independentChecksum(): String {
        fun hb(h: String) = ByteArray(h.length / 2) { h.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        val data = hb(rid) + hb(index) + hb(modulus) + hb(exponent)
        return HexUtil.toHex(MessageDigest.getInstance("SHA-1").digest(data)).uppercase()
    }

    @Test fun expectedChecksum_matchesIndependentComputation() {
        val key = CaPublicKey(rid, index, modulus, exponent)
        assertEquals(independentChecksum(), CaPublicKeyStore.expectedChecksum(key))
    }

    @Test fun verifyChecksum_match() {
        val key = CaPublicKey(rid, index, modulus, exponent, checksumHex = independentChecksum())
        assertEquals(CaPublicKeyStore.ChecksumResult.MATCH, CaPublicKeyStore.verifyChecksum(key))
    }

    @Test fun verifyChecksum_mismatch() {
        val key = CaPublicKey(rid, index, modulus, exponent, checksumHex = "00".repeat(20))
        assertEquals(CaPublicKeyStore.ChecksumResult.MISMATCH, CaPublicKeyStore.verifyChecksum(key))
    }

    @Test fun verifyChecksum_absentWhenNoChecksum() {
        val key = CaPublicKey(rid, index, modulus, exponent)
        assertEquals(CaPublicKeyStore.ChecksumResult.ABSENT, CaPublicKeyStore.verifyChecksum(key))
    }

    @Test fun mistypedModulus_isDetected() {
        // Same published checksum, but one nibble of the modulus is wrong → MISMATCH.
        val good = CaPublicKey(rid, index, modulus, exponent)
        val checksum = CaPublicKeyStore.expectedChecksum(good)
        val typo = CaPublicKey(rid, index, "0102030405060709", exponent, checksumHex = checksum)
        assertEquals(CaPublicKeyStore.ChecksumResult.MISMATCH, CaPublicKeyStore.verifyChecksum(typo))
    }

    @Test fun parse_readsChecksumAndHashAlias() {
        val json = """
            { "keys": [
              { "rid": "A0 00 00 00 03", "index": "92", "modulus": "0102", "exponent": "03", "checksum": "AABB" },
              { "rid": "A000000004", "index": "05", "modulus": "0304", "exponent": "03", "hash": "CCDD" }
            ] }
        """.trimIndent()
        val keys = CaPublicKeyStore.parse(json)
        assertEquals(2, keys.size)
        assertEquals("A000000003", keys[0].rid)   // spaces stripped, upper-cased
        assertEquals("AABB", keys[0].checksumHex)
        assertEquals("CCDD", keys[1].checksumHex)  // "hash" accepted as alias
    }

    @Test fun parse_toleratesGarbage() {
        assertEquals(0, CaPublicKeyStore.parse("not json").size)
        assertNull(CaPublicKeyStore.find(emptyList(), rid, index))
    }
}
