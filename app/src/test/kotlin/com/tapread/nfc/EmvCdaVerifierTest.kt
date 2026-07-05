package com.tapread.nfc

import com.tapread.nfc.util.CaPublicKey
import com.tapread.nfc.util.EmvCdaVerifier
import com.tapread.nfc.util.HexUtil
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

/**
 * Builds a genuine CA -> Issuer -> ICC RSA certificate chain and a valid SDAD in the exact
 * EMV recovered-data formats, then checks that [EmvCdaVerifier] accepts the genuine chain and
 * rejects tampering. This exercises the RSA recovery, byte-offset math, and SHA-1/UN binding
 * without needing a real card or published test vectors.
 */
class EmvCdaVerifierTest {

    private val RID = "A000000003"
    private val CA_INDEX = "09"
    private val AID = RID + "1010"   // Visa-shaped AID

    private class Key(val n: BigInteger, val e: BigInteger, val d: BigInteger, val len: Int) {
        val modBytes get() = toFixed(n, len)
        val expBytes get() = trimLeadingZeros(e.toByteArray())
        /** RSA private operation used to create a certificate: block^d mod n, fixed length. */
        fun sign(block: ByteArray) = toFixed(BigInteger(1, block).modPow(d, n), len)
    }

    private fun genKey(bits: Int): Key {
        val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(bits) }.generateKeyPair()
        val pub = kp.public as RSAPublicKey
        val priv = kp.private as RSAPrivateKey
        return Key(pub.modulus, pub.publicExponent, priv.privateExponent, bits / 8)
    }

    private fun sha1(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-1").digest(b)

    /** Build a public-key certificate block (Issuer format 02 or ICC format 04). */
    private fun buildCertBlock(
        format: Int, headerFixedLen: Int, pkLenIndex: Int, nLen: Int,
        keyMod: ByteArray, keyExp: ByteArray
    ): ByteArray {
        val block = ByteArray(nLen)
        block[0] = 0x6A
        block[1] = format.toByte()
        block[pkLenIndex] = keyMod.size.toByte()
        block[pkLenIndex + 1] = keyExp.size.toByte()
        val leftmostLen = nLen - headerFixedLen - 21
        val leftmost = ByteArray(leftmostLen) { 0xBB.toByte() }
        System.arraycopy(keyMod, 0, leftmost, 0, keyMod.size)   // key fits, remainder empty
        System.arraycopy(leftmost, 0, block, headerFixedLen, leftmostLen)
        val hashInput = block.copyOfRange(1, headerFixedLen + leftmostLen) + keyExp
        val hash = sha1(hashInput)
        System.arraycopy(hash, 0, block, nLen - 21, 20)
        block[nLen - 1] = 0xBC.toByte()
        return block
    }

    /** Build an SDAD (Signed Dynamic Application Data, format 05) block bound to [un]. */
    private fun buildSdad(nLen: Int, un: ByteArray, dynNum: ByteArray, cid: Byte, ac: ByteArray, txnHash: ByteArray): ByteArray {
        val iccDynData = byteArrayOf(dynNum.size.toByte()) + dynNum + byteArrayOf(cid) + ac + txnHash
        val block = ByteArray(nLen)
        block[0] = 0x6A
        block[1] = 0x05
        block[2] = 0x01                    // hash algo (SHA-1)
        block[3] = iccDynData.size.toByte()
        System.arraycopy(iccDynData, 0, block, 4, iccDynData.size)
        for (i in (4 + iccDynData.size) until (nLen - 21)) block[i] = 0xBB.toByte()  // pad
        val hashInput = block.copyOfRange(1, nLen - 21) + un
        val hash = sha1(hashInput)
        System.arraycopy(hash, 0, block, nLen - 21, 20)
        block[nLen - 1] = 0xBC.toByte()
        return block
    }

    private data class Chain(
        val tags: EmvCdaVerifier.CertTags,
        val caKey: CaPublicKey,
        val un: String
    )

    private fun buildGenuineChain(unHex: String = "11223344"): Chain {
        val ca = genKey(2048)      // 256 bytes
        val issuer = genKey(1024)  // 128 bytes — fits in CA leftmost (256-36=220)
        val icc = genKey(512)      // 64 bytes  — fits in issuer leftmost (128-42=86)

        val issuerBlock = buildCertBlock(0x02, 15, 13, ca.len, issuer.modBytes, issuer.expBytes)
        val issuerCert = ca.sign(issuerBlock)

        val iccBlock = buildCertBlock(0x04, 21, 19, issuer.len, icc.modBytes, icc.expBytes)
        val iccCert = issuer.sign(iccBlock)

        val un = HexUtil.toHex(hexToBytes(unHex))
        val ac = hexToBytes("A1B2C3D4E5F60708")
        val txnHash = ByteArray(20) { 0x33 }
        val dynNum = hexToBytes("0102030405060708")
        val sdadBlock = buildSdad(icc.len, hexToBytes(unHex), dynNum, 0x90.toByte(), ac, txnHash)
        val sdad = icc.sign(sdadBlock)

        val caKey = CaPublicKey(RID, CA_INDEX, HexUtil.toHex(ca.modBytes), HexUtil.toHex(ca.expBytes))
        val tags = EmvCdaVerifier.CertTags(
            aid = AID,
            caIndexHex = CA_INDEX,
            issuerCertHex = HexUtil.toHex(issuerCert),
            issuerRemHex = null,
            issuerExpHex = HexUtil.toHex(issuer.expBytes),
            iccCertHex = HexUtil.toHex(iccCert),
            iccExpHex = HexUtil.toHex(icc.expBytes),
            iccRemHex = null,
            sdadHex = HexUtil.toHex(sdad),
            unHex = un
        )
        return Chain(tags, caKey, un)
    }

    @Test fun verifiesGenuineChain() {
        val chain = buildGenuineChain()
        val result = EmvCdaVerifier.verify(chain.tags, listOf(chain.caKey))
        assertTrue(result.summary, result.overallVerified)
        assertEquals("A1B2C3D4E5F60708", result.recoveredAcHex)
        assertEquals("0102030405060708", result.iccDynamicNumberHex)
    }

    @Test fun rejectsWrongUnpredictableNumber() {
        val chain = buildGenuineChain(unHex = "11223344")
        // Present a different UN than the one the SDAD was signed over
        val tampered = chain.tags.copy(unHex = "AABBCCDD")
        val result = EmvCdaVerifier.verify(tampered, listOf(chain.caKey))
        assertFalse(result.overallVerified)
        assertTrue(result.steps.any { it.name == "SDAD signature" && it.status.name == "FAIL" })
    }

    @Test fun failsWhenCaKeyMissing() {
        val chain = buildGenuineChain()
        val result = EmvCdaVerifier.verify(chain.tags, emptyList())
        assertFalse(result.overallVerified)
        assertTrue(result.steps.any { it.name == "CA public key" && it.status.name == "SKIPPED" })
    }

    @Test fun failsWithWrongCaKey() {
        val chain = buildGenuineChain()
        val bogusCa = CaPublicKey(RID, CA_INDEX, HexUtil.toHex(genKey(2048).modBytes), "010001")
        val result = EmvCdaVerifier.verify(chain.tags, listOf(bogusCa))
        assertFalse(result.overallVerified)
        assertTrue(result.steps.any { it.name == "Issuer public key" && it.status.name == "FAIL" })
    }

    @Test fun noSdad_notAttempted() {
        val chain = buildGenuineChain()
        val result = EmvCdaVerifier.verify(chain.tags.copy(sdadHex = null), listOf(chain.caKey))
        assertFalse(result.attempted)
    }

    @Test fun rejectsCorruptedSdad() {
        val chain = buildGenuineChain()
        // Flip one byte of the SDAD ciphertext — RSA recovery no longer yields a 6A..05..BC block.
        val bytes = hexToBytes(chain.tags.sdadHex!!)
        bytes[bytes.size / 2] = (bytes[bytes.size / 2].toInt() xor 0xFF).toByte()
        val result = EmvCdaVerifier.verify(chain.tags.copy(sdadHex = HexUtil.toHex(bytes)), listOf(chain.caKey))
        assertFalse(result.overallVerified)
        assertTrue(result.steps.any { it.name == "SDAD signature" && it.status.name == "FAIL" })
    }

    @Test fun malformedHex_doesNotCrash() {
        val chain = buildGenuineChain()
        // Non-hex garbage in a tag must produce a FAIL result, not an exception.
        val result = EmvCdaVerifier.verify(chain.tags.copy(issuerCertHex = "ZZZZ"), listOf(chain.caKey))
        assertFalse(result.overallVerified)
    }

    // helpers

    private fun hexToBytes(hex: String): ByteArray {
        val c = hex.replace(" ", "")
        return ByteArray(c.length / 2) { c.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }

    companion object {
        fun toFixed(bi: BigInteger, len: Int): ByteArray {
            var b = bi.toByteArray()
            if (b.size > len) b = b.copyOfRange(b.size - len, b.size)
            if (b.size < len) {
                val p = ByteArray(len)
                System.arraycopy(b, 0, p, len - b.size, b.size)
                b = p
            }
            return b
        }

        fun trimLeadingZeros(b: ByteArray): ByteArray {
            var i = 0
            while (i < b.size - 1 && b[i] == 0.toByte()) i++
            return b.copyOfRange(i, b.size)
        }
    }
}
