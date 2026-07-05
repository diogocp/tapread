package com.tapread.nfc

import com.tapread.nfc.util.TlvParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TlvParserTest {

    // ── readLength: short + long form, and the previously-mishandled cases ──

    @Test fun readLength_shortForm() {
        assertEquals(0x03 to 2, TlvParser.readLength("03AABBCC", 0))
    }

    @Test fun readLength_longForm81() {
        assertEquals(0xB0 to 4, TlvParser.readLength("81B0", 0))
    }

    @Test fun readLength_longForm82() {
        assertEquals(0x0110 to 6, TlvParser.readLength("820110", 0))
    }

    @Test fun readLength_rejectsIndefinite80() {
        assertNull(TlvParser.readLength("80", 0))            // indefinite form — not valid in EMV
    }

    @Test fun readLength_rejectsAbsurdLongForm() {
        assertNull(TlvParser.readLength("8501020304050607", 0))  // 5 length bytes → rejected
    }

    @Test fun readLength_rejectsOverflowingLength() {
        // 84 7FFFFFFF: len*2 would overflow Int and defeat the walker's bounds check.
        assertNull(TlvParser.readLength("847FFFFFFF", 0))
        // Boundary: Int.MAX/2 is allowed, one more is rejected.
        assertEquals(0x3FFFFFFF to 10, TlvParser.readLength("843FFFFFFF", 0))
        assertNull(TlvParser.readLength("8440000000", 0))
    }

    @Test fun findValue_doesNotCrashOnOverflowingLength() {
        // Must return null, not throw StringIndexOutOfBoundsException, on the live read path.
        assertNull(TlvParser.findValue("57847FFFFFFF9000", "8C"))
        assertNull(TlvParser.topLevelValue("57847FFFFFFF9000", "57"))
        assertTrue(TlvParser.parse("57847FFFFFFF9000").isEmpty())
    }

    // ── readTag: single and multi-byte ──

    @Test fun readTag_singleAndMultiByte() {
        assertEquals("82" to 2, TlvParser.readTag("8202AABB", 0))
        assertEquals("9F38" to 4, TlvParser.readTag("9F3806", 0))
        assertEquals("5F2A" to 4, TlvParser.readTag("5F2A02", 0))
    }

    @Test fun isConstructed_matchesBit6() {
        assertTrue(TlvParser.isConstructed("6F"))
        assertTrue(TlvParser.isConstructed("70"))
        assertTrue(TlvParser.isConstructed("77"))
        assertTrue(TlvParser.isConstructed("A5"))
        assertFalse(TlvParser.isConstructed("80"))   // primitive
        assertFalse(TlvParser.isConstructed("8C"))   // primitive
        assertFalse(TlvParser.isConstructed("5F24")) // primitive
        assertFalse(TlvParser.isConstructed("9F46")) // primitive
    }

    // ── findValue: nesting, SW strip, and false-positive resistance ──

    @Test fun findValue_recursesConstructedAndStripsSw() {
        // 6F { 84 07 A0000000031010, A5 { 9F38 03 9F6604 } }  + SW
        val fci = "6F148407A0000000031010A5099F38069F66049F02069000"
        assertEquals("9F66049F0206", TlvParser.findValue(fci, "9F38"))
        assertEquals("A0000000031010", TlvParser.findValue(fci, "84"))
    }

    @Test fun findValue_notPresent() {
        assertNull(TlvParser.findValue("70045F3401019000", "8C"))
    }

    @Test fun findValue_doesNotDescendIntoPrimitiveValues() {
        // A primitive Track-2 (57) whose value bytes merely LOOK like tag 8C must NOT match.
        val record = "57048C039F379000"   // 57 04 { 8C 03 9F 37 }, SW 9000
        assertNull(TlvParser.findValue(record, "8C"))
        assertNull(TlvParser.findValue(record, "9F37"))
        assertEquals("8C039F37", TlvParser.findValue(record, "57"))
    }

    @Test fun findValue_longFormLengthDoesNotDerailWalk() {
        // 77 0A { 90 81 03 AABBCC, 8C 02 9F37 } + SW — the tag after a long-form field must still be found.
        val gpo = "770A908103AABBCC8C029F379000"
        assertEquals("9F37", TlvParser.findValue(gpo, "8C"))
        assertEquals("AABBCC", TlvParser.findValue(gpo, "90"))
    }

    // ── Format 1 vs Format 2 (topLevelValue vs findValue) ──

    @Test fun topLevelValue_format1_doesNotSeeInsidePrimitive() {
        val gpo = "80061B80080101009000"        // Format 1: 80 { AIP 1B80, AFL 08010100 }
        assertEquals("1B8008010100", TlvParser.topLevelValue(gpo, "80"))
        // 94 (AFL) is inside the primitive 80 value → must NOT be found by a TLV search.
        assertNull(TlvParser.findValue(gpo, "94"))
        assertEquals("80", TlvParser.firstTag(gpo))
    }

    @Test fun findValue_format2_findsAflInsideTag77() {
        val gpo = "770E82027C0094080801010010010301" + "9000"
        assertEquals("7C00", TlvParser.findValue(gpo, "82"))
        assertEquals("0801010010010301", TlvParser.findValue(gpo, "94"))
        assertEquals("77", TlvParser.firstTag(gpo))
    }

    // ── parse() tree: long-form length no longer misread ──

    @Test fun parse_handlesLongFormLength() {
        val nodes = TlvParser.parse("578103AABBCC9000")  // 57 81 03 AABBCC + SW
        assertEquals(1, nodes.size)
        assertEquals("57", nodes[0].tag)
        assertEquals(3, nodes[0].length)
        assertEquals("AABBCC", nodes[0].value)
    }
}
