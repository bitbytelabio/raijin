package io.bitbytelab.raijin.turbo.hp3

import io.bitbytelab.raijin.turbo.hp3.h3.Http3Exception
import io.bitbytelab.raijin.turbo.hp3.h3.qpack.FieldLine
import io.bitbytelab.raijin.turbo.hp3.h3.qpack.QpackDecoder
import io.bitbytelab.raijin.turbo.hp3.h3.qpack.QpackDynamicTable
import io.bitbytelab.raijin.turbo.hp3.h3.qpack.QpackEncoder
import io.bitbytelab.raijin.turbo.hp3.h3.qpack.QpackEncoderStream
import io.bitbytelab.raijin.turbo.hp3.h3.qpack.QpackException
import java.io.ByteArrayInputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class QpackDynamicTableTest {

    // Each of these costs 32 + 1 + 1 = 34 octets, RFC 9204 section 3.2.1.
    private val a = FieldLine("a", "1")
    private val b = FieldLine("b", "2")
    private val c = FieldLine("c", "3")

    @Test
    fun capacityStartsAtZeroUntilTheEncoderSetsIt() {
        val table = QpackDynamicTable(4096)

        assertEquals(0L, table.capacity())
        assertEquals(4096L, table.snapshot().maxCapacity())
        val failure = assertFailsWith<QpackException> { table.insert(a) }
        assertEquals(Http3Exception.QPACK_ENCODER_STREAM_ERROR, failure.errorCode())
        assertEquals(0L, table.insertCount())
    }

    @Test
    fun capacityAboveTheAdvertisedMaximumIsRefused() {
        val table = QpackDynamicTable(100)

        val failure = assertFailsWith<QpackException> { table.setCapacity(101) }
        assertEquals(Http3Exception.QPACK_ENCODER_STREAM_ERROR, failure.errorCode())
        assertEquals(0L, table.capacity())

        table.setCapacity(100)
        assertEquals(100L, table.capacity())
    }

    @Test
    fun entryLargerThanTheCapacityIsRefusedAndLeavesTheTableAsItWas() {
        val table = QpackDynamicTable(4096)
        table.setCapacity(40)
        table.insert(a)

        // 32 + 5 + 5 = 42 octets, two more than the whole table.
        val failure = assertFailsWith<QpackException> { table.insert(FieldLine("abcde", "fghij")) }
        assertEquals(Http3Exception.QPACK_ENCODER_STREAM_ERROR, failure.errorCode())
        assertEquals(1L, table.insertCount())
        assertEquals(a, table.get(0))
    }

    @Test
    fun insertionEvictsTheOldestEntriesToFit() {
        val table = QpackDynamicTable(4096)
        table.setCapacity(100)
        table.insert(a)
        table.insert(b)
        table.insert(c)

        assertEquals(3L, table.insertCount())
        assertFailsWith<QpackException> { table.get(0) }
        assertEquals(b, table.get(1))
        assertEquals(c, table.get(2))
    }

    @Test
    fun loweringTheCapacityEvictsWhatNoLongerFits() {
        val table = QpackDynamicTable(4096)
        table.setCapacity(100)
        table.insert(a)
        table.insert(b)

        table.setCapacity(40)
        assertEquals(40L, table.capacity())
        assertFailsWith<QpackException> { table.get(0) }
        assertEquals(b, table.get(1))

        table.setCapacity(0)
        assertFailsWith<QpackException> { table.get(1) }
        assertEquals(2L, table.insertCount())
    }

    @Test
    fun encoderStreamInstructionsAreHeldToTheSameRules() {
        val table = QpackDynamicTable(4096)
        val insert = QpackEncoderStream.encodeInsertWithNameReference(0, "example.com")

        val beforeCapacity = assertFailsWith<QpackException> {
            QpackEncoderStream.readInstruction(ByteArrayInputStream(insert), table)
        }
        assertEquals(Http3Exception.QPACK_ENCODER_STREAM_ERROR, beforeCapacity.errorCode())

        val input = ByteArrayInputStream(QpackEncoderStream.encodeSetCapacity(220) + insert)
        assertTrue(QpackEncoderStream.readInstruction(input, table))
        assertTrue(QpackEncoderStream.readInstruction(input, table))
        assertFalse(QpackEncoderStream.readInstruction(input, table))
        assertEquals(220L, table.capacity())
        assertEquals(FieldLine(":authority", "example.com"), table.get(0))

        val aboveMaximum = assertFailsWith<QpackException> {
            QpackEncoderStream.readInstruction(
                ByteArrayInputStream(QpackEncoderStream.encodeSetCapacity(4097)), table)
        }
        assertEquals(Http3Exception.QPACK_ENCODER_STREAM_ERROR, aboveMaximum.errorCode())
        assertEquals(220L, table.capacity())
    }

    @Test
    fun fieldSectionsReferencingTheTableDecodeAgainstTheAdvertisedMaximum() {
        // The wrapped Required Insert Count is sized by the advertised maximum, not by whatever
        // capacity the encoder chose, so a smaller capacity must not change how it decodes.
        val table = QpackDynamicTable(4096)
        table.setCapacity(220)
        val authority = FieldLine(":authority", "example.com")
        table.insert(authority)
        val fields = listOf(FieldLine(":method", "GET"), authority, FieldLine(":path", "/"))

        val encoded = QpackEncoder.encodeFieldSection(fields, QpackEncoder.DynamicEntry(authority, 0), 4096)
        val section = QpackDecoder.decodeSection(encoded, table)

        assertEquals(fields, section.fields())
        assertEquals(1L, section.requiredInsertCount())
    }
}
