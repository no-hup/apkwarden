package io.apkwarden.core.parser

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

class AxmlParserTest {

    @Test
    fun `parses binary XML document correctly`() {
        val strings = listOf(
            "manifest",       // 0
            "package",        // 1
            "com.example.app",// 2
            "activity",       // 3
            "name",           // 4
            ".MainActivity",  // 5
            "exported"        // 6
        )

        val axmlBytes = buildSimpleAxml(strings)
        val parser = AxmlParser(axmlBytes)
        val root = parser.parse()

        assertThat(root.tag).isEqualTo("manifest")
        assertThat(root.findAttribute("package")?.value).isEqualTo("com.example.app")

        val activities = root.findChildren("activity")
        assertThat(activities).hasSize(1)
        val mainActivity = activities[0]
        assertThat(mainActivity.findAttribute("name")?.value).isEqualTo(".MainActivity")
        assertThat(mainActivity.findAttribute("exported")?.booleanValue).isTrue()
    }

    private fun buildSimpleAxml(strings: List<String>): ByteArray {
        val stringPoolBytes = buildStringPool(strings)

        // Element: activity
        val activityAttrBytes = ByteArrayOutputStream()
        // attr 1: name=".MainActivity"
        writeAttr(activityAttrBytes, nsIdx = -1, nameIdx = 4, rawValIdx = 5, dataType = 0x03, data = 5)
        // attr 2: exported=true (TYPE_INT_BOOLEAN = 0x12, data = 1)
        writeAttr(activityAttrBytes, nsIdx = -1, nameIdx = 6, rawValIdx = -1, dataType = 0x12, data = 1)

        val activityElemBytes = buildElementChunk(
            nameIdx = 3,
            attributes = activityAttrBytes.toByteArray(),
            attrCount = 2,
            children = emptyList()
        )

        // Root Element: manifest
        val manifestAttrBytes = ByteArrayOutputStream()
        // attr 1: package="com.example.app"
        writeAttr(manifestAttrBytes, nsIdx = -1, nameIdx = 1, rawValIdx = 2, dataType = 0x03, data = 2)

        val manifestElemBytes = buildElementChunk(
            nameIdx = 0,
            attributes = manifestAttrBytes.toByteArray(),
            attrCount = 1,
            children = listOf(activityElemBytes)
        )

        val totalSize = 8 + stringPoolBytes.size + manifestElemBytes.size
        val out = ByteBuffer.allocate(totalSize).order(ByteOrder.LITTLE_ENDIAN)
        out.putShort(0x0003.toShort()) // RES_XML_TYPE
        out.putShort(8.toShort())      // header size
        out.putInt(totalSize)

        out.put(stringPoolBytes)
        out.put(manifestElemBytes)

        return out.array()
    }

    private fun writeAttr(
        baos: ByteArrayOutputStream,
        nsIdx: Int,
        nameIdx: Int,
        rawValIdx: Int,
        dataType: Int,
        data: Int
    ) {
        val buf = ByteBuffer.allocate(20).order(ByteOrder.LITTLE_ENDIAN)
        buf.putInt(nsIdx)
        buf.putInt(nameIdx)
        buf.putInt(rawValIdx)
        buf.putShort(8.toShort()) // size
        buf.put(0.toByte())       // res0
        buf.put(dataType.toByte())
        buf.putInt(data)
        baos.write(buf.array())
    }

    private fun buildElementChunk(
        nameIdx: Int,
        attributes: ByteArray,
        attrCount: Int,
        children: List<ByteArray>
    ): ByteArray {
        val startHeaderSize = 36
        val startChunkSize = startHeaderSize + attributes.size
        val endChunkSize = 24

        val totalChildSize = children.sumOf { it.size }
        val totalSize = startChunkSize + totalChildSize + endChunkSize

        val buf = ByteBuffer.allocate(totalSize).order(ByteOrder.LITTLE_ENDIAN)

        // START_ELEMENT
        buf.putShort(0x0102.toShort())
        buf.putShort(16.toShort())
        buf.putInt(startChunkSize)
        buf.putInt(1) // line
        buf.putInt(-1) // comment
        buf.putInt(-1) // ns
        buf.putInt(nameIdx)
        buf.putShort(20.toShort()) // attrStart
        buf.putShort(20.toShort()) // attrSize
        buf.putShort(attrCount.toShort())
        buf.putShort(0.toShort())
        buf.putShort(0.toShort())
        buf.putShort(0.toShort())
        buf.put(attributes)

        // Children
        for (child in children) {
            buf.put(child)
        }

        // END_ELEMENT
        buf.putShort(0x0103.toShort())
        buf.putShort(16.toShort())
        buf.putInt(endChunkSize)
        buf.putInt(1)
        buf.putInt(-1)
        buf.putInt(-1)
        buf.putInt(nameIdx)

        return buf.array()
    }

    private fun buildStringPool(strings: List<String>): ByteArray {
        val count = strings.size
        val stringOffsets = IntArray(count)

        val strData = ByteArrayOutputStream()
        for (i in strings.indices) {
            stringOffsets[i] = strData.size()
            val s = strings[i]
            // UTF-8 string encoding for AXML
            val bytes = s.toByteArray(Charsets.UTF_8)
            strData.write(bytes.size)
            strData.write(bytes.size)
            strData.write(bytes)
            strData.write(0) // null terminator
        }

        // pad to 4 bytes
        while (strData.size() % 4 != 0) {
            strData.write(0)
        }

        val headerSize = 28
        val stringsStart = headerSize + count * 4
        val totalSize = stringsStart + strData.size()

        val buf = ByteBuffer.allocate(totalSize).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(0x0001.toShort()) // RES_STRING_POOL_TYPE
        buf.putShort(headerSize.toShort())
        buf.putInt(totalSize)
        buf.putInt(count)
        buf.putInt(0) // style count
        buf.putInt(1 shl 8) // UTF-8 flag
        buf.putInt(stringsStart)
        buf.putInt(0) // stylesStart

        for (offset in stringOffsets) {
            buf.putInt(offset)
        }
        buf.put(strData.toByteArray())

        return buf.array()
    }
}
