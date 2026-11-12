package io.apkwarden.core.parser

import java.nio.ByteBuffer
import java.nio.ByteOrder

data class AxmlAttribute(
    val namespace: String?,
    val name: String,
    val value: String,
    val rawValue: String?,
    val resourceId: Int,
    val dataType: Int,
    val data: Int
) {
    val booleanValue: Boolean?
        get() = when (dataType) {
            0x12 -> data != 0 // TYPE_INT_BOOLEAN: any non-zero is true (aapt writes 0xFFFFFFFF)
            0x03 -> value.equals("true", ignoreCase = true) || value == "1"
            0x10, 0x11 -> data != 0
            else -> null
        }

    val isReference: Boolean
        get() = dataType == 0x01 // TYPE_REFERENCE
}

data class AxmlNode(
    val tag: String,
    val attributes: List<AxmlAttribute>,
    val children: List<AxmlNode>,
    val text: String? = null
) {
    fun findAttribute(name: String, resId: Int = 0, namespace: String? = null): AxmlAttribute? {
        return attributes.firstOrNull {
            (resId != 0 && it.resourceId == resId) ||
            (it.name == name && (namespace == null || it.namespace == namespace))
        } ?: attributes.firstOrNull { it.name == name }
    }

    fun findChildren(tag: String): List<AxmlNode> {
        return children.filter { it.tag == tag }
    }
}

object AndroidResIds {
    const val ATTR_NAME = 0x01010003
    const val ATTR_PERMISSION = 0x01010006
    const val ATTR_READ_PERMISSION = 0x01010007
    const val ATTR_WRITE_PERMISSION = 0x01010008
    const val ATTR_EXPORTED = 0x01010010
    const val ATTR_AUTHORITIES = 0x01010018
    const val ATTR_GRANT_URI_PERMISSIONS = 0x0101001b
    const val ATTR_SCHEME = 0x01010027
    const val ATTR_HOST = 0x01010028
    const val ATTR_PORT = 0x01010029
    const val ATTR_PATH = 0x0101002a
    const val ATTR_PATH_PREFIX = 0x0101002b
    const val ATTR_PATH_PATTERN = 0x0101002c
    const val ATTR_MIME_TYPE = 0x01010026
    const val ATTR_AUTOVERIFY = 0x010104e1
}

class AxmlParser(private val bytes: ByteArray) {

    fun parse(): AxmlNode {
        require(bytes.size >= 8) { "AXML bytes too short" }
        val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)

        val fileType = buffer.short.toInt() and 0xFFFF
        val headerSize = buffer.short.toInt() and 0xFFFF
        val fileSize = buffer.int

        require(fileType == RES_XML_TYPE) { "Invalid AXML magic: 0x${fileType.toString(16)}" }

        var stringPool: List<String> = emptyList()
        var resourceIds: List<Int> = emptyList()

        val nodeStack = mutableListOf<MutableNode>()
        var rootNode: AxmlNode? = null

        while (buffer.hasRemaining()) {
            val chunkStart = buffer.position()
            if (buffer.remaining() < 8) break

            val chunkType = buffer.short.toInt() and 0xFFFF
            val chunkHeaderSize = buffer.short.toInt() and 0xFFFF
            val chunkSize = buffer.int

            if (chunkSize <= 0 || chunkStart + chunkSize > bytes.size) {
                break
            }

            when (chunkType) {
                RES_STRING_POOL_TYPE -> {
                    stringPool = parseStringPool(buffer, chunkStart, chunkSize)
                    buffer.position(chunkStart + chunkSize)
                }
                RES_XML_RESOURCE_MAP_TYPE -> {
                    val count = (chunkSize - chunkHeaderSize) / 4
                    val ids = mutableListOf<Int>()
                    for (i in 0 until count) {
                        ids.add(buffer.int)
                    }
                    resourceIds = ids
                    buffer.position(chunkStart + chunkSize)
                }
                RES_XML_START_ELEMENT_TYPE -> {
                    buffer.int // line number
                    buffer.int // comment
                    val nsIdx = buffer.int
                    val nameIdx = buffer.int
                    buffer.short // attrStart
                    buffer.short // attrSize
                    val attrCount = buffer.short.toInt() and 0xFFFF
                    buffer.short // idIndex
                    buffer.short // classIndex
                    buffer.short // styleIndex

                    val tag = getString(stringPool, nameIdx) ?: "unknown"
                    val attributes = mutableListOf<AxmlAttribute>()

                    for (i in 0 until attrCount) {
                        val aNsIdx = buffer.int
                        val aNameIdx = buffer.int
                        val aRawValIdx = buffer.int
                        val aSize = buffer.short.toInt() and 0xFFFF
                        val aRes0 = buffer.get().toInt() and 0xFF
                        val aDataType = buffer.get().toInt() and 0xFF
                        val aData = buffer.int

                        val attrNs = getString(stringPool, aNsIdx)
                        val attrName = getString(stringPool, aNameIdx) ?: "attr_$i"
                        val attrRawVal = getString(stringPool, aRawValIdx)
                        val resId = if (aNameIdx in resourceIds.indices) resourceIds[aNameIdx] else 0

                        val resolvedVal = formatTypedValue(aDataType, aData, attrRawVal, stringPool)

                        attributes.add(
                            AxmlAttribute(
                                namespace = attrNs,
                                name = attrName,
                                value = resolvedVal,
                                rawValue = attrRawVal,
                                resourceId = resId,
                                dataType = aDataType,
                                data = aData
                            )
                        )
                    }

                    val current = MutableNode(tag, attributes)
                    if (nodeStack.isNotEmpty()) {
                        nodeStack.last().children.add(current)
                    } else if (rootNode == null) {
                        // Will be converted when popped
                    }
                    nodeStack.add(current)
                    buffer.position(chunkStart + chunkSize)
                }
                RES_XML_END_ELEMENT_TYPE -> {
                    if (nodeStack.isNotEmpty()) {
                        val popped = nodeStack.removeAt(nodeStack.lastIndex)
                        if (nodeStack.isEmpty()) {
                            rootNode = popped.toImmutable()
                        }
                    }
                    buffer.position(chunkStart + chunkSize)
                }
                RES_XML_CDATA_TYPE -> {
                    buffer.int // line
                    buffer.int // comment
                    val dataIdx = buffer.int
                    buffer.int // typed_data size
                    val cdata = getString(stringPool, dataIdx)
                    if (nodeStack.isNotEmpty()) {
                        nodeStack.last().text = cdata
                    }
                    buffer.position(chunkStart + chunkSize)
                }
                else -> {
                    buffer.position(chunkStart + chunkSize)
                }
            }
        }

        return rootNode ?: throw IllegalStateException("Failed to parse root XML element from AXML")
    }

    private fun parseStringPool(buffer: ByteBuffer, chunkStart: Int, chunkSize: Int): List<String> {
        val stringCount = buffer.int
        val styleCount = buffer.int
        val flags = buffer.int
        val stringsStart = buffer.int
        val stylesStart = buffer.int

        val isUtf8 = (flags and (1 shl 8)) != 0

        val stringOffsets = IntArray(stringCount)
        for (i in 0 until stringCount) {
            stringOffsets[i] = buffer.int
        }

        val stringsAbsoluteStart = chunkStart + stringsStart
        val strings = ArrayList<String>(stringCount)

        for (i in 0 until stringCount) {
            val offset = stringsAbsoluteStart + stringOffsets[i]
            if (offset >= bytes.size) {
                strings.add("")
                continue
            }
            val str = if (isUtf8) {
                readUtf8String(bytes, offset)
            } else {
                readUtf16String(bytes, offset)
            }
            strings.add(str)
        }

        return strings
    }

    private fun readUtf8String(data: ByteArray, offset: Int): String {
        var pos = offset
        if (pos >= data.size) return ""
        // Length in characters (varint)
        var charLen = data[pos].toInt() and 0xFF
        if ((charLen and 0x80) != 0) {
            pos++
            if (pos < data.size) {
                charLen = ((charLen and 0x7F) shl 8) or (data[pos].toInt() and 0xFF)
            }
        }
        pos++
        if (pos >= data.size) return ""

        // Length in bytes (varint)
        var byteLen = data[pos].toInt() and 0xFF
        if ((byteLen and 0x80) != 0) {
            pos++
            if (pos < data.size) {
                byteLen = ((byteLen and 0x7F) shl 8) or (data[pos].toInt() and 0xFF)
            }
        }
        pos++
        if (pos + byteLen > data.size) {
            byteLen = data.size - pos
        }
        return if (byteLen > 0) String(data, pos, byteLen, Charsets.UTF_8) else ""
    }

    private fun readUtf16String(data: ByteArray, offset: Int): String {
        var pos = offset
        if (pos + 2 > data.size) return ""
        val charLen = (data[pos].toInt() and 0xFF) or ((data[pos + 1].toInt() and 0xFF) shl 8)
        pos += 2
        val byteLen = charLen * 2
        if (pos + byteLen > data.size) return ""
        return String(data, pos, byteLen, Charsets.UTF_16LE)
    }

    private fun getString(pool: List<String>, index: Int): String? {
        return if (index in pool.indices) pool[index] else null
    }

    private fun formatTypedValue(dataType: Int, data: Int, rawValue: String?, pool: List<String>): String {
        return when (dataType) {
            0x03 -> getString(pool, data) ?: rawValue ?: "" // TYPE_STRING
            0x12 -> if (data != 0) "true" else "false" // TYPE_INT_BOOLEAN
            0x01 -> "@0x${data.toString(16)}" // TYPE_REFERENCE
            0x10 -> data.toString() // TYPE_INT_DEC
            0x11 -> "0x${data.toString(16)}" // TYPE_INT_HEX
            else -> rawValue ?: data.toString()
        }
    }

    private class MutableNode(
        val tag: String,
        val attributes: List<AxmlAttribute>,
        val children: MutableList<MutableNode> = mutableListOf(),
        var text: String? = null
    ) {
        fun toImmutable(): AxmlNode = AxmlNode(tag, attributes, children.map { it.toImmutable() }, text)
    }

    companion object {
        private const val RES_XML_TYPE = 0x0003
        private const val RES_STRING_POOL_TYPE = 0x0001
        private const val RES_XML_RESOURCE_MAP_TYPE = 0x0180
        private const val RES_XML_START_ELEMENT_TYPE = 0x0102
        private const val RES_XML_END_ELEMENT_TYPE = 0x0103
        private const val RES_XML_CDATA_TYPE = 0x0104
    }
}
