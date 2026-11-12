package io.apkwarden.core.parser

import java.nio.ByteBuffer

/**
 * Zero-dependency AAPT2 compiled XML protobuf decoder.
 * Used for parsing AndroidManifest.xml from Android App Bundles (.aab),
 * where AAPT2 writes aapt.pb.XmlNode instead of standard binary AXML.
 */
class ProtoXmlDecoder(private val buffer: ByteBuffer) {

    private fun readVarint(): Long {
        var result = 0L
        var shift = 0
        while (buffer.hasRemaining()) {
            val b = buffer.get().toLong()
            result = result or ((b and 0x7FL) shl shift)
            if ((b and 0x80L) == 0L) return result
            shift += 7
            if (shift > 64) break
        }
        return result
    }

    private fun readString(length: Int): String {
        val bytes = ByteArray(length)
        buffer.get(bytes)
        return String(bytes, Charsets.UTF_8)
    }

    private fun skipField(wireType: Int) {
        when (wireType) {
            0 -> readVarint() // varint
            1 -> buffer.position(buffer.position() + 8) // 64-bit
            2 -> {
                val len = readVarint().toInt()
                buffer.position(buffer.position() + len) // length-delimited
            }
            5 -> buffer.position(buffer.position() + 4) // 32-bit
            else -> {}
        }
    }

    fun decodeNode(): AxmlNode {
        var element: AxmlNode? = null
        var text: String? = null

        while (buffer.hasRemaining()) {
            val tag = readVarint().toInt()
            val fieldNum = tag ushr 3
            val wireType = tag and 0x07

            when (fieldNum) {
                2 -> { // XmlElement
                    val len = readVarint().toInt()
                    val slice = buffer.slice()
                    slice.limit(len)
                    element = ProtoXmlDecoder(slice).decodeElement()
                    buffer.position(buffer.position() + len)
                }
                3 -> { // text
                    val len = readVarint().toInt()
                    text = readString(len)
                }
                else -> skipField(wireType)
            }
        }

        return element ?: AxmlNode(tag = "empty", attributes = emptyList(), children = emptyList(), text = text)
    }

    fun decodeElement(): AxmlNode {
        var name = ""
        val attributes = mutableListOf<AxmlAttribute>()
        val children = mutableListOf<AxmlNode>()

        while (buffer.hasRemaining()) {
            val tag = readVarint().toInt()
            val fieldNum = tag ushr 3
            val wireType = tag and 0x07

            when (fieldNum) {
                3 -> { // name
                    val len = readVarint().toInt()
                    name = readString(len)
                }
                4 -> { // attribute
                    val len = readVarint().toInt()
                    val slice = buffer.slice()
                    slice.limit(len)
                    attributes.add(ProtoXmlDecoder(slice).decodeAttribute())
                    buffer.position(buffer.position() + len)
                }
                5 -> { // child (XmlNode)
                    val len = readVarint().toInt()
                    val slice = buffer.slice()
                    slice.limit(len)
                    children.add(ProtoXmlDecoder(slice).decodeNode())
                    buffer.position(buffer.position() + len)
                }
                else -> skipField(wireType)
            }
        }

        return AxmlNode(
            tag = name,
            attributes = attributes,
            children = children
        )
    }

    fun decodeAttribute(): AxmlAttribute {
        var namespace: String? = null
        var name = ""
        var value = ""
        var resId = 0

        while (buffer.hasRemaining()) {
            val tag = readVarint().toInt()
            val fieldNum = tag ushr 3
            val wireType = tag and 0x07

            when (fieldNum) {
                1 -> { // namespace_uri
                    val len = readVarint().toInt()
                    namespace = readString(len)
                }
                2 -> { // name
                    val len = readVarint().toInt()
                    name = readString(len)
                }
                3 -> { // value
                    val len = readVarint().toInt()
                    value = readString(len)
                }
                5 -> { // resource_id
                    resId = readVarint().toInt()
                }
                else -> skipField(wireType)
            }
        }

        val dataType = when {
            value.equals("true", ignoreCase = true) || value.equals("false", ignoreCase = true) -> 0x12 // TYPE_INT_BOOLEAN
            value.startsWith("@") -> 0x01 // TYPE_REFERENCE
            value.toIntOrNull() != null -> 0x10 // TYPE_INT_DEC
            else -> 0x03 // TYPE_STRING
        }
        val data = when (dataType) {
            0x12 -> if (value.equals("true", ignoreCase = true)) 1 else 0
            0x10 -> value.toIntOrNull() ?: 0
            0x01 -> value.removePrefix("@").toIntOrNull(16) ?: 0
            else -> 0
        }

        return AxmlAttribute(
            namespace = namespace,
            name = name,
            value = value,
            rawValue = value,
            resourceId = resId,
            dataType = dataType,
            data = data
        )
    }

    companion object {
        fun decode(bytes: ByteArray): AxmlNode {
            return ProtoXmlDecoder(ByteBuffer.wrap(bytes)).decodeNode()
        }
    }
}
