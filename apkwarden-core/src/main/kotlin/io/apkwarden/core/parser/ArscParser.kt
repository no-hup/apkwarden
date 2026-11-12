package io.apkwarden.core.parser

import java.nio.ByteBuffer
import java.nio.ByteOrder

data class ResourceEntry(
    val id: Int,
    val typeName: String,
    val keyName: String,
    val value: String,
    val rawValue: Any?,
    val configQualifier: String = "default",
    val minSdkQualifier: Int? = null
)

class ArscParser(private val bytes: ByteArray) {

    private val entriesById = mutableMapOf<Int, MutableList<ResourceEntry>>()
    private val stringPool = mutableListOf<String>()

    fun parse(): Map<Int, List<ResourceEntry>> {
        if (bytes.size < 12) return emptyMap()
        val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)

        val tableType = buffer.short.toInt() and 0xFFFF
        val headerSize = buffer.short.toInt() and 0xFFFF
        val totalSize = buffer.int
        val packageCount = buffer.int

        if (tableType != RES_TABLE_TYPE) return emptyMap()

        var currentTypeStrings = listOf<String>()
        var currentKeyStrings = listOf<String>()
        var currentPackageId = 0x7f

        while (buffer.hasRemaining()) {
            val chunkStart = buffer.position()
            if (buffer.remaining() < 8) break

            val chunkType = buffer.short.toInt() and 0xFFFF
            val chunkHeaderSize = buffer.short.toInt() and 0xFFFF
            val chunkSize = buffer.int

            if (chunkSize <= 0 || chunkStart + chunkSize > bytes.size) break

            when (chunkType) {
                RES_STRING_POOL_TYPE -> {
                    // Global string pool (only if not already read)
                    if (stringPool.isEmpty()) {
                        stringPool.addAll(parseStringPool(buffer, chunkStart, chunkSize))
                    }
                    buffer.position(chunkStart + chunkSize)
                }
                RES_TABLE_PACKAGE_TYPE -> {
                    currentPackageId = buffer.int
                    // Read package name (128 utf-16 characters)
                    val pkgNameBytes = ByteArray(256)
                    buffer.get(pkgNameBytes)
                    val typeStringsOffset = buffer.int
                    buffer.int // lastPublicType
                    val keyStringsOffset = buffer.int
                    buffer.int // lastPublicKey

                    // Read package string pools if present
                    if (typeStringsOffset > 0) {
                        val pos = chunkStart + typeStringsOffset
                        val typeBuf = ByteBuffer.wrap(bytes, pos, bytes.size - pos).order(ByteOrder.LITTLE_ENDIAN)
                        val typeHdr = typeBuf.short.toInt() and 0xFFFF
                        if (typeHdr == RES_STRING_POOL_TYPE) {
                            val hdrSz = typeBuf.short.toInt() and 0xFFFF
                            val sz = typeBuf.int
                            currentTypeStrings = parseStringPool(typeBuf, pos, sz)
                        }
                    }

                    if (keyStringsOffset > 0) {
                        val pos = chunkStart + keyStringsOffset
                        val keyBuf = ByteBuffer.wrap(bytes, pos, bytes.size - pos).order(ByteOrder.LITTLE_ENDIAN)
                        val keyHdr = keyBuf.short.toInt() and 0xFFFF
                        if (keyHdr == RES_STRING_POOL_TYPE) {
                            val hdrSz = keyBuf.short.toInt() and 0xFFFF
                            val sz = keyBuf.int
                            currentKeyStrings = parseStringPool(keyBuf, pos, sz)
                        }
                    }

                    buffer.position(chunkStart + chunkHeaderSize)
                }
                RES_TABLE_TYPE_TYPE -> {
                    parseTypeChunk(buffer, chunkStart, chunkHeaderSize, chunkSize, currentPackageId, currentTypeStrings, currentKeyStrings)
                    buffer.position(chunkStart + chunkSize)
                }
                else -> {
                    buffer.position(chunkStart + chunkSize)
                }
            }
        }

        return entriesById
    }

    private fun parseTypeChunk(
        buffer: ByteBuffer,
        chunkStart: Int,
        chunkHeaderSize: Int,
        chunkSize: Int,
        packageId: Int,
        typeStrings: List<String>,
        keyStrings: List<String>
    ) {
        val typeId = buffer.get().toInt() and 0xFF
        val res0 = buffer.get()
        val res1 = buffer.short
        val entryCount = buffer.int
        val entriesStart = buffer.int

        // Config qualifier parsing
        // Config structure starts at offset 16 within the chunk
        var minSdk: Int? = null
        var qualifier = "default"

        val configSize = chunkHeaderSize - 16
        if (configSize >= 48) { // standard ResTable_config size
            val configStart = chunkStart + 16
            // sdkVersion is at offset 36 in ResTable_config
            if (configStart + 38 <= bytes.size) {
                val sdkVer = (bytes[configStart + 36].toInt() and 0xFF) or ((bytes[configStart + 37].toInt() and 0xFF) shl 8)
                if (sdkVer > 0) {
                    minSdk = sdkVer
                    qualifier = "v$sdkVer"
                }
            }
        }

        buffer.position(chunkStart + chunkHeaderSize)
        val entryOffsets = IntArray(entryCount)
        for (i in 0 until entryCount) {
            entryOffsets[i] = buffer.int
        }

        val entriesBase = chunkStart + entriesStart
        val typeName = if (typeId - 1 in typeStrings.indices) typeStrings[typeId - 1] else "type_$typeId"

        for (i in 0 until entryCount) {
            val offset = entryOffsets[i]
            if (offset == -1 || offset < 0) continue

            val entryPos = entriesBase + offset
            if (entryPos + 8 > bytes.size) continue

            val entryBuf = ByteBuffer.wrap(bytes, entryPos, bytes.size - entryPos).order(ByteOrder.LITTLE_ENDIAN)
            val size = entryBuf.short.toInt() and 0xFFFF
            val flags = entryBuf.short.toInt() and 0xFFFF
            val keyIndex = entryBuf.int

            val keyName = if (keyIndex in keyStrings.indices) keyStrings[keyIndex] else "key_$i"
            val isComplex = (flags and 0x0001) != 0

            val resId = (packageId shl 24) or (typeId shl 16) or i

            if (!isComplex && entryPos + size + 8 <= bytes.size) {
                entryBuf.position(size)
                if (entryBuf.remaining() >= 8) {
                    val valSize = entryBuf.short.toInt() and 0xFFFF
                    val res0Val = entryBuf.get()
                    val dataType = entryBuf.get().toInt() and 0xFF
                    val data = entryBuf.int

                    val (formattedVal, rawVal) = decodeResValue(dataType, data)
                    val entry = ResourceEntry(
                        id = resId,
                        typeName = typeName,
                        keyName = keyName,
                        value = formattedVal,
                        rawValue = rawVal,
                        configQualifier = qualifier,
                        minSdkQualifier = minSdk
                    )

                    entriesById.getOrPut(resId) { mutableListOf() }.add(entry)
                }
            }
        }
    }

    private fun decodeResValue(dataType: Int, data: Int): Pair<String, Any?> {
        return when (dataType) {
            0x03 -> { // TYPE_STRING
                val str = if (data in stringPool.indices) stringPool[data] else "str_$data"
                str to str
            }
            0x12 -> { // TYPE_INT_BOOLEAN
                val bool = data != 0
                bool.toString() to bool
            }
            0x01 -> { // TYPE_REFERENCE
                val refStr = "@0x${data.toString(16)}"
                refStr to data
            }
            0x10 -> data.toString() to data // TYPE_INT_DEC
            0x11 -> "0x${data.toString(16)}" to data // TYPE_INT_HEX
            else -> data.toString() to data
        }
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
        var charLen = data[pos].toInt() and 0xFF
        if ((charLen and 0x80) != 0) {
            pos++
            if (pos < data.size) {
                charLen = ((charLen and 0x7F) shl 8) or (data[pos].toInt() and 0xFF)
            }
        }
        pos++
        if (pos >= data.size) return ""

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

    fun resolveString(resId: Int): String? {
        val entry = entriesById[resId]?.firstOrNull() ?: return null
        return entry.value
    }

    fun resolveBoolean(resId: Int, targetSdk: Int = 34): Boolean? {
        val candidates = entriesById[resId] ?: return null
        // Pick the most specific config matching targetSdk
        val matching = candidates
            .filter { it.minSdkQualifier == null || it.minSdkQualifier <= targetSdk }
            .maxByOrNull { it.minSdkQualifier ?: 0 }
            ?: candidates.firstOrNull()

        return matching?.rawValue as? Boolean
    }

    fun resolvePath(resId: Int): String? {
        val entry = entriesById[resId]?.firstOrNull() ?: return null
        return entry.value
    }

    companion object {
        private const val RES_TABLE_TYPE = 0x0002
        private const val RES_STRING_POOL_TYPE = 0x0001
        private const val RES_TABLE_PACKAGE_TYPE = 0x0200
        private const val RES_TABLE_TYPE_TYPE = 0x0201
    }
}
