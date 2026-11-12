package io.apkwarden.core

import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class SampleGeneratorTest {

    @Test
    fun `generate sample apk for CLI testing`() {
        val rootDir = File("..").canonicalFile
        val samplesDir = File(rootDir, "samples").apply { mkdirs() }
        val sampleApk = File(samplesDir, "sample-vulnerable.apk")

        if (sampleApk.exists()) return

        val axml = createSampleAxml()
        val dex = "dummy dex content ~~R8{backend:dex,compilation-mode:release,min-api:24,pg-map-id:map-hash-sample,version:8.4.10}".toByteArray()
        val dummySo = ByteArray(128).also {
            it[0] = 0x7F.toByte()
            it[1] = 'E'.code.toByte()
            it[2] = 'L'.code.toByte()
            it[3] = 'F'.code.toByte()
        }

        FileOutputStream(sampleApk).use { fos ->
            ZipOutputStream(fos).use { zos ->
                zos.putNextEntry(ZipEntry("AndroidManifest.xml"))
                zos.write(axml)
                zos.closeEntry()

                zos.putNextEntry(ZipEntry("classes.dex"))
                zos.write(dex)
                zos.closeEntry()

                zos.putNextEntry(ZipEntry("lib/arm64-v8a/libcrypto_native.so"))
                zos.write(dummySo)
                zos.closeEntry()
            }
        }
    }

    private fun createSampleAxml(): ByteArray {
        val strings = listOf(
            "manifest",               // 0
            "package",                // 1
            "com.example.vulnerable",// 2
            "uses-sdk",               // 3
            "minSdkVersion",          // 4
            "targetSdkVersion",       // 5
            "application",            // 6
            "activity",               // 7
            "name",                   // 8
            ".DeepLinkActivity",      // 9
            "exported",               // 10
            "intent-filter",          // 11
            "action",                 // 12
            "android.intent.action.VIEW", // 13
            "category",               // 14
            "android.intent.category.BROWSABLE", // 15
            "data",                   // 16
            "scheme",                 // 17
            "https",                  // 18
            "vulnerable",             // 19
            "host",                   // 20
            "pay.example.com",        // 21
            "path",                   // 22
            "/checkout",              // 23
            "autoVerify"              // 24
        )

        val stringPoolBytes = buildStringPool(strings)

        val data1Attr = ByteArrayOutputStream().apply {
            writeAttr(this, -1, 17, 18, 0x03, 18)
            writeAttr(this, -1, 20, 21, 0x03, 21)
            writeAttr(this, -1, 22, 23, 0x03, 23)
        }.toByteArray()
        val data1Elem = buildElementChunk(16, data1Attr, 3, emptyList())

        val data2Attr = ByteArrayOutputStream().apply {
            writeAttr(this, -1, 17, 19, 0x03, 19)
        }.toByteArray()
        val data2Elem = buildElementChunk(16, data2Attr, 1, emptyList())

        val actionAttr = ByteArrayOutputStream().apply {
            writeAttr(this, -1, 8, 13, 0x03, 13)
        }.toByteArray()
        val actionElem = buildElementChunk(12, actionAttr, 1, emptyList())

        val catAttr = ByteArrayOutputStream().apply {
            writeAttr(this, -1, 8, 15, 0x03, 15)
        }.toByteArray()
        val catElem = buildElementChunk(14, catAttr, 1, emptyList())

        val filterAttr = ByteArrayOutputStream().apply {
            writeAttr(this, -1, 24, -1, 0x12, 1)
        }.toByteArray()
        val filterElem = buildElementChunk(11, filterAttr, 1, listOf(actionElem, catElem, data1Elem, data2Elem))

        val actAttr = ByteArrayOutputStream().apply {
            writeAttr(this, -1, 8, 9, 0x03, 9)
            writeAttr(this, -1, 10, -1, 0x12, 1)
        }.toByteArray()
        val actElem = buildElementChunk(7, actAttr, 2, listOf(filterElem))

        val appElem = buildElementChunk(6, ByteArray(0), 0, listOf(actElem))

        val sdkAttr = ByteArrayOutputStream().apply {
            writeAttr(this, -1, 4, -1, 0x10, 24)
            writeAttr(this, -1, 5, -1, 0x10, 33)
        }.toByteArray()
        val sdkElem = buildElementChunk(3, sdkAttr, 2, emptyList())

        val manifestAttr = ByteArrayOutputStream().apply {
            writeAttr(this, -1, 1, 2, 0x03, 2)
        }.toByteArray()
        val manifestElem = buildElementChunk(0, manifestAttr, 1, listOf(sdkElem, appElem))

        val totalSize = 8 + stringPoolBytes.size + manifestElem.size
        val out = ByteBuffer.allocate(totalSize).order(ByteOrder.LITTLE_ENDIAN)
        out.putShort(0x0003.toShort())
        out.putShort(8.toShort())
        out.putInt(totalSize)
        out.put(stringPoolBytes)
        out.put(manifestElem)

        return out.array()
    }

    private fun writeAttr(baos: ByteArrayOutputStream, ns: Int, name: Int, raw: Int, type: Int, data: Int) {
        val buf = ByteBuffer.allocate(20).order(ByteOrder.LITTLE_ENDIAN)
        buf.putInt(ns)
        buf.putInt(name)
        buf.putInt(raw)
        buf.putShort(8.toShort())
        buf.put(0.toByte())
        buf.put(type.toByte())
        buf.putInt(data)
        baos.write(buf.array())
    }

    private fun buildElementChunk(nameIdx: Int, attrs: ByteArray, attrCount: Int, children: List<ByteArray>): ByteArray {
        val startHeaderSize = 36
        val startChunkSize = startHeaderSize + attrs.size
        val endChunkSize = 24
        val totalChildSize = children.sumOf { it.size }
        val totalSize = startChunkSize + totalChildSize + endChunkSize

        val buf = ByteBuffer.allocate(totalSize).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(0x0102.toShort())
        buf.putShort(16.toShort())
        buf.putInt(startChunkSize)
        buf.putInt(1)
        buf.putInt(-1)
        buf.putInt(-1)
        buf.putInt(nameIdx)
        buf.putShort(20.toShort())
        buf.putShort(20.toShort())
        buf.putShort(attrCount.toShort())
        buf.putShort(0.toShort())
        buf.putShort(0.toShort())
        buf.putShort(0.toShort())
        buf.put(attrs)

        for (child in children) buf.put(child)

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
        val offsets = IntArray(count)
        val data = ByteArrayOutputStream()
        for (i in strings.indices) {
            offsets[i] = data.size()
            val sBytes = strings[i].toByteArray(Charsets.UTF_8)
            data.write(sBytes.size)
            data.write(sBytes.size)
            data.write(sBytes)
            data.write(0)
        }
        while (data.size() % 4 != 0) data.write(0)

        val headerSize = 28
        val stringsStart = headerSize + count * 4
        val totalSize = stringsStart + data.size()

        val buf = ByteBuffer.allocate(totalSize).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(0x0001.toShort())
        buf.putShort(headerSize.toShort())
        buf.putInt(totalSize)
        buf.putInt(count)
        buf.putInt(0)
        buf.putInt(1 shl 8)
        buf.putInt(stringsStart)
        buf.putInt(0)
        for (off in offsets) buf.putInt(off)
        buf.put(data.toByteArray())
        return buf.array()
    }
}
