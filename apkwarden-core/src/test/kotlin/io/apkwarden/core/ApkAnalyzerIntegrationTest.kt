package io.apkwarden.core

import io.apkwarden.core.lock.SurfaceLockGenerator
import io.apkwarden.core.model.ComponentType
import io.apkwarden.core.model.RuntimeStack
import io.apkwarden.core.parser.AxmlParserTest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class ApkAnalyzerIntegrationTest {

    @Test
    fun `end to end analysis of synthetic apk produces surface and lockfile`(@TempDir tempDir: File) {
        val apkFile = File(tempDir, "sample-release.apk")
        buildSyntheticApk(apkFile)

        val result = ApkAnalyzer.analyze(apkFile)

        // 1. Ingest
        assertThat(result.isAab).isFalse()
        assertThat(result.isSplitSet).isFalse()

        // 2. Attack Surface
        assertThat(result.attackSurface.packageName).isEqualTo("com.example.secureapp")
        assertThat(result.attackSurface.exportedComponents).hasSize(1)
        val exportedAct = result.attackSurface.exportedComponents.first()
        assertThat(exportedAct.name).isEqualTo("com.example.secureapp.DeepLinkActivity")
        assertThat(exportedAct.type).isEqualTo(ComponentType.ACTIVITY)

        // 3. Deep links (cartesian product of 2 schemes x 1 host x 1 path = 2 links)
        assertThat(result.attackSurface.deepLinks).hasSize(2)
        assertThat(result.attackSurface.deepLinks).anyMatch { it.scheme == "https" && it.host == "app.example.com" && it.path == "/auth" && it.autoVerify }
        assertThat(result.attackSurface.deepLinks).anyMatch { it.scheme == "sample" && it.host == "app.example.com" && it.path == "/auth" && !it.autoVerify }

        // 4. Fingerprint & R8 Marker
        assertThat(result.fingerprint.primaryStack).isEqualTo(RuntimeStack.PURE_DEX)
        assertThat(result.fingerprint.compilerMarker?.compiler).isEqualTo("R8")
        assertThat(result.fingerprint.compilerMarker?.isFullMode).isTrue()
        assertThat(result.fingerprint.compilerMarker?.pgMapId).isEqualTo("map-hash-1234")
        assertThat(result.fingerprint.nativeLibraries).hasSize(1)
        assertThat(result.fingerprint.nativeLibraries.first().name).isEqualTo("libcrypto_jni.so")

        // 5. Surface Lock
        val lockJson = SurfaceLockGenerator.serialize(result.surfaceLock)
        val lockFile = File(tempDir, "surface.lock.json")
        lockFile.writeText(lockJson)

        assertThat(lockFile).exists()
        assertThat(lockJson).contains("\"packageName\": \"com.example.secureapp\"")
        assertThat(lockJson).contains("\"com.example.secureapp.DeepLinkActivity\"")
        assertThat(result.surfaceLock.sha256Fingerprint).isNotEmpty()
    }

    private fun buildSyntheticApk(dest: File) {
        val axml = createSyntheticAxml()
        val dex = "dummy dex content ~~R8{backend:dex,compilation-mode:release,min-api:26,pg-map-id:map-hash-1234,version:8.4.10}".toByteArray()
        val dummySo = ByteArray(128).also {
            // Put ELF magic at start
            it[0] = 0x7F.toByte()
            it[1] = 'E'.code.toByte()
            it[2] = 'L'.code.toByte()
            it[3] = 'F'.code.toByte()
        }

        FileOutputStream(dest).use { fos ->
            ZipOutputStream(fos).use { zos ->
                zos.putNextEntry(ZipEntry("AndroidManifest.xml"))
                zos.write(axml)
                zos.closeEntry()

                zos.putNextEntry(ZipEntry("classes.dex"))
                zos.write(dex)
                zos.closeEntry()

                zos.putNextEntry(ZipEntry("lib/arm64-v8a/libcrypto_jni.so"))
                zos.write(dummySo)
                zos.closeEntry()
            }
        }
    }

    private fun createSyntheticAxml(): ByteArray {
        val strings = listOf(
            "manifest",               // 0
            "package",                // 1
            "com.example.secureapp",  // 2
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
            "sample",                 // 19
            "host",                   // 20
            "app.example.com",        // 21
            "path",                   // 22
            "/auth",                  // 23
            "autoVerify"              // 24
        )

        val stringPoolBytes = buildStringPool(strings)

        // data nodes
        val data1Attr = ByteArrayOutputStream().apply {
            writeAttr(this, -1, 17, 18, 0x03, 18) // scheme="https"
            writeAttr(this, -1, 20, 21, 0x03, 21) // host="app.example.com"
            writeAttr(this, -1, 22, 23, 0x03, 23) // path="/auth"
        }.toByteArray()
        val data1Elem = buildElementChunk(16, data1Attr, 3, emptyList())

        val data2Attr = ByteArrayOutputStream().apply {
            writeAttr(this, -1, 17, 19, 0x03, 19) // scheme="sample"
        }.toByteArray()
        val data2Elem = buildElementChunk(16, data2Attr, 1, emptyList())

        // action node
        val actionAttr = ByteArrayOutputStream().apply {
            writeAttr(this, -1, 8, 13, 0x03, 13) // name="android.intent.action.VIEW"
        }.toByteArray()
        val actionElem = buildElementChunk(12, actionAttr, 1, emptyList())

        // category node
        val catAttr = ByteArrayOutputStream().apply {
            writeAttr(this, -1, 8, 15, 0x03, 15) // name="android.intent.category.BROWSABLE"
        }.toByteArray()
        val catElem = buildElementChunk(14, catAttr, 1, emptyList())

        // intent-filter node
        val filterAttr = ByteArrayOutputStream().apply {
            writeAttr(this, -1, 24, -1, 0x12, 1) // autoVerify=true
        }.toByteArray()
        val filterElem = buildElementChunk(11, filterAttr, 1, listOf(actionElem, catElem, data1Elem, data2Elem))

        // activity node
        val actAttr = ByteArrayOutputStream().apply {
            writeAttr(this, -1, 8, 9, 0x03, 9) // name=".DeepLinkActivity"
            writeAttr(this, -1, 10, -1, 0x12, 1) // exported=true
        }.toByteArray()
        val actElem = buildElementChunk(7, actAttr, 2, listOf(filterElem))

        // application node
        val appElem = buildElementChunk(6, ByteArray(0), 0, listOf(actElem))

        // uses-sdk node
        val sdkAttr = ByteArrayOutputStream().apply {
            writeAttr(this, -1, 4, -1, 0x10, 26) // minSdk=26
            writeAttr(this, -1, 5, -1, 0x10, 34) // targetSdk=34
        }.toByteArray()
        val sdkElem = buildElementChunk(3, sdkAttr, 2, emptyList())

        // manifest root node
        val manifestAttr = ByteArrayOutputStream().apply {
            writeAttr(this, -1, 1, 2, 0x03, 2) // package="com.example.secureapp"
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
        buf.putInt(1 shl 8) // utf8
        buf.putInt(stringsStart)
        buf.putInt(0)
        for (off in offsets) buf.putInt(off)
        buf.put(data.toByteArray())
        return buf.array()
    }
}
