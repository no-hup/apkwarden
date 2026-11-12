package io.apkwarden.core.fingerprint

import io.apkwarden.core.ingest.HardenedZipReader
import io.apkwarden.core.model.RuntimeStack
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class StackFingerprinterTest {

    @Test
    fun `detects pure dex stack when no cross-platform indicators`() {
        val zipBytes = createZip(
            "AndroidManifest.xml" to ByteArray(10),
            "classes.dex" to "dex".toByteArray()
        )
        val archive = HardenedZipReader("app.apk", zipBytes)
        val fp = StackFingerprinter.fingerprint(archive, listOf("dex".toByteArray()))

        assertThat(fp.primaryStack).isEqualTo(RuntimeStack.PURE_DEX)
        assertThat(fp.packer.detected).isFalse()
        assertThat(fp.coverageStatement.dexCoveragePct).isEqualTo(95)
    }

    @Test
    fun `detects flutter stack and reports blind spot`() {
        val zipBytes = createZip(
            "AndroidManifest.xml" to ByteArray(10),
            "classes.dex" to "dex".toByteArray(),
            "lib/arm64-v8a/libflutter.so" to ByteArray(100),
            "lib/arm64-v8a/libapp.so" to ByteArray(100),
            "assets/flutter_assets/kernel_blob.bin" to ByteArray(50)
        )
        val archive = HardenedZipReader("flutter_app.apk", zipBytes)
        val fp = StackFingerprinter.fingerprint(archive, emptyList())

        assertThat(fp.primaryStack).isEqualTo(RuntimeStack.FLUTTER)
        assertThat(fp.coverageStatement.dexCoveragePct).isEqualTo(15)
        assertThat(fp.coverageStatement.blindSpots).anyMatch { it.contains("Flutter AOT runtime detected") }
    }

    @Test
    fun `detects commercial packer and reduces coverage score`() {
        val zipBytes = createZip(
            "AndroidManifest.xml" to ByteArray(10),
            "classes.dex" to "dex".toByteArray(),
            "lib/arm64-v8a/libjiagu.so" to ByteArray(100)
        )
        val archive = HardenedZipReader("packed.apk", zipBytes)
        val fp = StackFingerprinter.fingerprint(archive, emptyList())

        assertThat(fp.packer.detected).isTrue()
        assertThat(fp.packer.packerName).contains("Jiagu")
        assertThat(fp.coverageStatement.isPacked).isTrue()
        assertThat(fp.coverageStatement.dexCoveragePct).isEqualTo(5)
    }

    private fun createZip(vararg entries: Pair<String, ByteArray>): ByteArray {
        val baos = ByteArrayOutputStream()
        ZipOutputStream(baos).use { zos ->
            for ((name, bytes) in entries) {
                val entry = ZipEntry(name)
                zos.putNextEntry(entry)
                zos.write(bytes)
                zos.closeEntry()
            }
        }
        return baos.toByteArray()
    }
}
