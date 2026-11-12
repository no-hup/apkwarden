package io.apkwarden.core.ingest

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class HardenedZipReaderTest {

    @Test
    fun `reads valid zip cleanly without anomalies`() {
        val zipBytes = createZip(
            "AndroidManifest.xml" to "hello manifest".toByteArray(),
            "classes.dex" to "dex bytecode dummy".toByteArray()
        )

        val reader = HardenedZipReader("test.apk", zipBytes)
        assertThat(reader.listEntries()).containsExactlyInAnyOrder("AndroidManifest.xml", "classes.dex")
        assertThat(reader.hasEntry("AndroidManifest.xml")).isTrue()
        assertThat(reader.getEntryBytes("AndroidManifest.xml")).isEqualTo("hello manifest".toByteArray())
        assertThat(reader.getAnomalies()).isEmpty()
    }

    @Test
    fun `detects duplicate entry anomaly`() {
        val baos = ByteArrayOutputStream()
        ZipOutputStream(baos).use { zos ->
            zos.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zos.write("first copy".toByteArray())
            zos.closeEntry()

            // /AndroidManifest.xml bypasses standard ZipOutputStream duplicate check, but normalizes to same entry
            zos.putNextEntry(ZipEntry("/AndroidManifest.xml"))
            zos.write("second copy (malicious attempt)".toByteArray())
            zos.closeEntry()
        }

        val reader = HardenedZipReader("duplicate.apk", baos.toByteArray())
        assertThat(reader.getAnomalies()).anyMatch {
            it.type == AnomalyType.DUPLICATE_ENTRY && it.entryName == "AndroidManifest.xml"
        }
        // First copy preserved
        assertThat(reader.getEntryBytes("AndroidManifest.xml")).isEqualTo("first copy".toByteArray())
    }

    @Test
    fun `detects directory traversal attempt`() {
        val zipBytes = createZip(
            "../../etc/passwd" to "root:x:0:0".toByteArray(),
            "classes.dex" to "dummy".toByteArray()
        )

        val reader = HardenedZipReader("traversal.apk", zipBytes)
        assertThat(reader.getAnomalies()).anyMatch {
            it.type == AnomalyType.PATH_TRAVERSAL_ATTEMPT && it.entryName == "../../etc/passwd"
        }
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
