package io.apkwarden.core.testutil

import com.android.tools.smali.smali.Smali
import com.android.tools.smali.smali.SmaliOptions
import io.apkwarden.core.ingest.HardenedZipReader
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

object SmaliDexBuilder {

    fun assemble(smaliCode: String, apiLevel: Int = 28): ByteArray {
        val tempSmali = File.createTempFile("test_", ".smali")
        val tempDex = File.createTempFile("test_", ".dex")
        try {
            tempSmali.writeText(smaliCode)
            val options = SmaliOptions().apply {
                this.apiLevel = apiLevel
                this.outputDexFile = tempDex.absolutePath
            }
            val success = Smali.assemble(options, tempSmali.absolutePath)
            if (!success) {
                throw IllegalStateException("Failed to assemble smali code:\n$smaliCode")
            }
            return tempDex.readBytes()
        } finally {
            tempSmali.delete()
            tempDex.delete()
        }
    }

    fun buildTestApk(
        manifestXmlBytes: ByteArray,
        smaliCode: String,
        apiLevel: Int = 28
    ): HardenedZipReader {
        val dexBytes = assemble(smaliCode, apiLevel)
        val baos = ByteArrayOutputStream()
        ZipOutputStream(baos).use { zos ->
            zos.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zos.write(manifestXmlBytes)
            zos.closeEntry()

            zos.putNextEntry(ZipEntry("classes.dex"))
            zos.write(dexBytes)
            zos.closeEntry()
        }
        return HardenedZipReader("test-synthetic.apk", baos.toByteArray())
    }
}
