package io.apkwarden.core.ingest

import io.apkwarden.core.dex.DexIndex
import io.apkwarden.core.testutil.SmaliDexBuilder
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class SplitApkClusterTest {

    private fun createZip(entries: Map<String, ByteArray>): ByteArray {
        val baos = ByteArrayOutputStream()
        ZipOutputStream(baos).use { zos ->
            for ((name, bytes) in entries) {
                zos.putNextEntry(ZipEntry(name))
                zos.write(bytes)
                zos.closeEntry()
            }
        }
        return baos.toByteArray()
    }

    @Test
    fun `namespaces split dex files to prevent multi-dex collisions`() {
        val baseSmali = """
            .class public Lcom/example/BaseClass;
            .super Ljava/lang/Object;
        """.trimIndent()
        val baseDex = SmaliDexBuilder.assemble(baseSmali)
        val baseZip = HardenedZipReader("base.apk", createZip(mapOf("classes.dex" to baseDex)))

        val splitSmali = """
            .class public Lcom/example/FeatureSplitClass;
            .super Ljava/lang/Object;
        """.trimIndent()
        val splitDex = SmaliDexBuilder.assemble(splitSmali)
        val splitZip = HardenedZipReader("split_feature.apk", createZip(mapOf("classes.dex" to splitDex)))

        val cluster = SplitApkCluster("cluster", baseZip, listOf(splitZip))
        val entries = cluster.listEntries()

        assertThat(entries).contains("classes.dex", "split_0_classes.dex")

        val dexIndex = DexIndex.build(cluster)
        assertThat(dexIndex.classDefs).containsKey("com.example.BaseClass")
        assertThat(dexIndex.classDefs).containsKey("com.example.FeatureSplitClass")
    }
}
