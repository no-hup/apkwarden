package io.apkwarden.core.ingest

import java.io.ByteArrayInputStream
import java.io.InputStream

class SplitApkCluster(
    override val archiveName: String,
    val baseApk: HardenedZipReader,
    val splitApks: List<HardenedZipReader>
) : ApkArchive {

    private val allArchives = listOf(baseApk) + splitApks

    override val isSplitSet: Boolean get() = true
    override val isAab: Boolean get() = false

    override fun listEntries(): List<String> {
        val set = mutableSetOf<String>()
        for (archive in allArchives) {
            set.addAll(archive.listEntries())
        }
        return set.toList()
    }

    override fun hasEntry(name: String): Boolean {
        return allArchives.any { it.hasEntry(name) }
    }

    override fun getEntryBytes(name: String): ByteArray? {
        // Base APK has precedence for root manifests/resources, splits provide native libs & split dex
        return baseApk.getEntryBytes(name) ?: splitApks.firstNotNullOfOrNull { it.getEntryBytes(name) }
    }

    override fun openEntryStream(name: String): InputStream? {
        val bytes = getEntryBytes(name) ?: return null
        return ByteArrayInputStream(bytes)
    }

    override fun getAnomalies(): List<ZipAnomaly> {
        return allArchives.flatMap { it.getAnomalies() }
    }

    override fun close() {
        for (archive in allArchives) {
            archive.close()
        }
    }
}
