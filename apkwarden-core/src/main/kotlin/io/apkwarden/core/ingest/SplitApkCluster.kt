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
        val list = mutableListOf<String>()
        list.addAll(baseApk.listEntries())

        splitApks.forEachIndexed { index, split ->
            for (entry in split.listEntries()) {
                if (entry.endsWith(".dex")) {
                    // Feature split DEX files are namespaced to avoid collision with base classes*.dex
                    list.add("split_${index}_$entry")
                } else if (!baseApk.hasEntry(entry)) {
                    list.add(entry)
                }
            }
        }
        return list.distinct()
    }

    override fun hasEntry(name: String): Boolean {
        if (name.startsWith("split_")) {
            val parts = name.split('_', limit = 3)
            if (parts.size >= 3) {
                val splitIdx = parts[1].toIntOrNull()
                if (splitIdx != null && splitIdx in splitApks.indices) {
                    return splitApks[splitIdx].hasEntry(parts[2])
                }
            }
        }
        return allArchives.any { it.hasEntry(name) }
    }

    override fun getEntryBytes(name: String): ByteArray? {
        if (name.startsWith("split_")) {
            val parts = name.split('_', limit = 3)
            if (parts.size >= 3) {
                val splitIdx = parts[1].toIntOrNull()
                if (splitIdx != null && splitIdx in splitApks.indices) {
                    return splitApks[splitIdx].getEntryBytes(parts[2])
                }
            }
        }
        // Base APK has precedence for root manifests/resources, splits provide native libs & resources
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
