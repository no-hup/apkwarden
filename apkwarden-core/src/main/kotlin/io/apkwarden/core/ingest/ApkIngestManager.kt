package io.apkwarden.core.ingest

import java.io.ByteArrayInputStream
import java.io.File
import java.util.zip.ZipInputStream

object ApkIngestManager {

    fun open(file: File): ApkArchive {
        require(file.exists()) { "File or directory does not exist: ${file.absolutePath}" }

        if (file.isDirectory) {
            return openDirectory(file)
        }

        val name = file.name.lowercase()
        return when {
            name.endsWith(".aab") -> {
                val zip = HardenedZipReader.fromFile(file)
                AabArchive(zip)
            }
            name.endsWith(".apk") -> {
                val zip = HardenedZipReader.fromFile(file)
                if (zip.isAab) {
                    AabArchive(zip)
                } else {
                    zip
                }
            }
            name.endsWith(".apks") || name.endsWith(".xapk") || name.endsWith(".apkm") || name.endsWith(".zip") -> {
                openSplitBundleArchive(file)
            }
            else -> {
                // Try as standard zip
                val zip = HardenedZipReader.fromFile(file)
                if (zip.isAab) AabArchive(zip) else zip
            }
        }
    }

    private fun openDirectory(dir: File): ApkArchive {
        val apkFiles = dir.walkTopDown().maxDepth(2).filter { it.isFile && it.name.lowercase().endsWith(".apk") }.toList()
        require(apkFiles.isNotEmpty()) { "No .apk files found in directory: ${dir.absolutePath}" }

        if (apkFiles.size == 1) {
            return HardenedZipReader.fromFile(apkFiles.first())
        }

        val readers = apkFiles.map { HardenedZipReader.fromFile(it) }
        val base = readers.firstOrNull { isBaseApk(it) } ?: readers.first()
        val splits = readers.filter { it !== base }

        return SplitApkCluster(dir.name, base, splits)
    }

    private fun openSplitBundleArchive(file: File): ApkArchive {
        val bytes = file.readBytes()
        val innerApks = mutableListOf<Pair<String, ByteArray>>()

        ByteArrayInputStream(bytes).use { bais ->
            ZipInputStream(bais).use { zis ->
                var entry = zis.nextEntry
                while (entry != null) {
                    if (!entry.isDirectory && entry.name.lowercase().endsWith(".apk")) {
                        val apkBytes = zis.readBytes()
                        innerApks.add(entry.name to apkBytes)
                    }
                    zis.closeEntry()
                    entry = zis.nextEntry
                }
            }
        }

        require(innerApks.isNotEmpty()) { "No internal APKs found in split bundle archive: ${file.name}" }

        if (innerApks.size == 1) {
            val (name, apkBytes) = innerApks.first()
            return HardenedZipReader(name, apkBytes)
        }

        val readers = innerApks.map { (name, apkBytes) -> HardenedZipReader(name, apkBytes) }
        val base = readers.firstOrNull { isBaseApk(it) } ?: readers.first()
        val splits = readers.filter { it !== base }

        return SplitApkCluster(file.name, base, splits)
    }

    private fun isBaseApk(reader: HardenedZipReader): Boolean {
        // Base APK has classes.dex and AndroidManifest.xml without split prefix
        val name = reader.archiveName.lowercase()
        if (name.contains("base") || name == "standalone.apk") return true
        if (reader.hasEntry("AndroidManifest.xml") && reader.hasEntry("classes.dex")) return true
        return false
    }
}
