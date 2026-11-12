package io.apkwarden.core.ingest

import java.io.ByteArrayInputStream
import java.io.InputStream

class AabArchive(
    private val underlying: HardenedZipReader
) : ApkArchive {

    override val archiveName: String get() = underlying.archiveName
    override val isSplitSet: Boolean get() = false
    override val isAab: Boolean get() = true

    val embeddedProguardMap: String?
        get() {
            val mapBytes = underlying.getEntryBytes("BUNDLE-METADATA/com.android.tools.build.obfuscation/proguard.map")
            return mapBytes?.toString(Charsets.UTF_8)
        }

    override fun listEntries(): List<String> {
        return underlying.listEntries().mapNotNull { aabPathToApkPath(it) }
    }

    override fun hasEntry(name: String): Boolean {
        val mapped = apkPathToAabPath(name)
        return underlying.hasEntry(mapped)
    }

    override fun getEntryBytes(name: String): ByteArray? {
        val mapped = apkPathToAabPath(name)
        return underlying.getEntryBytes(mapped)
    }

    override fun openEntryStream(name: String): InputStream? {
        val mapped = apkPathToAabPath(name)
        return underlying.openEntryStream(mapped)
    }

    override fun getAnomalies(): List<ZipAnomaly> = underlying.getAnomalies()

    override fun close() {
        underlying.close()
    }

    private fun apkPathToAabPath(apkPath: String): String {
        return when {
            apkPath == "AndroidManifest.xml" -> "base/manifest/AndroidManifest.xml"
            apkPath.startsWith("classes") && apkPath.endsWith(".dex") -> "base/dex/$apkPath"
            apkPath.startsWith("lib/") -> "base/$apkPath"
            apkPath.startsWith("assets/") -> "base/$apkPath"
            apkPath.startsWith("res/") -> "base/$apkPath"
            apkPath == "resources.arsc" -> "base/resources.pb"
            else -> "base/$apkPath"
        }
    }

    private fun aabPathToApkPath(aabPath: String): String? {
        return when {
            aabPath == "base/manifest/AndroidManifest.xml" -> "AndroidManifest.xml"
            aabPath.startsWith("base/dex/") -> aabPath.removePrefix("base/dex/")
            aabPath.startsWith("base/lib/") -> aabPath.removePrefix("base/")
            aabPath.startsWith("base/assets/") -> aabPath.removePrefix("base/")
            aabPath.startsWith("base/res/") -> aabPath.removePrefix("base/")
            aabPath == "base/resources.pb" -> "resources.pb"
            aabPath.startsWith("base/") -> aabPath.removePrefix("base/")
            else -> aabPath
        }
    }
}
