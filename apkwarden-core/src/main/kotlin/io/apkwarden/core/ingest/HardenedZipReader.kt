package io.apkwarden.core.ingest

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream

class HardenedZipReader(
    override val archiveName: String,
    private val rawBytes: ByteArray
) : ApkArchive {

    private val entries = mutableMapOf<String, ByteArray>()
    private val anomalies = mutableListOf<ZipAnomaly>()
    private val entryMetadataList = mutableListOf<ZipEntryMetadata>()

    init {
        parseArchive()
    }

    private fun parseArchive() {
        var totalUncompressedBytes = 0L
        val seenEntries = mutableSetOf<String>()

        ByteArrayInputStream(rawBytes).use { bais ->
            ZipInputStream(bais).use { zis ->
                var entry: ZipEntry? = zis.nextEntry
                while (entry != null) {
                    val rawName = entry.name
                    val normalizedName = normalizePath(rawName)

                    // 1. Path traversal check
                    if (rawName.contains("../") || rawName.contains("..\\") || rawName.startsWith("/") || rawName.startsWith("\\")) {
                        anomalies.add(
                            ZipAnomaly(
                                AnomalyType.PATH_TRAVERSAL_ATTEMPT,
                                rawName,
                                "Entry name contains directory traversal characters or root path prefix"
                            )
                        )
                    }

                    // 2. Duplicate entry check
                    if (!seenEntries.add(normalizedName)) {
                        anomalies.add(
                            ZipAnomaly(
                                AnomalyType.DUPLICATE_ENTRY,
                                normalizedName,
                                "Duplicate ZIP entry detected. This can be exploited to bypass signature verification (Master Key attack pattern)."
                            )
                        )
                    }

                    // Read content with size and ratio bounding
                    val contentStream = ByteArrayOutputStream()
                    val buffer = ByteArray(8192)
                    var entryBytesRead = 0L

                    var bytesRead: Int
                    while (zis.read(buffer).also { bytesRead = it } != -1) {
                        entryBytesRead += bytesRead
                        totalUncompressedBytes += bytesRead

                        if (entryBytesRead > MAX_ENTRY_UNCOMPRESSED_BYTES) {
                            anomalies.add(
                                ZipAnomaly(
                                    AnomalyType.MAX_SIZE_EXCEEDED,
                                    normalizedName,
                                    "Entry exceeded maximum allowed uncompressed size ($MAX_ENTRY_UNCOMPRESSED_BYTES bytes)"
                                )
                            )
                            throw SecurityException("Security violation: ZIP entry $normalizedName exceeded maximum size limit")
                        }

                        if (totalUncompressedBytes > MAX_TOTAL_UNCOMPRESSED_BYTES) {
                            anomalies.add(
                                ZipAnomaly(
                                    AnomalyType.MAX_SIZE_EXCEEDED,
                                    normalizedName,
                                    "Archive exceeded total allowed uncompressed size ($MAX_TOTAL_UNCOMPRESSED_BYTES bytes)"
                                )
                            )
                            throw SecurityException("Security violation: Archive exceeded total uncompressed size limit")
                        }

                        contentStream.write(buffer, 0, bytesRead)
                    }

                    val uncompressedData = contentStream.toByteArray()
                    val compSize = if (entry.compressedSize > 0) entry.compressedSize else entryBytesRead

                    // 3. Compression ratio check (Zip Bomb check)
                    if (entryBytesRead > 1_000_000 && compSize > 0) {
                        val ratio = entryBytesRead.toDouble() / compSize.toDouble()
                        if (ratio > MAX_COMPRESSION_RATIO) {
                            anomalies.add(
                                ZipAnomaly(
                                    AnomalyType.EXCESSIVE_COMPRESSION_RATIO,
                                    normalizedName,
                                    "Suspicious compression ratio ($ratio:1) exceeds safety threshold ($MAX_COMPRESSION_RATIO:1)"
                                )
                            )
                        }
                    }

                    if (!entry.isDirectory) {
                        // Store the first seen entry for security (matching Android's historical Dalvik extractor behavior)
                        if (!entries.containsKey(normalizedName)) {
                            entries[normalizedName] = uncompressedData
                        }
                    }

                    entryMetadataList.add(
                        ZipEntryMetadata(
                            name = normalizedName,
                            uncompressedSize = entryBytesRead,
                            compressedSize = compSize,
                            crc = entry.crc,
                            isDirectory = entry.isDirectory
                        )
                    )

                    zis.closeEntry()
                    entry = zis.nextEntry
                }
            }
        }
    }

    override val isSplitSet: Boolean get() = false
    override val isAab: Boolean get() = entries.containsKey("base/manifest/AndroidManifest.xml")

    override fun listEntries(): List<String> = entries.keys.toList()

    override fun hasEntry(name: String): Boolean = entries.containsKey(normalizePath(name))

    override fun getEntryBytes(name: String): ByteArray? = entries[normalizePath(name)]

    override fun openEntryStream(name: String): InputStream? {
        val bytes = getEntryBytes(name) ?: return null
        return ByteArrayInputStream(bytes)
    }

    override fun getAnomalies(): List<ZipAnomaly> = anomalies

    override fun close() {
        entries.clear()
        anomalies.clear()
        entryMetadataList.clear()
    }

    companion object {
        const val MAX_ENTRY_UNCOMPRESSED_BYTES = 250L * 1024 * 1024 // 250 MB
        const val MAX_TOTAL_UNCOMPRESSED_BYTES = 2L * 1024 * 1024 * 1024 // 2 GB
        const val MAX_COMPRESSION_RATIO = 100.0

        fun fromFile(file: File): HardenedZipReader {
            require(file.exists()) { "File does not exist: ${file.absolutePath}" }
            require(file.length() <= MAX_TOTAL_UNCOMPRESSED_BYTES) { "File exceeds safety size threshold" }
            val bytes = file.readBytes()
            return HardenedZipReader(file.name, bytes)
        }

        private fun normalizePath(name: String): String {
            return name.replace('\\', '/').trimStart('/')
        }
    }
}
