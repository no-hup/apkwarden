package io.apkwarden.core.ingest

import java.io.InputStream

data class ZipEntryMetadata(
    val name: String,
    val uncompressedSize: Long,
    val compressedSize: Long,
    val crc: Long,
    val isDirectory: Boolean
)

data class ZipAnomaly(
    val type: AnomalyType,
    val entryName: String,
    val description: String
)

enum class AnomalyType {
    DUPLICATE_ENTRY,
    PATH_TRAVERSAL_ATTEMPT,
    EXCESSIVE_COMPRESSION_RATIO,
    MAX_SIZE_EXCEEDED
}

interface ApkArchive : AutoCloseable {
    val archiveName: String
    val isSplitSet: Boolean
    val isAab: Boolean

    fun listEntries(): List<String>
    fun hasEntry(name: String): Boolean
    fun getEntryBytes(name: String): ByteArray?
    fun openEntryStream(name: String): InputStream?
    fun getAnomalies(): List<ZipAnomaly>
}
