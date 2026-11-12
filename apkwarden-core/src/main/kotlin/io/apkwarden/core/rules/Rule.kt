package io.apkwarden.core.rules

import io.apkwarden.core.dex.DexIndex
import io.apkwarden.core.ingest.ApkArchive
import io.apkwarden.core.model.AttackSurface
import io.apkwarden.core.model.Finding
import io.apkwarden.core.model.StackFingerprint

data class AnalysisContext(
    val archive: ApkArchive,
    val attackSurface: AttackSurface,
    val stackFingerprint: StackFingerprint,
    val dexIndex: DexIndex
)

interface Rule {
    val id: String
    val name: String
    val description: String
    fun analyze(context: AnalysisContext): List<Finding>
}
