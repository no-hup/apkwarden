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
    val targetSinks: Set<String> get() = emptySet()
    fun analyze(context: AnalysisContext): List<Finding>
}

internal data class Quadruple<A, B, C, D>(val first: A, val second: B, val third: C, val fourth: D)
