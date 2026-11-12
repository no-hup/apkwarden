package io.apkwarden.core.scan

import io.apkwarden.core.ApkAnalyzer
import io.apkwarden.core.dex.DexIndex
import io.apkwarden.core.ingest.ApkArchive
import io.apkwarden.core.model.*
import io.apkwarden.core.rules.AnalysisContext
import io.apkwarden.core.rules.Rule
import io.apkwarden.core.rules.RuleRegistry
import java.time.Instant

class ScanEngine(private val rules: List<Rule> = RuleRegistry.allRules) {

    fun scan(archive: ApkArchive): ScanReport {
        // 1. Unified analysis: Manifest, ARSC, Attack Surface, Fingerprint, Lockfile
        val analysis = ApkAnalyzer.analyzeArchive(archive)

        // 2. Index DEX bytecode with target sink filtering
        val dexIndex = DexIndex.build(archive, RuleRegistry.allTargetSinks)

        // 3. Run Rules Engine
        val context = AnalysisContext(
            archive = archive,
            attackSurface = analysis.attackSurface,
            stackFingerprint = analysis.fingerprint,
            dexIndex = dexIndex
        )

        val findings = mutableListOf<Finding>()
        for (rule in rules) {
            findings.addAll(rule.analyze(context))
        }

        // 4. Calculate Summary & Security Score
        val criticalCount = findings.count { it.severity == Severity.CRITICAL }
        val highCount = findings.count { it.severity == Severity.HIGH }
        val mediumCount = findings.count { it.severity == Severity.MEDIUM }
        val lowCount = findings.count { it.severity == Severity.LOW }
        val infoCount = findings.count { it.severity == Severity.INFO }

        // Warnings collection from unified analysis and dex indexing
        val scanWarnings = mutableListOf<String>()
        scanWarnings.addAll(analysis.warnings)
        scanWarnings.addAll(dexIndex.parsingErrors)
        if (analysis.fingerprint.packer.detected) {
            scanWarnings.add("PACKER DETECTED: Commercial protector '${analysis.fingerprint.packer.packerName}' detected. Bytecode analysis has reduced visibility (${analysis.fingerprint.coverageStatement.dexCoveragePct}% coverage).")
        }
        scanWarnings.addAll(analysis.fingerprint.coverageStatement.blindSpots)

        // Security score formula: Starts at 100, penalizes by severity
        val penalty = (criticalCount * 25) + (highCount * 15) + (mediumCount * 5) + (lowCount * 2)
        val score = maxOf(0, 100 - penalty)

        val summary = ScanSummary(
            totalFindings = findings.size,
            criticalCount = criticalCount,
            highCount = highCount,
            mediumCount = mediumCount,
            lowCount = lowCount,
            infoCount = infoCount,
            securityScore = score
        )

        return ScanReport(
            apkName = archive.archiveName,
            scanTimestamp = Instant.now().toString(),
            attackSurface = analysis.attackSurface,
            stackFingerprint = analysis.fingerprint,
            findings = findings.sortedWith(compareBy({ it.severity }, { it.id })),
            summary = summary,
            scanWarnings = scanWarnings
        )
    }
}
