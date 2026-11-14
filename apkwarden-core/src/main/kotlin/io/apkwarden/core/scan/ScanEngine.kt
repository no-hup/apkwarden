package io.apkwarden.core.scan

import io.apkwarden.core.ApkAnalyzer
import io.apkwarden.core.dex.DexIndex
import io.apkwarden.core.ingest.ApkArchive
import io.apkwarden.core.model.*
import io.apkwarden.core.rules.AnalysisContext
import io.apkwarden.core.rules.Rule
import io.apkwarden.core.rules.RuleRegistry
import java.time.Instant

class ScanEngine(
    private val rules: List<Rule> = RuleRegistry.allRules,
    private val extraFirstPartyPrefixes: Set<String> = emptySet()
) {

    private data class FindingDedupKey(
        val id: String,
        val targetClass: String?,
        val targetMethod: String?,
        val methodDescriptor: String?,
        val lineOrOffset: String?,
        val evidence: String?
    )

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

        val rawFindings = mutableListOf<Finding>()
        for (rule in rules) {
            rawFindings.addAll(rule.analyze(context))
        }

        // 4. Deduplicate findings: drop rows only when the whole tuple matches
        val appPackage = analysis.attackSurface.packageName
        val dedupedFindings = rawFindings.distinctBy {
            FindingDedupKey(
                id = it.id,
                targetClass = it.targetClass,
                targetMethod = it.targetMethod,
                methodDescriptor = it.methodDescriptor,
                lineOrOffset = it.lineOrOffset,
                evidence = it.evidence
            )
        }.map { finding ->
            // Attribute ownership
            val owner = classifyOwner(finding.targetClass, finding.component, appPackage, extraFirstPartyPrefixes)
            finding.copy(owner = owner)
        }

        // 5. Calculate Summary & Security Scores charging once per (ruleId, targetClass)
        val criticalCount = dedupedFindings.count { it.severity == Severity.CRITICAL }
        val highCount = dedupedFindings.count { it.severity == Severity.HIGH }
        val mediumCount = dedupedFindings.count { it.severity == Severity.MEDIUM }
        val lowCount = dedupedFindings.count { it.severity == Severity.LOW }
        val infoCount = dedupedFindings.count { it.severity == Severity.INFO }

        val overallScore = computeScore(dedupedFindings)
        val firstPartyScore = computeScore(dedupedFindings.filter { it.owner == FindingOwner.FIRST_PARTY })
        val libraryScore = computeScore(dedupedFindings.filter { it.owner == FindingOwner.LIBRARY })
        val unclassifiedScore = computeScore(dedupedFindings.filter { it.owner == FindingOwner.UNKNOWN })

        val reviewQueueCount = dedupedFindings.count {
            it.owner == FindingOwner.FIRST_PARTY &&
                    (it.confidence == Confidence.CERTAIN || it.confidence == Confidence.FIRM) &&
                    (it.reachability == Reachability.DIRECT || it.reachability == Reachability.REACHABLE || it.targetMethod == null)
        }

        // Warnings collection from unified analysis and dex indexing
        val scanWarnings = mutableListOf<String>()
        scanWarnings.addAll(analysis.warnings)
        scanWarnings.addAll(dexIndex.parsingErrors)
        if (analysis.fingerprint.packer.detected) {
            scanWarnings.add("PACKER DETECTED: Commercial protector '${analysis.fingerprint.packer.packerName}' detected. Bytecode analysis has reduced visibility (${analysis.fingerprint.coverageStatement.dexCoveragePct}% coverage).")
        }
        scanWarnings.addAll(analysis.fingerprint.coverageStatement.blindSpots)

        val summary = ScanSummary(
            totalFindings = dedupedFindings.size,
            criticalCount = criticalCount,
            highCount = highCount,
            mediumCount = mediumCount,
            lowCount = lowCount,
            infoCount = infoCount,
            securityScore = overallScore,
            firstPartyScore = firstPartyScore,
            libraryScore = libraryScore,
            unclassifiedScore = unclassifiedScore,
            reviewQueueCount = reviewQueueCount
        )

        return ScanReport(
            apkName = archive.archiveName,
            scanTimestamp = Instant.now().toString(),
            attackSurface = analysis.attackSurface,
            stackFingerprint = analysis.fingerprint,
            findings = dedupedFindings.sortedWith(compareBy({ it.severity }, { it.id })),
            summary = summary,
            scanWarnings = scanWarnings
        )
    }

    private fun classifyOwner(targetClass: String?, component: String?, appPackage: String, extraPrefixes: Set<String>): FindingOwner {
        val target = targetClass ?: component ?: return FindingOwner.UNKNOWN
        val norm = target.removePrefix("L").replace('/', '.').removeSuffix(";")
        if (appPackage.isNotEmpty() && norm.startsWith(appPackage)) return FindingOwner.FIRST_PARTY
        if (extraPrefixes.any { norm.startsWith(it) }) return FindingOwner.FIRST_PARTY
        if (KnownLibraries.PREFIXES.any { norm.startsWith(it) }) return FindingOwner.LIBRARY
        return FindingOwner.UNKNOWN
    }

    private fun computeScore(findings: List<Finding>): Int {
        // Charge score once per (ruleId, targetClass)
        val groups = findings.groupBy { Pair(it.id, it.targetClass ?: "") }
        var penalty = 0
        for ((_, group) in groups) {
            val highestSev = group.minByOrNull { it.severity.ordinal }?.severity ?: continue
            penalty += when (highestSev) {
                Severity.CRITICAL -> 25
                Severity.HIGH -> 15
                Severity.MEDIUM -> 5
                Severity.LOW -> 2
                Severity.INFO -> 0
            }
        }
        return maxOf(0, 100 - penalty)
    }
}
