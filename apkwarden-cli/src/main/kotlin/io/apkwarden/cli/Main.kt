package io.apkwarden.cli

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.core.ProgramResult
import com.github.ajalt.clikt.core.main
import com.github.ajalt.clikt.core.subcommands
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.types.file
import io.apkwarden.core.ApkAnalyzer
import io.apkwarden.core.lock.SurfaceLockGenerator
import io.apkwarden.core.model.Severity
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.File

class ApkwardenCli : CliktCommand(name = "apkwarden") {
    override fun help(context: Context): String = "APKwarden: Fast, reachability-first Android security analyzer."
    override fun run() = Unit
}

class SurfaceCommand : CliktCommand(name = "surface") {
    override fun help(context: Context): String = "Analyze and display the resolved attack surface of an APK, split cluster, or AAB."

    private val target by argument("apk-file", help = "Path to APK, AAB, split directory, or .apks bundle").file(mustExist = true)

    override fun run() {
        echo("Analyzing attack surface: ${target.name}...")
        val result = ApkAnalyzer.analyze(target)
        val surface = result.attackSurface

        echo("")
        echo("=== PACKAGE SUMMARY ===")
        echo("Package:         ${surface.packageName}")
        echo("Version:         ${surface.versionName ?: "N/A"} (${surface.versionCode})")
        echo("SDK Range:       minSdk=${surface.minSdk}, targetSdk=${surface.targetSdk}")
        echo("Debuggable:      ${surface.isDebuggable}")
        echo("Allow Backup:    ${surface.allowBackup}")
        echo("Archive Format:  ${if (result.isAab) "AAB" else if (result.isSplitSet) "Split Cluster" else "Standalone APK"}")

        if (result.warnings.isNotEmpty()) {
            echo("")
            echo("=== INGEST WARNINGS ===")
            result.warnings.forEach { echo("⚠️  $it") }
        }

        echo("")
        echo("=== EXPORTED ATTACK SURFACE (${surface.exportedComponents.size} components) ===")
        if (surface.exportedComponents.isEmpty()) {
            echo("No exported components found.")
        } else {
            surface.exportedComponents.forEach { comp ->
                val permStr = when {
                    comp.permission != null -> " [Guarded by: ${comp.permission}]"
                    comp.readPermission != null || comp.writePermission != null -> " [Read: ${comp.readPermission ?: "none"}, Write: ${comp.writePermission ?: "none"}]"
                    else -> " ⚠️ UNGUARDED"
                }
                echo("• [${comp.type}] ${comp.name}$permStr")
            }
        }

        if (surface.deepLinks.isNotEmpty()) {
            echo("")
            echo("=== DEEP LINKS (${surface.deepLinks.size} patterns) ===")
            surface.deepLinks.forEach { link ->
                val autoVerifyStr = if (link.autoVerify) " (App Link / autoVerify=true)" else ""
                val hostStr = if (link.host != null) "://${link.host}" else "://"
                val pathStr = link.path ?: ""
                echo("• ${link.scheme}$hostStr$pathStr -> ${link.targetComponent}$autoVerifyStr")
            }
        }

        if (surface.fileProviderPaths.isNotEmpty()) {
            echo("")
            echo("=== FILE PROVIDER PATHS (${surface.fileProviderPaths.size} paths) ===")
            surface.fileProviderPaths.forEach { fp ->
                val warn = if (fp.isRootPath) " 🚨 CRITICAL (root-path exposed)" else if (fp.isBroadWildcard) " ⚠️ BROAD WILDCARD" else ""
                echo("• <${fp.tag} name=\"${fp.name}\" path=\"${fp.path}\">$warn")
            }
        }

        val nsc = surface.networkSecurityConfig
        if (nsc != null) {
            echo("")
            echo("=== NETWORK SECURITY CONFIG ===")
            echo("Base Cleartext Permitted: ${nsc.baseCleartextPermitted}")
            echo("Trusts User Certs:        ${nsc.trustUserCertsGlobally}")
            nsc.domainConfigs.forEach { dc ->
                val pins = if (dc.certificatePins.isNotEmpty()) " (Pinned: ${dc.certificatePins.size} pins)" else ""
                echo("• ${dc.domain}: cleartext=${dc.cleartextPermitted}, trustUserCerts=${dc.trustUserCerts}$pins")
            }
        }
    }
}

class LockCommand : CliktCommand(name = "lock") {
    override fun help(context: Context): String = "Generate a deterministic surface.lock.json file to commit to git for PR security diffs."

    private val target by argument("apk-file", help = "Path to APK, AAB, or split cluster").file(mustExist = true)
    private val output by option("-o", "--output", help = "Output lockfile destination").default("surface.lock.json")

    override fun run() {
        val result = ApkAnalyzer.analyze(target)
        val jsonStr = SurfaceLockGenerator.serialize(result.surfaceLock)
        val outFile = File(output)
        outFile.writeText(jsonStr)
        echo("✓ Generated surface lockfile: ${outFile.absolutePath} (SHA256: ${result.surfaceLock.sha256Fingerprint.take(12)}...)")
    }
}

class FingerprintCommand : CliktCommand(name = "fingerprint") {
    override fun help(context: Context): String = "Inspect build compilers, packers, native libraries, and blind spots."

    private val target by argument("apk-file", help = "Path to APK or AAB").file(mustExist = true)

    override fun run() {
        val result = ApkAnalyzer.analyze(target)
        val fp = result.fingerprint
        val cov = fp.coverageStatement

        echo("=== STACK FINGERPRINT: ${target.name} ===")
        echo("Primary Runtime:     ${fp.primaryStack}")
        echo("Detected Runtimes:   ${fp.detectedStacks.joinToString(", ").ifEmpty { "PURE_DEX" }}")

        echo("")
        echo("=== PACKER & PROTECTOR ===")
        if (fp.packer.detected) {
            echo("🚨 PACKER DETECTED:   ${fp.packer.packerName}")
            echo("Signature:           ${fp.packer.signatureFound}")
            echo("Confidence:          ${fp.packer.confidence}")
        } else {
            echo("No known commercial packer or shell detected.")
        }

        echo("")
        echo("=== COMPILER & OBFUSCATION ===")
        val cm = fp.compilerMarker
        if (cm != null) {
            echo("Compiler:            ${cm.compiler} ${cm.version ?: ""}")
            echo("Compilation Mode:    ${if (cm.isFullMode) "R8 Full Mode" else "Compat / D8"}")
            echo("Min API:             ${cm.minApi ?: "N/A"}")
            echo("PG Map ID:           ${cm.pgMapId ?: "None"}")
        } else {
            echo("No R8/D8 marker embedded in DEX string table.")
        }

        if (fp.nativeLibraries.isNotEmpty()) {
            echo("")
            echo("=== NATIVE LIBRARIES (${fp.nativeLibraries.size} files) ===")
            fp.nativeLibraries.forEach { lib ->
                val alignStr = when (lib.is16KbAligned) {
                    true -> "✓ 16KB Aligned"
                    false -> "⚠️ NOT 16KB Aligned (Google Play warning)"
                    null -> "N/A"
                }
                val versions = if (lib.detectedVersionStrings.isNotEmpty()) " [${lib.detectedVersionStrings.joinToString(", ")}]" else ""
                echo("• ${lib.name} (${lib.abi}): $alignStr$versions")
            }
        }

        echo("")
        echo("=== COVERAGE & BLIND-SPOT STATEMENT ===")
        echo("DEX Static Coverage: ${cov.dexCoveragePct}%")
        cov.notes.forEach { echo("ℹ️  $it") }
        cov.blindSpots.forEach { echo("⚠️  $it") }
    }
}

class IngestCheckCommand : CliktCommand(name = "ingest-check") {
    override fun help(context: Context): String = "Verify zip integrity, path traversal safety, and split configuration."

    private val target by argument("apk-file", help = "Path to APK or split bundle").file(mustExist = true)

    override fun run() {
        val result = ApkAnalyzer.analyze(target)
        echo("=== INGEST INTEGRITY CHECK: ${target.name} ===")
        echo("Archive Type: ${if (result.isAab) "AAB (Android App Bundle)" else if (result.isSplitSet) "Split APK Cluster" else "Standalone APK"}")

        if (result.warnings.isEmpty()) {
            echo("✓ Clean archive: Zero ZIP anomalies or integrity violations detected.")
        } else {
            echo("⚠️  Archive Warnings / Anomalies:")
            result.warnings.forEach { echo("  • $it") }
        }
    }
}

class ScanCommand : CliktCommand(name = "scan") {
    override fun help(context: Context): String = "Perform full bytecode and attack surface security scan with 20 high-precision AppSec rules."

    private val target by argument("apk-file", help = "Path to APK, AAB, or split bundle").file(mustExist = true)
    private val jsonOutput by option("--json", help = "Output report as JSON").flag(default = false)
    private val failOn by option("--fail-on", help = "Exit with code 2 if findings at or above severity exist (CRITICAL, HIGH, MEDIUM, LOW, NEVER)").default("CRITICAL")

    private val json = Json { prettyPrint = true }

    override fun run() {
        if (!jsonOutput) {
            echo("Scanning ${target.name} for Android security vulnerabilities...")
        }

        val report = ApkAnalyzer.scan(target)

        if (jsonOutput) {
            echo(json.encodeToString(report))
        } else {
            val summary = report.summary
            val surface = report.attackSurface
            val fp = report.stackFingerprint

            echo("")
            echo("══════════════════════════════════════════════════════════════════════")
            echo("                      APKWarden Security Report                       ")
            echo("══════════════════════════════════════════════════════════════════════")
            echo("Target:          ${report.apkName}")
            echo("Package:         ${surface.packageName}")
            echo("SDK Target:      minSdk=${surface.minSdk}, targetSdk=${surface.targetSdk}")
            echo("Primary Stack:   ${fp.primaryStack}")
            echo("Security Score:  ${summary.securityScore}/100")
            echo("Findings:        CRITICAL: ${summary.criticalCount} | HIGH: ${summary.highCount} | MEDIUM: ${summary.mediumCount} | LOW: ${summary.lowCount} | INFO: ${summary.infoCount}")
            echo("──────────────────────────────────────────────────────────────────────")

            if (report.scanWarnings.isNotEmpty()) {
                echo("")
                echo("=== ⚠️  SCAN WARNINGS & BLIND SPOTS ===")
                report.scanWarnings.forEach { echo("• $it") }
            }

            if (report.findings.isEmpty()) {
                echo("")
                if (report.scanWarnings.any { it.contains("PACKER") || it.contains("Failed to parse") }) {
                    echo("⚠️  No static findings detected in available DEX bytecode, but note scan warnings/blind spots above.")
                } else {
                    echo("✓ Clean bill of health: Zero vulnerabilities found across all rules!")
                }
            } else {
                var currentSeverity: Severity? = null
                for (finding in report.findings) {
                    if (finding.severity != currentSeverity) {
                        currentSeverity = finding.severity
                        val badge = when (currentSeverity) {
                            Severity.CRITICAL -> "🔴 [CRITICAL]"
                            Severity.HIGH -> "🟠 [HIGH]"
                            Severity.MEDIUM -> "🟡 [MEDIUM]"
                            Severity.LOW -> "🔵 [LOW]"
                            Severity.INFO -> "⚪ [INFO]"
                        }
                        echo("")
                        echo("=== $badge FINDINGS ===")
                    }

                    echo("• [${finding.id}] ${finding.title} (${finding.cwe} / ${finding.owasp})")
                    echo("  Confidence:   ${finding.confidence}")
                    if (finding.component != null) {
                        echo("  Component:    ${finding.component}")
                    }
                    if (finding.targetMethod != null) {
                        echo("  Method:       ${finding.targetClass}#${finding.targetMethod}")
                    }
                    if (finding.evidence != null) {
                        echo("  Evidence:     ${finding.evidence}")
                    }
                    echo("  Description:  ${finding.description}")
                    echo("  Remediation:  ${finding.remediation}")
                    echo("")
                }
            }
            echo("══════════════════════════════════════════════════════════════════════")
        }

        // CI Gating evaluation
        val failSeverity = when (failOn.uppercase()) {
            "CRITICAL" -> Severity.CRITICAL
            "HIGH" -> Severity.HIGH
            "MEDIUM" -> Severity.MEDIUM
            "LOW" -> Severity.LOW
            "NEVER" -> null
            else -> throw com.github.ajalt.clikt.core.UsageError("Unknown --fail-on severity '$failOn'. Valid choices: CRITICAL, HIGH, MEDIUM, LOW, NEVER")
        }

        if (failSeverity != null) {
            val thresholdOrdinal = failSeverity.ordinal
            val violations = report.findings.filter { it.severity.ordinal <= thresholdOrdinal }
            if (violations.isNotEmpty()) {
                if (!jsonOutput) {
                    echo("❌ CI GATE FAILED: Found ${violations.size} finding(s) at or above $failSeverity threshold.")
                }
                throw ProgramResult(2)
            }
        }
    }
}

fun main(args: Array<String>) = ApkwardenCli()
    .subcommands(
        ScanCommand(),
        SurfaceCommand(),
        LockCommand(),
        FingerprintCommand(),
        IngestCheckCommand()
    )
    .main(args)
