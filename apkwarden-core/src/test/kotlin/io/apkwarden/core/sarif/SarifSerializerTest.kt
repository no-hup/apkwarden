package io.apkwarden.core.sarif

import io.apkwarden.core.model.*
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class SarifSerializerTest {

    @Test
    fun `serializes scan report to OASIS SARIF 2_1_0 format`() {
        val finding = Finding(
            id = "APK-SEC-001",
            title = "Intent Redirection in Exported Component",
            severity = Severity.CRITICAL,
            confidence = Confidence.FIRM,
            cwe = "CWE-926",
            owasp = "M4: Insufficient Input/Output Validation",
            description = "Exported Activity forwards external Intent to startActivity.",
            remediation = "Validate target package or use explicit Intent.",
            component = "com.example.MainActivity",
            targetClass = "com.example.MainActivity",
            targetMethod = "handleIntent",
            evidence = "startActivity invoked with tainted register",
            codeSnippet = "> 0005: invoke-virtual Landroid/app/Activity;->startActivity",
            reachability = Reachability.DIRECT
        )

        val report = ScanReport(
            apkName = "test.apk",
            scanTimestamp = "2026-11-13T00:00:00Z",
            attackSurface = AttackSurface(
                packageName = "com.example",
                versionCode = 1,
                versionName = "1.0",
                minSdk = 26,
                targetSdk = 34,
                compileSdk = 34,
                isDebuggable = false,
                isTestOnly = false,
                allowBackup = false,
                dataExtractionRulesDefined = true
            ),
            stackFingerprint = StackFingerprint(
                primaryStack = RuntimeStack.PURE_DEX,
                detectedStacks = listOf(RuntimeStack.PURE_DEX),
                packer = PackerDetection(detected = false, packerName = null, signatureFound = null, confidence = "HIGH"),
                compilerMarker = null,
                nativeLibraries = emptyList(),
                coverageStatement = CoverageStatement(
                    primaryStack = RuntimeStack.PURE_DEX,
                    isPacked = false,
                    packerName = null,
                    dexCoveragePct = 100,
                    nativeCodePresent = false,
                    nativeLibraryCount = 0
                )
            ),
            findings = listOf(finding),
            summary = ScanSummary(
                totalFindings = 1,
                criticalCount = 1,
                highCount = 0,
                mediumCount = 0,
                lowCount = 0,
                infoCount = 0,
                securityScore = 75
            )
        )

        val sarifJson = SarifSerializer.serialize(report)
        assertThat(sarifJson).contains("\"version\": \"2.1.0\"")
        assertThat(sarifJson).contains("\"name\": \"APKWarden\"")
        assertThat(sarifJson).contains("\"ruleId\": \"APK-SEC-001\"")
        assertThat(sarifJson).contains("\"level\": \"error\"")
        assertThat(sarifJson).contains("\"uri\": \"com/example/MainActivity.smali\"")
        assertThat(sarifJson).contains("> 0005: invoke-virtual Landroid/app/Activity;->startActivity")

        val sarifReport = SarifSerializer.toSarif(report)
        assertThat(sarifReport.runs).hasSize(1)
        val run = sarifReport.runs.first()
        assertThat(run.results).hasSize(1)
        assertThat(run.tool.driver.rules).isNotEmpty
    }
}
