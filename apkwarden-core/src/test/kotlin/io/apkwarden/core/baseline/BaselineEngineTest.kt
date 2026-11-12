package io.apkwarden.core.baseline

import io.apkwarden.core.model.Confidence
import io.apkwarden.core.model.Finding
import io.apkwarden.core.model.Severity
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class BaselineEngineTest {

    private fun sampleFinding(id: String, targetClass: String, method: String): Finding {
        return Finding(
            id = id,
            title = "Test Finding",
            severity = Severity.HIGH,
            confidence = Confidence.FIRM,
            cwe = "CWE-926",
            owasp = "M4",
            description = "Test description",
            remediation = "Test remediation",
            targetClass = targetClass,
            targetMethod = method
        )
    }

    @Test
    fun `generates baseline and suppresses matching findings`() {
        val f1 = sampleFinding("APK-SEC-001", "com.example.OldActivity", "forward")
        val f2 = sampleFinding("APK-SEC-007", "com.example.LegacyWeb", "loadUrl")

        val baseline = BaselineEngine.generateBaseline(listOf(f1), defaultReason = "Legacy accepted risk")
        assertThat(baseline.suppressions).hasSize(1)
        assertThat(baseline.suppressions.first().ruleId).isEqualTo("APK-SEC-001")
        assertThat(baseline.suppressions.first().target).isEqualTo("com.example.OldActivity#forward")

        val processed = BaselineEngine.applyBaseline(listOf(f1, f2), baseline)
        assertThat(processed).hasSize(2)

        val p1 = processed.first { it.id == "APK-SEC-001" }
        val p2 = processed.first { it.id == "APK-SEC-007" }

        assertThat(p1.isSuppressed).isTrue()
        assertThat(p2.isSuppressed).isFalse()
    }

    @Test
    fun `supports class-level wildcard suppression`() {
        val f1 = sampleFinding("APK-SEC-001", "com.example.LegacyActivity", "methodA")
        val f2 = sampleFinding("APK-SEC-001", "com.example.LegacyActivity", "methodB")

        val baseline = BaselineFile(
            schemaVersion = 1,
            generatedAt = "2026-11-13T00:00:00Z",
            suppressions = listOf(
                BaselineSuppression(
                    ruleId = "APK-SEC-001",
                    target = "com.example.LegacyActivity",
                    reason = "Entire legacy class suppressed"
                )
            )
        )

        val processed = BaselineEngine.applyBaseline(listOf(f1, f2), baseline)
        assertThat(processed).allMatch { it.isSuppressed }
    }
}
