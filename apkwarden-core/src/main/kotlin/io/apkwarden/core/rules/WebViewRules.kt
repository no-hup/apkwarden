package io.apkwarden.core.rules

import io.apkwarden.core.dex.MethodAnalyzer
import io.apkwarden.core.dex.RegisterValue
import io.apkwarden.core.dex.TaintSource
import io.apkwarden.core.model.Confidence
import io.apkwarden.core.model.Finding
import io.apkwarden.core.model.Reachability
import io.apkwarden.core.model.Severity

/**
 * APK-SEC-007: WebView Arbitrary URL Loading
 * Exported component loads untrusted URL from Intent directly into WebView.
 */
class WebViewArbitraryUrlRule : Rule {
    override val id = "APK-SEC-007"
    override val name = "Untrusted Intent URL Loaded in WebView"
    override val description = "Exported component receives a URL from an incoming Intent and passes it directly to WebView.loadUrl without origin/domain validation."
    override val targetSinks = setOf("loadUrl", "loadDataWithBaseURL")

    override fun analyze(context: AnalysisContext): List<Finding> {
        val findings = mutableListOf<Finding>()
        val loadUrlCalls = context.dexIndex.findCallSites("android.webkit.WebView", "loadUrl") +
                context.dexIndex.findCallSites("android.webkit.WebView", "loadDataWithBaseURL")

        for (cs in loadUrlCalls) {
            val reachability = context.dexIndex.checkReachability(cs.callerClass, context.attackSurface)
            if (reachability == Reachability.UNREACHABLE) continue

            val analyzer = MethodAnalyzer(cs.method)
            val args = analyzer.getInvocationArgs(cs.instruction)
            // loadUrl(url) -> arg 0 is this, arg 1 is url
            if (args.size < 2) continue
            val urlReg = args[1]
            val regVal = analyzer.getRegisterValue(urlReg, cs.instructionIndex)

            val isTainted = when (regVal) {
                is RegisterValue.Tainted -> regVal.source == TaintSource.INTENT_EXTRA || regVal.source == TaintSource.INTENT_DATA
                is RegisterValue.Unknown -> {
                    // Check if method extracts intent extra or data
                    analyzer.containsCallTo("android.content.Intent", "getStringExtra") ||
                            analyzer.containsCallTo("android.content.Intent", "getDataString")
                }
                else -> false
            }

            if (isTainted) {
                val (title, severity, confidence, desc) = when (reachability) {
                    Reachability.DIRECT -> Quadruple(
                        "Arbitrary URL Loaded in WebView from Exported Component",
                        Severity.HIGH,
                        if (regVal is RegisterValue.Tainted) Confidence.CERTAIN else Confidence.FIRM,
                        "Exported component '${cs.callerClass}' loads a URL derived from an untrusted Intent into WebView in method '${cs.callerMethod}'. Attackers can trigger this component with javascript:// or malicious web endpoints."
                    )
                    Reachability.REACHABLE -> Quadruple(
                        "Arbitrary URL Loaded in WebView via Reachable Component",
                        Severity.HIGH,
                        Confidence.FIRM,
                        "Component '${cs.callerClass}' is reachable from an exported component and loads an untrusted Intent URL into WebView in method '${cs.callerMethod}'."
                    )
                    Reachability.UNKNOWN -> Quadruple(
                        "Potential Arbitrary URL Loaded in WebView (Indirect / Unknown Entry Point)",
                        Severity.MEDIUM,
                        Confidence.TENTATIVE,
                        "Class '${cs.callerClass}' loads an untrusted URL into WebView in method '${cs.callerMethod}'. An entry point from an exported component was not statically resolved within 3 hops, but this may be reachable dynamically."
                    )
                    Reachability.UNREACHABLE -> continue
                }

                findings.add(
                    Finding(
                        id = id,
                        title = title,
                        severity = severity,
                        confidence = confidence,
                        cwe = "CWE-79",
                        owasp = "M4: Insufficient Input/Output Validation",
                        description = desc,
                        remediation = "Validate that the loaded URL strictly matches an allowed HTTPS domain whitelist before loading: `if (isValidDomain(url)) webView.loadUrl(url)`.",
                        component = cs.callerClass,
                        targetClass = cs.callerClass,
                        targetMethod = cs.callerMethod,
                        methodDescriptor = analyzer.getMethodDescriptor(),
                        evidence = "WebView.loadUrl invoked with tainted intent URL argument ($regVal)",
                        lineOrOffset = "Instruction offset: ${cs.instructionIndex}",
                        reachability = reachability,
                        codeSnippet = analyzer.getDisassemblySnippet(cs.instructionIndex)
                    )
                )
            }
        }
        return findings
    }
}

/**
 * APK-SEC-008: Insecure WebView File Access
 * WebSettings.setAllowFileAccess(true) or setAllowUniversalAccessFromFileURLs(true)
 */
class WebViewFileAccessRule : Rule {
    override val id = "APK-SEC-008"
    override val name = "Insecure WebView File Access Enabled"
    override val description = "WebSettings explicitly enables file access or cross-origin access from file URLs, allowing malicious web content or XSS to exfiltrate private app files."
    override val targetSinks = setOf("setAllowFileAccess", "setAllowFileAccessFromFileURLs", "setAllowUniversalAccessFromFileURLs")

    override fun analyze(context: AnalysisContext): List<Finding> {
        val findings = mutableListOf<Finding>()
        val fileAccessCalls = context.dexIndex.findCallSites("android.webkit.WebSettings", "setAllowFileAccess") +
                context.dexIndex.findCallSites("android.webkit.WebSettings", "setAllowFileAccessFromFileURLs") +
                context.dexIndex.findCallSites("android.webkit.WebSettings", "setAllowUniversalAccessFromFileURLs")

        for (cs in fileAccessCalls) {
            val analyzer = MethodAnalyzer(cs.method)
            val args = analyzer.getInvocationArgs(cs.instruction)
            // setAllow*(boolean enabled) -> arg 0 is this, arg 1 is boolean (1=true, 0=false)
            if (args.size < 2) continue
            val boolReg = args[1]
            val regVal = analyzer.getRegisterValue(boolReg, cs.instructionIndex)

            var enabled = false
            if (regVal is RegisterValue.IntConstant && regVal.value != 0) {
                enabled = true
            }

            if (enabled) {
                val isUniversal = cs.targetMethod.contains("Universal")
                findings.add(
                    Finding(
                        id = id,
                        title = "Insecure WebView Setting: ${cs.targetMethod}(true)",
                        severity = if (isUniversal) Severity.CRITICAL else Severity.HIGH,
                        confidence = Confidence.CERTAIN,
                        cwe = "CWE-200",
                        owasp = "M1: Insecure Data Storage",
                        description = "Class '${cs.callerClass}#${cs.callerMethod}' calls '${cs.targetClass}.${cs.targetMethod}(true)'. This allows any webpage displayed in the WebView to read local file assets and sensitive app data.",
                        remediation = "Disable file access on WebSettings: `webSettings.setAllowFileAccess(false)` and `webSettings.setAllowUniversalAccessFromFileURLs(false)`.",
                        component = cs.callerClass,
                        targetClass = cs.callerClass,
                        targetMethod = cs.callerMethod,
                        methodDescriptor = analyzer.getMethodDescriptor(),
                        evidence = "${cs.targetMethod}(true) invoked in ${cs.callerClass}",
                        lineOrOffset = "Instruction offset: ${cs.instructionIndex}"
                    )
                )
            }
        }
        return findings
    }
}

/**
 * APK-SEC-009: JavaScript Interface Exposed
 * addJavascriptInterface on WebView
 */
class JavascriptInterfaceRule : Rule {
    override val id = "APK-SEC-009"
    override val name = "WebView JavaScript Interface Exposed"
    override val description = "Application attaches native Java objects to WebView via addJavascriptInterface. On minSdk < 17 this leads to remote code execution; on modern SDKs it exposes internal methods to web content."
    override val targetSinks = setOf("addJavascriptInterface")

    override fun analyze(context: AnalysisContext): List<Finding> {
        val findings = mutableListOf<Finding>()
        val jsInterfaceCalls = context.dexIndex.findCallSites("android.webkit.WebView", "addJavascriptInterface")

        for (cs in jsInterfaceCalls) {
            val analyzer = MethodAnalyzer(cs.method)
            val isRceRisk = context.attackSurface.minSdk < 17
            val severity = if (isRceRisk) Severity.CRITICAL else Severity.MEDIUM

            findings.add(
                Finding(
                    id = id,
                    title = if (isRceRisk) "RCE via WebView addJavascriptInterface on minSdk < 17" else "JavaScript Interface Attached to WebView",
                    severity = severity,
                    confidence = Confidence.CERTAIN,
                    cwe = "CWE-94",
                    owasp = "M4: Insufficient Input/Output Validation",
                    description = "Class '${cs.callerClass}#${cs.callerMethod}' calls 'WebView.addJavascriptInterface'. " +
                            if (isRceRisk) "Because minSdk (${context.attackSurface.minSdk}) is below 17, methods can be invoked via Java reflection to execute arbitrary shell commands."
                            else "Exposed object methods can be called by any untrusted web content or XSS loaded into the WebView.",
                    remediation = if (isRceRisk) "Raise minSdk to 17+ and annotate methods with @JavascriptInterface."
                    else "Ensure only whitelisted, strictly HTTPS origins can load in the WebView, and only expose minimal, non-sensitive methods.",
                    component = cs.callerClass,
                    targetClass = cs.callerClass,
                    targetMethod = cs.callerMethod,
                    methodDescriptor = analyzer.getMethodDescriptor(),
                    evidence = "Call to WebView.addJavascriptInterface in ${cs.callerClass}",
                    lineOrOffset = "Instruction offset: ${cs.instructionIndex}"
                )
            )
        }
        return findings
    }
}
