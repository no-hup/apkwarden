package io.apkwarden.core.rules

object RuleRegistry {
    val allRules: List<Rule> = listOf(
        IntentRedirectionRule(),
        MutablePendingIntentRule(),
        ImplicitPendingIntentRule(),
        DynamicReceiverExportRule(),
        DirtyStreamTraversalRule(),
        ZipSlipRule(),
        WebViewArbitraryUrlRule(),
        WebViewFileAccessRule(),
        JavascriptInterfaceRule(),
        DeepLinkHostValidationRule(),
        InsecureCryptoRule(),
        InsecureRandomRule(),
        InsecureTrustManagerRule(),
        AllowAllHostnameVerifierRule(),
        SqlInjectionRule(),
        WorldReadableWritableRule(),
        HardcodedSecretsRule(),
        CleartextTrafficRule(),
        OverprivilegedPermissionsRule(),
        InsecureSharedPrefsRule(),
        WebViewSslBypassRule()
    )

    fun getRuleById(id: String): Rule? = allRules.firstOrNull { it.id.equals(id, ignoreCase = true) }
}
