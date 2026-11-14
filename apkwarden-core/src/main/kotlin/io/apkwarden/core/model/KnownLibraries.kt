package io.apkwarden.core.model

object KnownLibraries {
    val PREFIXES = listOf(
        "android.", "androidx.", "com.google.", "com.android.",
        "io.grpc.", "com.facebook.", "com.appsflyer.", "com.adjust.",
        "io.sentry.", "com.bytedance.", "com.mbridge.", "com.applovin.",
        "com.unity3d.", "com.ironsource.", "com.vungle.", "com.inmobi.",
        "com.flurry.", "com.crashlytics.", "io.reactivex.", "kotlin.",
        "kotlinx.", "okhttp3.", "okio.", "retrofit2.", "org.apache.",
        "xamarin.", "mono.", "com.microsoft.", "org.chromium.", "com.amazon."
    )

    fun isLibraryClass(className: String): Boolean {
        val norm = className.removePrefix("L").replace('/', '.').removeSuffix(";")
        return PREFIXES.any { norm.startsWith(it) }
    }
}
