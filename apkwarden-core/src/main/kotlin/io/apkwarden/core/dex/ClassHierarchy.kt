package io.apkwarden.core.dex

import com.android.tools.smali.dexlib2.iface.ClassDef

class ClassHierarchy(private val classDefs: Map<String, ClassDef>) {

    private val knownSdkHierarchy: Map<String, List<String>> = mapOf(
        "androidx.appcompat.app.AppCompatActivity" to listOf("androidx.fragment.app.FragmentActivity", "android.app.Activity"),
        "androidx.fragment.app.FragmentActivity" to listOf("androidx.activity.ComponentActivity", "android.app.Activity"),
        "androidx.activity.ComponentActivity" to listOf("android.app.Activity"),
        "android.app.Activity" to listOf("android.view.ContextThemeWrapper", "android.content.ContextWrapper", "android.content.Context"),
        "android.app.Service" to listOf("android.content.ContextWrapper", "android.content.Context"),
        "android.content.ContextWrapper" to listOf("android.content.Context"),
        "android.view.ContextThemeWrapper" to listOf("android.content.ContextWrapper", "android.content.Context"),
        "android.webkit.WebView" to listOf("android.widget.AbsoluteLayout", "android.view.ViewGroup", "android.view.View"),
        "android.webkit.WebViewClient" to listOf("java.lang.Object"),
        "android.webkit.WebChromeClient" to listOf("java.lang.Object"),
        "android.content.BroadcastReceiver" to listOf("java.lang.Object"),
        "android.content.ContentProvider" to listOf("java.lang.Object"),
        "javax.net.ssl.X509TrustManager" to listOf("javax.net.ssl.TrustManager"),
        "org.apache.http.conn.ssl.AllowAllHostnameVerifier" to listOf("javax.net.ssl.HostnameVerifier"),
        "org.apache.http.conn.ssl.SSLSocketFactory" to listOf("java.lang.Object")
    )

    fun isSubclassOf(subclassName: String, superclassName: String): Boolean {
        val normSub = normalizeType(subclassName)
        val normSuper = normalizeType(superclassName)

        if (normSub == normSuper) return true
        if (normSuper == "java.lang.Object") return true

        val visited = mutableSetOf<String>()
        return checkInheritance(normSub, normSuper, visited)
    }

    private fun checkInheritance(current: String, target: String, visited: MutableSet<String>): Boolean {
        if (!visited.add(current)) return false
        if (current == target) return true

        // Check internal class definition first
        val def = classDefs[current]
        if (def != null) {
            def.superclass?.let { s ->
                val normS = normalizeType(s)
                if (normS == target || checkInheritance(normS, target, visited)) return true
            }
            for (iface in def.interfaces) {
                val normI = normalizeType(iface)
                if (normI == target || checkInheritance(normI, target, visited)) return true
            }
        }

        // Check known Android SDK hierarchy
        val sdkParents = knownSdkHierarchy[current]
        if (sdkParents != null) {
            for (parent in sdkParents) {
                if (parent == target || checkInheritance(parent, target, visited)) return true
            }
        }

        return false
    }

    companion object {
        fun normalizeType(descriptor: String): String {
            if (descriptor.isEmpty()) return descriptor
            val trimmed = descriptor.trim()
            return if (trimmed.startsWith("L") && trimmed.endsWith(";")) {
                trimmed.substring(1, trimmed.length - 1).replace('/', '.')
            } else {
                trimmed.replace('/', '.')
            }
        }

        fun toDescriptor(className: String): String {
            val norm = normalizeType(className)
            return "L${norm.replace('.', '/')};"
        }
    }
}
