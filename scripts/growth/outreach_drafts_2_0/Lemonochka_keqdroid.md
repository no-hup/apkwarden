# Outreach Draft for Lemonochka/keqdroid

**Target**: Lemonochka/keqdroid
**Maintainer**: Kequinq (@Lemonochka)
**Contact**: lenorakirechaeva@gmail.com
**Urgent Finding**: [APK-SEC-001] Intent Redirection in Exported Component (🔴 [CRITICAL] / FIRM)

---

### Plain-Text Email Draft (High-Urgency 2.0 with 1-Click PR)

**Subject**: quick pre-release security check of keqdroid's APK

Hey Kequinq,

Came across keqdroid while looking at active Android repos on GitHub.

Between Android 14/15 platform changes and subtle bytecode regressions slipping into builds, shipping releases has gotten tricky.

I've been building apkwarden (github.com/no-hup/apkwarden), a free, airgapped CLI that runs as a quiet pre-flight check in CI. It catches platform gotchas and reachable bytecode flaws before release, and otherwise stays silent.

Ran a quick scan on your latest release APK (keqdroid-0.38.5-android.apk):

----------------------------------------------------------------------
APKWarden Release Pre-Flight: keqdroid-0.38.5-android.apk
Scorecard: App: 48/100 | Libs: 5/100 | Unclassified: 60/100
----------------------------------------------------------------------
ACTIONABLE REVIEW QUEUE (Top Finding Preview):

• [APK-SEC-001] Intent Redirection in Exported Component (🔴 [CRITICAL] / FIRM)
  Location:    com.keqdroid.keqdroid.VpnQuickTileService#$r8$lambda$EVL5iDO-NufczKDIPDzlkRTRl8c(Lcom/keqdroid/keqdroid/VpnQuickTileService;Landroid/content/Intent;Lkotlin/jvm/functions/Function1;)V
  Impact:      Exported class 'com.keqdroid.keqdroid.VpnQuickTileService' forwards an Intent received from external callers directly to 'startActivity' without verifying its target package or component.
  Remediation: Validate that the forwarded Intent's component package matches your application: `if (forwardIntent.getComponent()?.getPackageName() == getPackageName()) { startActivity(forwardIntent); }` or use explicit Intents.
----------------------------------------------------------------------

This is just one highlight from the scan—running `apkwarden <file.apk>` directly gives you the full audit.

Since your release workflow (`.github/workflows/release.yml`) already builds your APKs, dropping in a 1-step check is an easy way to ensure unexpected regressions don't slip into release builds.

If you'd like to test this in your pipeline, reply with "send PR" and I'd be happy to open a clean 1-file PR adding `.github/workflows/apkwarden.yml` to your repo so you can see it run automatically on your next build without any setup on your end.

And if anything in the report looks like a false alarm, feel free to call it out!

Cheers,
Shaurya
https://github.com/no-hup/apkwarden

