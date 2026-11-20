# Outreach Draft for evokelektrique/tunnel-forge

**Target**: evokelektrique/tunnel-forge
**Maintainer**: Bardiya (@femdiya)
**Contact**: femdiya@proton.me
**Urgent Finding**: [APK-SEC-001] Intent Redirection in Exported Component (🔴 [CRITICAL] / FIRM)

---

### Plain-Text Email Draft (High-Urgency 2.0 with 1-Click PR)

**Subject**: quick pre-release security check of tunnel-forge's APK

Hey Bardiya,

Came across tunnel-forge while looking at active Android repos on GitHub.

Between Android 14/15 platform changes and subtle bytecode regressions slipping into builds, shipping releases has gotten tricky.

I've been building apkwarden (github.com/no-hup/apkwarden), a free, airgapped CLI that runs as a quiet pre-flight check in CI. It catches platform gotchas and reachable bytecode flaws before release, and otherwise stays silent.

Ran a quick scan on your latest release APK (tunnel-forge-v0.7.9-android-arm64-v8a.apk):

----------------------------------------------------------------------
APKWarden Release Pre-Flight: tunnel-forge-v0.7.9-android-arm64-v8a.apk
Scorecard: App: 65/100 | Libs: 85/100 | Unclassified: 10/100
----------------------------------------------------------------------
ACTIONABLE REVIEW QUEUE (Top Finding Preview):

• [APK-SEC-001] Intent Redirection in Exported Component (🔴 [CRITICAL] / FIRM)
  Location:    io.github.evokelektrique.tunnelforge.MainActivity#r(Landroid/content/Intent;)Z
  Impact:      Exported class 'io.github.evokelektrique.tunnelforge.MainActivity' forwards an Intent received from external callers directly to 'startActivity' without verifying its target package or component.
  Remediation: Validate that the forwarded Intent's component package matches your application: `if (forwardIntent.getComponent()?.getPackageName() == getPackageName()) { startActivity(forwardIntent); }` or use explicit Intents.
----------------------------------------------------------------------

This is just one highlight from the scan—running `apkwarden <file.apk>` directly gives you the full audit.

Since your release workflow (`.github/workflows/release.yml`) already builds your APKs, dropping in a 1-step check is an easy way to ensure unexpected regressions don't slip into release builds.

If you'd like to test this in your pipeline, reply with "send PR" and I'd be happy to open a clean 1-file PR adding `.github/workflows/apkwarden.yml` to your repo so you can see it run automatically on your next build without any setup on your end.

And if anything in the report looks like a false alarm, feel free to call it out!

Cheers,
Shaurya
https://github.com/no-hup/apkwarden

