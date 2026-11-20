# Outreach Draft for CikeSeven/jotsy

**Target**: CikeSeven/jotsy
**Maintainer**: CikeSeven (@CikeSeven)
**Contact**: llyllydyx@163.com
**Urgent Finding**: [APK-SEC-001] Intent Redirection in Exported Component (🔴 [CRITICAL] / FIRM)

---

### Plain-Text Email Draft (High-Urgency 2.0 with 1-Click PR)

**Subject**: quick pre-release security check of jotsy's APK

Hey CikeSeven,

Came across jotsy while looking at active Android repos on GitHub.

Between Android 14/15 platform changes and subtle bytecode regressions slipping into builds, shipping releases has gotten tricky.

I've been building apkwarden (github.com/no-hup/apkwarden), a free, airgapped CLI that runs as a quiet pre-flight check in CI. It catches platform gotchas and reachable bytecode flaws before release, and otherwise stays silent.

Ran a quick scan on your latest release APK (jotsy-v1.0.1-arm64-v8a.apk):

----------------------------------------------------------------------
APKWarden Release Pre-Flight: jotsy-v1.0.1-arm64-v8a.apk
Scorecard: App: 70/100 | Libs: 85/100 | Unclassified: 0/100
----------------------------------------------------------------------
ACTIONABLE REVIEW QUEUE (Top Finding Preview):

• [APK-SEC-001] Intent Redirection in Exported Component (🔴 [CRITICAL] / FIRM)
  Location:    com.jotsy.diary.MainActivity#startActivityForResult(Landroid/content/Intent;ILandroid/os/Bundle;)V
  Impact:      Exported class 'com.jotsy.diary.MainActivity' forwards an Intent received from external callers directly to 'startActivityForResult' without verifying its target package or component.
  Remediation: Validate that the forwarded Intent's component package matches your application: `if (forwardIntent.getComponent()?.getPackageName() == getPackageName()) { startActivity(forwardIntent); }` or use explicit Intents.
----------------------------------------------------------------------

This is just one highlight from the scan—running `apkwarden <file.apk>` directly gives you the full audit.

Since your release workflow (`.github/workflows/release-apk.yml`) already builds your APKs, dropping in a 1-step check is an easy way to ensure unexpected regressions don't slip into release builds.

If you'd like to test this in your pipeline, reply with "send PR" and I'd be happy to open a clean 1-file PR adding `.github/workflows/apkwarden.yml` to your repo so you can see it run automatically on your next build without any setup on your end.

And if anything in the report looks like a false alarm, feel free to call it out!

Cheers,
Shaurya
https://github.com/no-hup/apkwarden

