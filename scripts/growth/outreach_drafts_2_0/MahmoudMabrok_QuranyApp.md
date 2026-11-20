# Outreach Draft for MahmoudMabrok/QuranyApp

**Target**: MahmoudMabrok/QuranyApp
**Maintainer**: Mahmoud Mabrok Fouad (@MahmoudMabrok)
**Contact**: mahmoudmabrok3579@gmail.com
**Score**: App: 75/100 | Libs: 100/100 | Unclassified: 55/100
**Urgent Finding**: [APK-SEC-018] Cleartext HTTP Traffic Permitted by Configuration (🟠 [HIGH] / CERTAIN)

---

### Plain-Text Email Draft (High-Urgency 2.0 with 1-Click PR)

**Subject**: quick pre-release security check of QuranyApp's APK

Hey Mahmoud,

Came across QuranyApp while looking at active Android repos on GitHub.

Between Android platform security updates and subtle bytecode regressions slipping into builds, shipping updates has gotten tricky.

I've been building apkwarden (github.com/no-hup/apkwarden), a free, airgapped CLI that runs as a quiet pre-flight check in CI. It catches platform gotchas and reachable bytecode flaws before release, and otherwise stays silent.

Ran a quick scan on your release APK (app-release.apk):

----------------------------------------------------------------------
APKWarden Release Pre-Flight: app-release.apk
Scorecard: App: 75/100 | Libs: 100/100 | Unclassified: 55/100
----------------------------------------------------------------------
ACTIONABLE REVIEW QUEUE (Top Finding Preview):

• [APK-SEC-018] Cleartext HTTP Traffic Permitted by Configuration (🟠 [HIGH] / CERTAIN)
  Location:     education.mahmoud.quranyapp
  Reachability: Manifest Declaration
  Evidence:     Manifest android:usesCleartextTraffic="true" explicitly set
  Impact:       Application explicitly permits unencrypted cleartext HTTP traffic across the entire app process.
  Remediation:  Disable global cleartext in AndroidManifest.xml (`android:usesCleartextTraffic="false"`) or scope it to specific domains via network_security_config.xml.
----------------------------------------------------------------------

Looking at your latest source code, your reciter CDN (`cdn.islamic.network`) and speech models are already streaming over HTTPS. So `android:usesCleartextTraffic="true"` in your AndroidManifest is likely obsolete tech debt that can be safely removed to harden your app against MITM risks and keep Play Store checks happy.

Since your CI (`.github/workflows/android ci.yml`) already builds and lints your project, dropping in a 1-step check is an easy way to ensure unexpected regressions don't slip into releases.

If you'd like to test this in your pipeline, reply with "send PR" and I'd be happy to open a clean 1-file PR adding `.github/workflows/apkwarden.yml` to your repo so you can see it run automatically on your next build without any setup on your end.

And if anything in the report looks like a false alarm, feel free to call it out!

Cheers,
Shaurya
https://github.com/no-hup/apkwarden
