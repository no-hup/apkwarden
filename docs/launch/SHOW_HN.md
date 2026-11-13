# Show HN Launch Draft

## Title:
`Show HN: APKwarden – Fast, local Android APK scan and PR diff in under a minute`

## First Comment (Post Immediately after Submitting):
```markdown
Hi HN! We built **APKwarden** (Apache-2.0) to solve a specific pain point in Android CI/CD pipelines: static security scanning that is fast enough to run on every pull request without uploading unreleased APKs to third-party cloud servers.

### The Problem
Traditional Android static scanners (like MobSF) were built for manual security assessments. They decompile the entire APK into 100,000+ Java files using JADX, which takes 15–30 minutes, requires 4–8 GB of heap, and generates hundreds of false-positive regex alerts on private, unreachable helper classes. Semgrep, on the other hand, only inspects source code and is blind to Android's manifest merger, library manifests, and compiled R8 output.

### What APKwarden Does
- **Direct Dalvik Multi-DEX Indexing:** Uses pure-JVM `dexlib2` to parse Dalvik bytecode directly in memory (<60s on 100MB multidex APKs under 2GB RAM).
- **PR Attack Surface Diffing (`surface.lock.json`):** Similar to lockfiles in package managers, commit `surface.lock.json` to git. Any PR that accidentally exports an Activity without permissions, adds dangerous permissions (`CAMERA`, `MANAGE_EXTERNAL_STORAGE`), enables cleartext HTTP, or removes certificate pinning is caught as a breaking PR diff.
- **Reachability-First Triage:** Flags in private, unexported classes are downgraded or suppressed, keeping CI alerts focused on exploitable entry points.
- **Modern CI Output:** Native OASIS SARIF 2.1.0 for GitHub Code Scanning, grandfathered baseline suppression (`--baseline`), and rich step summaries.
- **Zero Cloud & Zero Android SDK:** Runs 100% locally on standard Java 17+. No Android SDK, Gradle, NDK, or emulator required.

### What it Refuses to Do (Non-Goals)
- Not an emulator or dynamic sandbox (not a replacement for Frida or manual DAST).
- Does not decompile native C/C++ `.so` machine code into C source.
- Not an iOS scanner.

### Try It in 5 Seconds
```bash
git clone https://github.com/no-hup/apkwarden.git && cd apkwarden
./bin/apkwarden scan samples/sample-vulnerable.apk
```

Code, documentation, and SARIF specifications: https://github.com/no-hup/apkwarden

Feedback and pull requests are very welcome!
```
