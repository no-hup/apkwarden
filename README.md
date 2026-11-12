# APKwarden 🛡️

**Fast, reachability-first Android security analyzer.** Drop an APK or App Bundle, get real findings.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Kotlin](https://img.shields.io/badge/Kotlin-2.0.21-purple.svg)](https://kotlinlang.org)
[![Build](https://img.shields.io/badge/Build-Gradle%209.4-green.svg)](https://gradle.org)

---

## Why APKwarden?

Existing open-source APK scanners decompile 100 MB production apps into 100,000+ files, choke for 20+ minutes, flood developers with false-positive regex alerts, and fail silently on modern apps (R8 obfuscation, split APKs, App Bundles, Flutter, React Native).

**APKwarden** takes a fundamentally different approach:
- **Local-first, zero cloud upload:** Analyzes APKs/AABs on your machine or CI with **zero API costs** and **zero risk** of leaking confidential code.
- **Zero Android SDK or Gradle required:** No `android.jar`, no emulator, no NDK needed.
- **In-Memory Hardened Ingest:** Defends against Zip-Slip, Zip Bombs, and duplicate-entry signature bypass anomalies.
- **Multi-Format Ingest:** Native support for `.apk`, `.aab` (Android App Bundles), and split APK sets (`.apks`, `.xapk`, `.apkm`, or split directories).
- **Multi-Config Aware Attack Surface:** Accurately resolves `android:exported` across `minSdk`/`targetSdk` boundaries, handles `@bool/...` configuration qualifiers (like `values-v31`), deep-link cross products, and `FileProvider` paths.
- **`surface.lock.json`:** Generates a deterministic lockfile of your attack surface to commit to git—every PR that accidentally exports an activity, adds a dangerous permission, or loosens network security triggers an immediate PR diff!
- **Transparent Stack & Blind-Spot Statement:** Fingerprints compilers (R8 vs D8, full mode, `pg-map-id`), commercial packers (Jiagu, DexGuard, Promon, etc.), and cross-platform stacks (Flutter, React Native/Hermes, Unity, Cordova).

---

## Quick Start

### 1. Full Security Scan (CLI & CI Gating)
```bash
./gradlew :apkwarden-cli:run --args="scan app.apk"
# Or JSON output for CI pipelines
./gradlew :apkwarden-cli:run --args="scan app.apk --json"
# Or fail CI build if HIGH or CRITICAL issues exist
./gradlew :apkwarden-cli:run --args="scan app.apk --fail-on=HIGH"
```

### 2. Inspect Attack Surface
```bash
./gradlew :apkwarden-cli:run --args="surface app.apk"
```

### 3. Inspect Stack, Compiler, & Blind Spots
```bash
./gradlew :apkwarden-cli:run --args="fingerprint app.apk"
```

### 4. Generate `surface.lock.json` for Git CI Gating
```bash
./gradlew :apkwarden-cli:run --args="lock app.apk -o surface.lock.json"
```

### 5. Verify Archive Integrity
```bash
./gradlew :apkwarden-cli:run --args="ingest-check app.apk"
```

---

## Architecture & Development Status

APKwarden is built in 4 milestones:
- [x] **Milestone 1 — Corpus, Ingest Core & Attack Surface Resolver:**
  - Hardened in-memory zip parser with zip-bomb, zip-slip, and duplicate-entry guards.
  - Binary XML (AXML) parser.
  - `resources.arsc` table parser with configuration qualifier resolution.
  - Multi-format ingest (`.apk`, split clusters, `.aab` without native `aapt2`).
  - Stack fingerprinter & R8 marker extraction (`pg-map-id`).
  - Resolved attack surface & `surface.lock.json` generator.
  - Comprehensive unit & integration test suite.
- [x] **Milestone 2 — Bytecode Call-Site Index & Rules Engine:**
  - Pure-JVM multi-DEX indexing across `classes*.dex` with `dexlib2`.
  - Class inheritance resolution with built-in Android SDK hierarchy mapping.
  - Reachability gating: cross-references bytecode sinks with exported attack surface to eliminate internal false positives.
  - Lightweight intra-procedural register state & taint tracking (`MethodAnalyzer`).
  - 20 high-precision core AppSec rules:
    - `APK-SEC-001`: Intent Redirection in Exported Components (CRITICAL)
    - `APK-SEC-002`: Mutable PendingIntent on Android 12+ (HIGH)
    - `APK-SEC-003`: Implicit PendingIntent Hijacking (MEDIUM)
    - `APK-SEC-004`: Dynamic Receiver Missing Export Flag on Android 14+ (HIGH)
    - `APK-SEC-005`: Dirty Stream File Overwrite Traversal (CRITICAL)
    - `APK-SEC-006`: Zip Slip Archive Extraction Traversal (HIGH)
    - `APK-SEC-007`: Untrusted URL Loaded in WebView from Exported Component (HIGH)
    - `APK-SEC-008`: Insecure WebView File & Universal Access (HIGH/CRITICAL)
    - `APK-SEC-009`: WebView JavaScript Interface Exposure & RCE (MEDIUM/CRITICAL)
    - `APK-SEC-010`: Fragile Deep Link Host Validation via contains/endsWith (MEDIUM)
    - `APK-SEC-011`: Insecure ECB Cipher / DES / Static Keys (HIGH)
    - `APK-SEC-012`: Predictable java.util.Random in Security Contexts (MEDIUM)
    - `APK-SEC-013`: Insecure Custom X509TrustManager SSL Bypass (CRITICAL)
    - `APK-SEC-014`: AllowAll HostnameVerifier MitM Vulnerability (CRITICAL)
    - `APK-SEC-015`: Dynamic SQL Concatenation in rawQuery/execSQL (HIGH)
    - `APK-SEC-016`: World-Readable / World-Writable File Modes (HIGH)
    - `APK-SEC-017`: Hardcoded Cloud Keys & High-Entropy Credentials (HIGH)
    - `APK-SEC-018`: Insecure Cleartext HTTP Traffic in Bytecode (MEDIUM)
    - `APK-SEC-019`: High-Risk Sensitive Android Permissions (MEDIUM)
    - `APK-SEC-020`: Plaintext Tokens in Unencrypted SharedPreferences (LOW)
  - Synthetic Smali DEX fixtures for positive & negative rule verification (31 tests passing).
- [ ] **Milestone 3 — CI Gating, Lockfile Diffs, & Decompilation Snippets**
- [ ] **Milestone 4 — Native Packaging, Homebrew Formula, & Release**

See [DECISIONS.md](DECISIONS.md) for architectural decision records and engineering trade-offs.

---

## Testing

Run the full automated test suite:
```bash
./gradlew test
```

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
