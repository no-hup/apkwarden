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

### 1. Inspect Attack Surface
```bash
./gradlew :apkwarden-cli:run --args="surface app.apk"
```

### 2. Inspect Stack, Compiler, & Blind Spots
```bash
./gradlew :apkwarden-cli:run --args="fingerprint app.apk"
```

### 3. Generate `surface.lock.json` for Git CI Gating
```bash
./gradlew :apkwarden-cli:run --args="lock app.apk -o surface.lock.json"
```

### 4. Verify Archive Integrity
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
- [ ] **Milestone 2 — Play Pre-Flight, SBOM, & PoC Generation**
- [ ] **Milestone 3 — Bytecode Call-Site Index & YAML Rule Engine**
- [ ] **Milestone 4 — CI Gating, Diff Engine, & Release Packaging**

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
