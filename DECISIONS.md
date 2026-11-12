# Architecture Decision Records (ADRs) & Engineering Log

This document tracks all major architectural decisions, trade-offs, and design rationale for **APKwarden**.

---

## ADR 001: Project Name & Identity
* **Date:** 2026-11-12
* **Status:** Accepted
* **Context:** The tool is a reachability-first Android security analyzer designed for developers, AppSec engineers, and CI pipelines. We needed a name that communicates vigilance, authority, security guarding, and clarity.
* **Decision:** Named **`apkwarden`** (CLI binary: `apkwarden`).
* **Why:** Distinct, unencumbered on GitHub and package managers, instantly recognizable (analogous to trusted open-source security tools like Bitwarden), and clearly communicates its purpose: guarding Android packages.

---

## ADR 002: Distribution & Runtime Model — Local-First Single-Runtime JVM
* **Date:** 2026-11-12
* **Status:** Accepted
* **Context:** We evaluated three execution models: (1) hosted web upload service, (2) Python-based multi-runtime CLI, (3) single-runtime Kotlin/JVM fat JAR / CLI.
* **Decision:** **Local-first Kotlin/JVM CLI** distributed via Homebrew tap (`brew install apkwarden`), standalone archive with `jlink`-trimmed JRE, multi-arch Docker (`ghcr.io/apkwarden/apkwarden`), and composite GitHub Action.
* **Why:**
  1. **Confidentiality:** Security-conscious organizations and developers refuse to upload unreleased APKs/AABs (containing proprietary code, internal routes, and secrets) to external SaaS servers.
  2. **Security Liability:** Running a public server that extracts untrusted third-party APKs exposes the service to parser exploits (e.g. Apktool `CVE-2024-21633`), zip bombs, and malware hosting.
  3. **Zero Host Friction:** Standard Android tools force users to have the Android SDK, Gradle, or an emulator installed. APKwarden requires **zero Android SDK, zero NDK, zero Gradle, and zero emulators**. Everything runs directly on standard JVM bytecode.
  4. **Operating Cost:** \$0/month for both users and maintainers.

---

## ADR 003: Core Engine — Direct Dalvik Bytecode vs. Whole-App JADX + Semgrep
* **Date:** 2026-11-12
* **Status:** Accepted
* **Context:** Existing scanners (like MobSF) decompile the entire APK to thousands of Java files via JADX, then run regex/AST tools like Semgrep over the output.
* **Decision:** **Do NOT decompile the entire app.** Parse Dalvik bytecode directly using `dexlib2` with an in-memory call-site and constant index. JADX is used **strictly lazily** to generate small human-readable Java/Kotlin snippets for flagged classes in final reports.
* **Why:**
  1. **Speed & Memory:** Decompiling a 100 MB production multidex APK generates 50,000–150,000 `.java` files, requires 4–8 GB heap, and takes 10–30+ minutes. Direct bytecode analysis finishes in <60 seconds under 2 GB RAM.
  2. **Decompilation Failures:** Kotlin coroutines, synthetic lambdas, and modern bytecode often decompile to non-compilable or obfuscated garbage in JADX.
  3. **Finding Stability:** JADX decompiler output changes across versions, which shifts source line numbers and breaks stable finding fingerprints in CI.
  4. **Licensing:** Semgrep's official rule registry operates under a restrictive non-compete license. APKwarden uses its own clean Apache-2.0 YAML rule DSL.

---

## ADR 004: In-Memory Bounded Zip Ingest vs. Filesystem Extraction
* **Date:** 2026-11-12
* **Status:** Accepted
* **Context:** Most tools unzip the APK onto the local disk before inspecting files.
* **Decision:** Process APK archives **in-memory via streaming bounded readers**, never extracting untrusted paths to the host disk.
* **Why:**
  1. **Zip-Slip Immunity:** Path traversal sequences (`../../`) inside APK zip entry names cannot escape to the filesystem because entries are never written to disk.
  2. **Zip-Bomb & Memory Exhaustion Guards:** Enforce strict decompression ratio limits (max 100x), per-entry size caps (max 250 MB), and total uncompressed limits.
  3. **Duplicate Entry Validation:** Standard Java `ZipInputStream` and Android's OS package installer resolve duplicate zip entries differently. In-memory validation flags duplicate entry anomalies (which are often signature verification bypass or collision attacks) as security findings.

---

## ADR 005: Multi-Format Ingest — Native AAB Support Without `bundletool` Native Binaries
* **Date:** 2026-11-12
* **Status:** Accepted
* **Context:** Modern Android apps are published as Android App Bundles (`.aab`) or split APK sets (`.apks`, `.xapk`, `.apkm`). Google's official `bundletool` requires native `aapt2` binaries that fail on Linux ARM64 (Apple Silicon Docker containers and ARM CI runners).
* **Decision:** Parse `.aab` archives natively in pure JVM code (reading compiled protobuf `AndroidManifest.xml`, `base/dex/` bytecode, and `BUNDLE-METADATA/.../proguard.map`). Support `.apks`/`.xapk`/`.apkm` by reading the split APK cluster in-memory as a single unified virtual package.
* **Why:** Ensures 100% platform portability across x86_64 and ARM64 without native binary crashes, while providing instant first-class support for `.aab` files.

---

## ADR 006: Resolved Attack-Surface Mapping & `surface.lock.json`
* **Date:** 2026-11-12
* **Status:** Accepted
* **Context:** Developers need a way to track attack surface drift across pull requests without needing an old APK binary on hand.
* **Decision:** Build a multi-config aware `resources.arsc` resolver that resolves `@bool/x`, `@string/x`, and qualifiers (e.g. `values-v31`), calculates true `targetSdk`-aware component export status, deep-link cross products, and generates a deterministic `surface.lock.json`.
* **Why:** Allows engineering teams to commit `surface.lock.json` to their git repository (similar to Kotlin's `apiDump` / `apiCheck`). Any PR that accidentally exports an Activity, adds a dangerous permission, or alters network security configuration shows up as an immediate git diff in GitHub PR reviews.
