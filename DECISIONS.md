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


---

## ADR 007: Milestone 1 Parser Hardening & Export Nuances (Post-Consult Refinements)
* **Date:** 2026-11-12
* **Status:** Accepted
* **Context:** A staff-level adversarial review of our initial Milestone 1 parser identified five critical Android OS and binary parser edge cases:
  1. **ContentProvider Exporting:** Unlike Activities/Services/Receivers, ContentProvider default export is NEVER determined by `<intent-filter>`. By Android platform rules, ContentProviders default to `exported=true` if `targetSdk <= 16`, and `exported=false` if `targetSdk > 16`.
  2. **Three-State Export Classification:** For components on `targetSdk >= 31` with an `<intent-filter>` but missing `android:exported`, Android 12+ refuses to install them, but devices running Android < 12 install and treat them as exported. We must classify this as a distinct state: `EXPLICIT`, `IMPLICIT`, `LEGACY_DEVICE_ONLY`, or `NOT_EXPORTED`.
  3. **Application-Level Permission Inheritance:** Components lacking an explicit `android:permission` inherit `<application android:permission="...">`. Activity aliases inherit target activity permissions if not specified.
  4. **AXML Attribute Identification by Android Resource ID:** Malicious APKs strip or rename attribute strings in the string pool. Attribute lookups must check standard Android resource IDs (`0x01010010` for `exported`, `0x01010003` for `name`, `0x01010006` for `permission`) in addition to string names.
  5. **Network Security Config Platform Defaults:** Cleartext defaults depend on `targetSdk` (allowed by default on `targetSdk <= 27`, blocked on `targetSdk >= 28`); user CA cert trust defaults to true on `targetSdk <= 23`, false on `targetSdk >= 24`.
  6. **Sanitization:** Attacker-controlled package, component, and deep link strings must strip control characters and ANSI escapes to prevent terminal injection.
* **Decision:** Implemented these six refinements into the Milestone 1 core engine before proceeding to Milestone 2.

---

## ADR 008: Pure-JVM Multi-DEX Bytecode Indexing with `dexlib2`
* **Date:** 2026-11-12
* **Status:** Accepted
* **Context:** Android applications span multiple DEX files (`classes.dex`, `classes2.dex`, etc.). Traditional decompilers (e.g. jadx, CFR) produce Java source code which is slow, CPU-intensive, and fails on obfuscated or malformed control flow.
* **Decision:** Use Google's pure-JVM `dexlib2` library to parse Dalvik bytecode directly into memory without decompilation. Build an inverted call-site index (callee -> callers), class inheritance tree, and constant pools across all DEX files in a single pass.
* **Why:** In-memory bytecode indexing runs in seconds (5-10x faster than source decompilation), requires zero external binary tools, is immune to decompilation crashes, and preserves exact Dalvik instruction semantics.

---

## ADR 009: Context-Aware Reachability & Attack Surface Gating
* **Date:** 2026-11-12
* **Status:** Accepted
* **Context:** Traditional static scanners (e.g. MobSF) trigger hundreds of false positives by flagging dangerous calls (e.g. `startActivity(intent)`, `loadUrl(url)`) in private, internal helper classes that external applications cannot invoke.
* **Decision:** Cross-reference all bytecode sink detections with Milestone 1's resolved `AttackSurface`. A call to `startActivity` with an untrusted Intent is only flagged as `INTENT_REDIRECTION` (CRITICAL) if the call site is located within an exported component or reachable from an exported entry point (1–2 hop intra/inter-procedural call graph). Sinks in unexported internal components are either downgraded to `LOW`/`INFO` or suppressed entirely.
* **Why:** Eliminates the #1 reason developers turn off or ignore security scanners: noisy, unexploitable findings in unreachable code.

---

## ADR 010: Milestone 2 Post-Consult Flow & Rule Precision Hardening
* **Date:** 2026-11-12
* **Status:** Accepted
* **Context:** A staff-level adversarial review of the Milestone 2 rules engine identified several critical Dalvik flow and rule precision failure modes:
  1. **Register State Clearing:** Register overwrite tracking must clear destination registers on ANY instruction modifying register A (e.g. `iget`, `sget`, `new-instance`, arithmetic) rather than relying on `CAN_INITIALIZE_REFERENCE`. `check-cast` must preserve register value/taint.
  2. **Lifecycle Parameter Seeding:** Intent sources in components are often passed as method parameters (`onReceive(context, intent)`, `onNewIntent(intent)`, `onStartCommand(intent, ...)`). Method arguments must be seeded with taint tags on entry.
  3. **Explicit Intent Construction:** `new Intent(Context, Class)` is standard explicit intent construction and must NOT be flagged as implicit `PendingIntent`.
  4. **Fail-Open Hardening:** Corrupt/unparseable DEX files must record fatal scanner warnings rather than showing a false "Clean bill of health". Typos in `--fail-on` flags must throw an error rather than silently succeeding.
  5. **False Positive Elimination in Rules:**
     - Exclude `RSA/ECB/...` from ECB warnings (RSA block padding is standard, not ECB vulnerability).
     - Exclude resource IDs (`0x7f...`) from `FLAG_IMMUTABLE` (0x04000000) bitmask checks.
     - Support Kotlin `StringsKt.contains$default` / `endsWith$default` in deep link checks, and recognize leading-dot domains as safe.
     - Ignore `registerReceiver(null, filter)` battery-probe calls.
     - Recognize `File.getName()` as path traversal sanitization in Dirty Stream.
     - Exclude Android package/intent strings (`android.permission.*`) from entropy secret scanner, and raise threshold to 4.5.
     - Inspect manifest `<application android:usesCleartextTraffic="true">` for cleartext HTTP traffic.
  6. **Add Missing Critical SSL Rule:** Added `WebViewClient.onReceivedSslError` calling `handler.proceed()`.
* **Decision:** Implemented these engine and rule precision enhancements across `MethodAnalyzer`, `DexIndex`, and the rules suite.

---

## ADR 011: Milestone 2.5 Hardening — Selective Sink Indexing, Reachability Triage, and Split Multi-DEX Isolation
* **Date:** 2026-11-13
* **Status:** Accepted
* **Context:** A staff-level architecture review of large-scale production APK/AAB compatibility and reachability triage identified five structural improvements:
  1. **Pipeline Unification:** `ScanEngine.scan(archive)` must delegate directly to `ApkAnalyzer.analyzeArchive(archive)`. This guarantees that manifest parsing, ARSC resource resolution (`@bool/x`, `values-v31`), lone-split checks, and stack fingerprinting are 100% consistent across `surface`, `lock`, and `scan`.
  2. **Reachability Triage (`DIRECT`, `REACHABLE`, `UNKNOWN`, `UNREACHABLE`):** Rather than completely dropping findings when a call path is >2 hops away or routed via DI (Dagger/Hilt/ViewModel), findings are categorized with explicit reachability tags:
     - `DIRECT`: Originates directly inside an exported component (CRITICAL/HIGH severity).
     - `REACHABLE`: Statically proven reachable from an exported component within 3 hops (CRITICAL/HIGH severity).
     - `UNKNOWN`: Dangerous sink with tainted inputs, but call graph cannot be statically resolved to an exported entry point (downgraded to MEDIUM severity, TENTATIVE confidence). Never hidden from developers, but prevents false blocks in strict CI gating.
     - `UNREACHABLE`: Caller is an Android component explicitly declared unexported with no callers from exported components (suppressed).
  3. **Selective Sink Indexing in `DexIndex`:** Across 150MB+ production APKs with hundreds of thousands of methods, allocating a `CallSite` object for every Dalvik invocation exhausts multi-gigabyte heaps. Rules now declare `val targetSinks: Set<String>`. `DexIndex.build` only allocates `CallSite` objects for registered sink method names (<25 distinct methods), while retaining the lightweight `callerClass -> targetClass` string graph for reachability traversal. Reduces index memory footprint by >90%.
  4. **AAPT2 Protobuf XML Decoder for Android App Bundles (`.aab`):** In `.aab` archives, `base/manifest/AndroidManifest.xml` is encoded as an AAPT2 compiled protobuf message (`aapt.pb.XmlNode`), not binary AXML (`0x00080003`). Implemented a zero-dependency streaming protobuf decoder (`ProtoXmlDecoder`) integrated into `AxmlParser` that auto-detects and parses AAPT2 XML directly to `AxmlNode`.
  5. **Split APK Multi-DEX Namespace Isolation:** Feature split APKs in split sets often contain conflicting `classes.dex` entries. `SplitApkCluster` now automatically namespaces split DEX entries (`split_${index}_classes.dex`) to ensure complete, collision-free multi-DEX indexing across base and feature splits.
* **Decision:** Implemented these five architectural enhancements into `DexIndex`, `SplitApkCluster`, `ProtoXmlDecoder`, and the rules suite with comprehensive test coverage.



