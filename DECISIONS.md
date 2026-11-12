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

---

## ADR 012: Milestone 3 — Attack Surface Diffing, SARIF 2.1.0, Baseline Suppression, and Disassembly Snippets
* **Date:** 2026-11-13
* **Status:** Accepted
* **Context:** Developers and security teams integrating APKwarden into CI/CD pipelines need automated guardrails against regressions, seamless reporting into GitHub Code Scanning, grandfathered finding suppression, and immediate code context for flagged vulnerabilities.
* **Decision:**
  1. **Lockfile Diff Engine (`apkwarden diff`):** Compares committed `surface.lock.json` against new APK builds or PR lockfiles. Automatically flags breaking attack surface drift: added exported unguarded components, permission guards removed, dangerous runtime permissions added (`CAMERA`, `RECORD_AUDIO`, etc.), cleartext HTTP traffic enabled, user CA certificate trust enabled, domain pinning removed, and targetSdk downgrades. Exits with code 2 on breaking changes to gate PR merges.
  2. **SARIF 2.1.0 Output (`--sarif <file>`):** Serializes scan results into the standard OASIS Static Analysis Results Interchange Format (SARIF 2.1.0) compatible with GitHub Code Scanning (`upload-sarif`), GitLab SAST, Azure DevOps, and IDE SARIF viewers. Maps Dalvik findings to Smali virtual file URIs, line regions, rule definitions, remediation markdown, and CWE/OWASP tags.
  3. **Baseline Suppression (`--baseline <file>` / `--generate-baseline <file>`):** Enables engineering teams to record existing legacy vulnerabilities into `.apkwarden-baseline.json`. Findings matching the baseline are marked `(SUPPRESSED)` and bypassed during `--fail-on` threshold evaluation, allowing teams to enforce strict zero-vulnerability gating on new code without failing builds on grandfathered tech debt.
  4. **Contextual Dalvik Disassembly Snippets:** Instead of requiring full-app decompilation or leaving developers guessing, `MethodAnalyzer` generates 5-line Dalvik bytecode snippets surrounding flagged call sites with an arrow pointer (`>`) at the sink instruction. Displayed directly in CLI output and embedded in SARIF report snippets.

---

## ADR 013: Milestone 3 Post-Consult Staff Refinements & CI Hardening
* **Date:** 2026-11-13
* **Status:** Accepted
* **Context:** A staff-level adversarial review of the Milestone 3 SARIF, Diff, and reachability engine identified critical real-world CI integration edge cases:
  1. **GitHub Code Scanning Severity Contract:** GitHub Code Scanning ignores SARIF `level: "error"` when classifying alert severity. It strictly requires `@SerialName("security-severity")` on `SarifRuleProperties` formatted as a decimal string ("9.0" Critical, "8.0" High, "5.0" Medium, "2.0" Low). Without this, GitHub displays all alerts with default badges regardless of rule criticality.
  2. **Alert Fingerprint Stability (`partialFingerprints`):** In CI static analysis, line numbers shift between commits as code changes, causing GitHub Code Scanning to close existing alerts and reopen duplicate ones. Added `logicalFingerprint/v1` computed from `ruleId:targetClass:targetMethod` hash, ensuring alerts stay stable across refactors.
  3. **Native SARIF Suppressions:** Rather than filtering suppressed findings completely out of the SARIF report, APKwarden includes them with native SARIF `suppressions` objects (`kind: "external"`, `status: "accepted"`, `justification: "Grandfathered baseline suppression"`). This allows GitHub Code Scanning to track baseline debt visibly without failing check runs.
  4. **Snippet Secret Redaction:** Disassembly snippets for hardcoded credential rules (`APK-SEC-012`, `APK-SEC-013`) could expose real secrets in plain text inside CI build logs and SARIF artifacts. Snippet generation now masks sensitive literal values with `[REDACTED_SECRET]`.
  5. **Outer Class Lambda Reachability:** Kotlin compiles lambdas and coroutines into separate inner classes (e.g. `MainActivity$onCreate$1`). A pure class-equality check fails to associate the lambda with its enclosing component. `DexIndex.checkReachability()` now resolves inner classes by stripping the `$` suffix to test the enclosing class against the attack surface.
  6. **PR Lockfile Self-Approval Prevention (`--git-ref`):** If CI diffs against the local `surface.lock.json` in the PR checkout, a developer can inadvertently commit a new lockfile that auto-approves their own breaking changes. The `--git-ref <ref>` option allows CI workflows to run `git show origin/main:surface.lock.json` to guarantee comparison against the protected base branch.
  7. **Fatal Bytecode CI Gating:** If DEX parsing fails due to corrupt bytecode or undetected packers, `--fail-on` gates will fail the CI run with exit code 2 if any `Failed to parse` scan warning is logged, preventing silent fail-open passes.
  8. **Dangerous Permission Expansion:** Expanded `dangerousPermissions` set in `SurfaceDiffEngine` to include modern scoped storage and system alert permissions (`MANAGE_EXTERNAL_STORAGE`, `QUERY_ALL_PACKAGES`, `SYSTEM_ALERT_WINDOW`, `WRITE_SETTINGS`, `REQUEST_INSTALL_PACKAGES`, `ACCESS_BACKGROUND_LOCATION`, etc.).
* **Decision:** Implemented these refinements into `SarifSerializer`, `SarifReport`, `MethodAnalyzer`, `DexIndex`, `SurfaceDiffEngine`, and `Main.kt`.

---

## ADR 014: Milestone 4 — Packaging, Distribution, GitHub Action, and Public Launch
* **Date:** 2026-11-13
* **Status:** Accepted
* **Context:** The engine is feature-complete with 21 AppSec rules, attack surface diffing, and SARIF export. To drive widespread adoption across developers and AppSec engineers, APKwarden requires zero-friction local installation, container execution, and first-class CI/CD pipeline automation.
* **Decision:**
  1. **Dual Packaging Strategy (Fat JAR + Tarball Distribution):**
     - Configured Gradle `fatJar` task creating `apkwarden-all.jar` (~10MB self-contained executable). Runs on any system with Java 17+ without extracting or setting up classpath.
     - Configured `application` plugin (`distTar`, `distZip`, `installDist`) providing native UNIX shell and Windows batch launchers (`bin/apkwarden`).
  2. **Universal Local Runner (`bin/apkwarden`):** Root launcher script providing instant out-of-the-box CLI execution from git clones with automatic incremental compilation fallback.
  3. **Composite GitHub Action (`action.yml` & `scripts/run-action.sh`):**
     - First-class GitHub Action that runs `scan`, `diff`, `surface`, or `lock`.
     - Supports automated SARIF 2.1.0 upload to GitHub Code Scanning via `github/codeql-action/upload-sarif@v3`.
     - Automatically renders rich visual step summaries to `$GITHUB_STEP_SUMMARY` with vulnerability scoreboards, collapsible high-severity cards, and Dalvik disassembly snippets.
     - Automatically falls back to downloading pre-built fat JAR from GitHub Releases.
  4. **Homebrew Formula (`Formula/apkwarden.rb`):** Packaged for Homebrew taps (`brew install apkwarden`), configuring `Language::Java.overridable_java_home_env` to automatically bind Java 17+.
  5. **Secure Multi-Arch Docker Container (`Dockerfile`):** Multi-stage build on `eclipse-temurin:17-jre-alpine` running as non-root user `apkwarden` (UID 10001) with multi-arch support (`linux/amd64`, `linux/arm64`).
  6. **Automated CI/CD Workflows:** `.github/workflows/ci.yml` (multi-OS build, unit tests, CLI smoke tests, and SARIF verification) and `.github/workflows/release.yml` (GitHub Release publishing with checksums and GHCR container push).






