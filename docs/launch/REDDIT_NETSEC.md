# r/netsec Launch Draft

## Title:
`Dex-level Android attack-surface diffing and reachability-gated SAST without full JADX decompilation (APKwarden)`

## Post Body:
```markdown
Link: https://github.com/shaurya/apkwarden

Traditional Android SAST tooling (MobSF, AndroBugs, Semgrep) creates high friction in automated CI/CD:
1. Decompiling a 100MB production multidex APK into 50,000–150,000 Java source files via JADX takes 15–30+ minutes and 4–8 GB heap.
2. Source regex/AST matches flag calls to `startActivity`, `loadUrl`, and `Cipher.init` inside private, unreachable internal classes, drowning developers in false positives.
3. Semgrep runs on source code and cannot inspect the merged manifest, library manifests, or compiled R8 output.

We developed **APKwarden**, a local-first Android static security analyzer and PR gate built directly on compiled Dalvik bytecode:

### Technical Architecture
* **Pure-JVM Multi-DEX Indexer:** Uses `dexlib2` with selective sink indexing (allocating call-site objects only for ~25 registered AppSec sinks). Call graphs across multiple DEX files are resolved in memory in under 60 seconds with <2 GB RAM.
* **Reachability-First Triage:** Cross-references dangerous bytecode sinks with resolved entry points.
  - `DIRECT`: Sink invoked directly in exported component lifecycle (`onCreate`, `onReceive`).
  - `REACHABLE`: Statically proven reachable from an exported entry point within 6 hops.
  - `UNKNOWN`: In indirect application code (e.g., ViewModel / Dagger injected service); downgraded to MEDIUM severity.
  - `UNREACHABLE`: Component is explicitly `exported="false"` with zero callers from exported components (suppressed).
* **PR Attack Surface Lockfile (`surface.lock.json`):** Committable lockfile that diffs attack surfaces across pull requests. Catches newly exported unguarded components, stripped permission guards, dangerous permissions (`CAMERA`, `MANAGE_EXTERNAL_STORAGE`), cleartext HTTP traffic, and removed domain certificate pinning.
* **Native Protobuf AAB Parser:** Zero-dependency streaming protobuf decoder for compiled `AndroidManifest.xml` inside `.aab` bundles, avoiding native `aapt2` crashes on Linux ARM64.
* **SARIF 2.1.0 & Baselines:** Serializes into OASIS SARIF 2.1.0 with `@SerialName("security-severity")` tags, `logicalFingerprint/v1` to prevent alert churn across R8 refactors, and `--baseline` support for grandfathered debt.

### Known Limitations & Non-Goals
* Static analysis only: does not perform dynamic runtime instrumentation or Frida hooking.
* Does not disassemble native `.so` machine code into C source (inspects ELF headers and symbol tables only).
* Highly dynamic reflection (`Class.forName(...)`) cannot be statically traversed and is flagged as a potential blind spot.

Code, rules DSL, and benchmark fixtures: https://github.com/shaurya/apkwarden
```
