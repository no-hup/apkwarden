# APKwarden Agent Operating Guidelines

This guide is for AI coding assistants (Claude Code, Antigravity, GitHub Copilot, Cursor, Devin, Codex) interacting with repositories using APKwarden.

## Primary Workflows

### 1. Running a Security Scan
When asked to scan an APK or check an Android build:
```bash
# If running in the APKwarden repository:
./bin/apkwarden scan path/to/app.apk --sarif results.sarif

# If running as standalone JAR:
java -jar /path/to/apkwarden-all.jar scan path/to/app.apk --sarif results.sarif
```
- **Exit Code 0:** Clean run, zero findings above threshold.
- **Exit Code 2:** Active vulnerabilities found at or above the `--fail-on` threshold (default: `HIGH`).
- To prevent build failure while inspecting all findings, use `--fail-on NEVER`.

### 2. Auditing PR Attack Surface Drift
When a PR modifies `AndroidManifest.xml` or dependencies:
```bash
# Diff built APK against the committed base branch lockfile:
./bin/apkwarden diff path/to/app.apk --git-ref origin/main:surface.lock.json --fail-on-breaking
```
- Returns exit code 2 if breaking attack surface additions are detected (e.g. newly exported Activity without permission, dangerous permissions like `RECORD_AUDIO` or `MANAGE_EXTERNAL_STORAGE`, cleartext HTTP enabled).

### 3. Managing Baseline Technical Debt
When integrating APKwarden into an existing legacy codebase without failing CI on grandfathered issues:
```bash
# 1. Capture initial baseline of existing findings:
./bin/apkwarden scan app.apk --generate-baseline .apkwarden-baseline.json

# 2. Commit .apkwarden-baseline.json to git

# 3. Enforce zero new vulnerabilities in CI:
./bin/apkwarden scan app.apk --baseline .apkwarden-baseline.json --fail-on HIGH
```

### 4. Interpreting Reachability Tags
- `[DIRECT]`: Sink invoked directly in an exported component (`onCreate`, `onReceive`). High priority exploit vector.
- `[REACHABLE]`: Sink statically proven reachable from an exported entry point within 6 call hops.
- `[UNKNOWN]`: Sink is in a helper/service class where entry point could not be statically verified (often reached via dynamic invocation or dependency injection).
- `[UNREACHABLE]`: Component is explicitly `android:exported="false"` with zero exported callers.

### 5. Interpreting SARIF Results
APKWarden generates OASIS SARIF 2.1.0 JSON reports:
- Every finding includes `partialFingerprints["logicalFingerprint/v1"]` which remains stable across R8 code refactors.
- Every rule definition includes `properties["security-severity"]` formatted as a decimal string ("9.0", "8.0", "5.0", "2.0") matching GitHub Code Scanning's schema.
