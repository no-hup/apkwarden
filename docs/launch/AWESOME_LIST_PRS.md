# Curated "Awesome" List Submission Drafts

Submit these PRs after the repository is live on GitHub.

---

## 1. ashishb/android-security-awesome
**Target File:** `README.md` (Under `Static Analysis Tools`)

### Proposed Entry:
```markdown
* [APKwarden](https://github.com/shaurya/apkwarden) - Fast, reachability-first Android static security analyzer and PR gate. Analyzes Dalvik multi-DEX bytecode directly in <60 seconds, diffs attack surface in PRs via `surface.lock.json`, and exports OASIS SARIF 2.1.0 for GitHub Code Scanning. Apache-2.0.
```

### PR Title:
`Add APKwarden to Static Analysis Tools`

### PR Description:
```markdown
Hi! I'd like to suggest adding **APKwarden** to the Static Analysis Tools section.

APKwarden is an open-source (Apache-2.0), local-first Android static security analyzer. Unlike whole-app decompilers, it indexes Dalvik multi-DEX bytecode directly in memory via `dexlib2` (<60s on 100MB apps, <2GB heap) and cross-references dangerous sinks with exported components to eliminate false positives in unreachable internal code. It also supports `.aab` bundles and attack-surface PR diffing.
```

---

## 2. analysis-tools-dev/static-analysis
**Target File:** `data/tools/apkwarden.yml`

### Proposed Entry:
```yaml
name: APKwarden
categories:
  - security
languages:
  - java
  - kotlin
types:
  - apk
  - aab
license: Apache-2.0
homepage: https://github.com/shaurya/apkwarden
source: https://github.com/shaurya/apkwarden
description: "Fast, reachability-first Android security analyzer and PR gate. Scans Dalvik bytecode directly in under 60 seconds with native SARIF 2.1.0 output."
```

### PR Title:
`Add APKwarden (Android security analyzer)`

---

## 3. microsoft/sarif-tutorials / awesome-sarif
**Target File:** `README.md` (Under `SARIF Producers`)

### Proposed Entry:
```markdown
* [APKwarden](https://github.com/shaurya/apkwarden) - Static Android security analyzer that outputs OASIS SARIF 2.1.0 with GitHub Code Scanning `@SerialName("security-severity")` tags, stable logical alert fingerprints, and native baseline suppressions.
```
