# r/androiddev Launch Draft

## Title:
`We built a 60-second CI PR gate to catch silent manifest merger leaks and security regressions (Open Source / Apache-2.0)`

## Post Body:
```markdown
Hey r/androiddev!

If you've maintained a medium-to-large Android app, you've probably encountered this nightmare: a third-party SDK update silently adds an `<activity android:exported="true">` or a dangerous permission (`READ_MEDIA_IMAGES`, `SYSTEM_ALERT_WINDOW`) into your release build through Gradle's manifest merger. You only find out during Play Store review rejection or when an external researcher files a bug.

Traditional static scanners (like MobSF) take 20+ minutes because they decompile every single class into Java files via JADX, which makes them way too slow to run as required checks on every pull request.

To solve this, we built **APKwarden** — a fast, local-first Android security analyzer designed specifically for pull request gating:

### How it Works:
1. **Direct Dalvik Multi-DEX Indexing:** Instead of full decompilation, it uses pure-JVM `dexlib2` to index call-sites and registers directly in memory (<60 seconds on a 100MB release APK, <2GB heap).
2. **Attack Surface Lockfile (`surface.lock.json`):** Similar to how you commit `yarn.lock` or Kotlin API dump files, you commit `surface.lock.json` to git.
   - Any PR that exports an Activity/Service without a permission guard, adds runtime permissions, enables cleartext HTTP traffic, or removes domain certificate pins fails CI with a readable diff.
   - Run in CI against the base branch: `apkwarden diff app-release.apk --git-ref origin/main:surface.lock.json --fail-on-breaking`
3. **Reachability Triage:** In unexported internal classes, dangerous calls are downgraded to LOW/informational rather than breaking builds, eliminating false-positive alert fatigue.
4. **App Bundle & Split Support:** Reads `.aab` bundles (using a zero-dependency AAPT2 compiled protobuf decoder) and multi-DEX split clusters natively without native binary crashes on Apple Silicon / Linux ARM64.
5. **Apache-2.0 Licensed:** Completely free for commercial and internal enterprise CI pipelines (no GPL copyleft).

### 5-Second Local Smoke Test:
```bash
git clone https://github.com/shaurya/apkwarden.git && cd apkwarden
./bin/apkwarden scan samples/sample-vulnerable.apk
```

Or as a composite GitHub Action:
```yaml
- uses: shaurya/apkwarden@v1
  with:
    target: app/build/outputs/apk/release/app-release.apk
    command: diff
    git-ref: origin/main:surface.lock.json
    fail-on-breaking: 'true'
```

Repo: https://github.com/shaurya/apkwarden

Would love your thoughts, especially on tricky manifest merger edge cases or rules you'd like to see added!
```
