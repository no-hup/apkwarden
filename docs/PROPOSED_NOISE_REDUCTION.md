# APKwarden: noise cuts that do not drop real findings

Submitted against APKwarden 0.1.0, from scans of three shipped apps:

- Wispr Flow `com.wispr.flowapp` 1.0.0 (75)
- Paycor `com.paycor.perform` 6.3.9 (2026111204)
- ShareKaro Lite `share.sharekaro.pro` 5.1.49.1 (10501491)

All three scored 0/100. The score starts at 100. A critical costs 25, a high costs 15, a medium costs 5 (`ScanEngine`). One duplicated library critical is enough to floor the score. The findings below are still real bugs and must keep firing: an empty `X509TrustManager.checkServerTrusted` that does not throw, Payactiv WebViews that call `setAllowFileAccess(true)` and `addJavascriptInterface`, ShareKaro‚Äôs own `rawQuery` / `execSQL` call sites, and a 2-argument `registerReceiver` on targetSdk 34+.

These nine changes remove duplicate rows, strings that cannot be a secret or an endpoint, and separate first-party PR gating from third-party library noise. Each one says what to change, why, and why a real issue still shows up.

## 1. Collapse identical hits into one row

**Change.** Before scoring, in `ScanEngine.scan`, collapse findings that share the same rule id, class, method name, method descriptor, and instruction offset. Keep a single row. Record any extra offsets on that row. Count the collapsed list in `ScanSummary` and in the security score.

**Why.** The same sink is being emitted more than once, and the score charges full price per copy.

- Wispr: `io.grpc.util.AdvancedTlsX509TrustManager#checkServerTrusted` is the entire critical section, printed twice, same evidence (‚Äú8 instructions and throws no CertificateException‚Äù). Two criticals is 50 points off the score before any other finding.
- ShareKaro: `APK-SEC-006` prints `com.bytedance.adsdk.ahm.fi#ahm` four times with the same evidence.

`DexIndex.classDefs` is a map keyed by class name, so this is not two different classes. It is the same method (or the same overload shape) leaving the rule twice. The score formula then treats a duplicate as a second vulnerability.

**Why it is safe.** The key includes the method descriptor and the instruction offset. A second overload of `checkServerTrusted` has a different descriptor, so it stays. A second `execSQL` in the same method has a different offset, so it stays. Only a repeated emission of the same site disappears. Nothing that a developer would patch separately is removed.

## 2. Reject framework names in the entropy rule

**Change.** In `HardcodedSecretsRule.isPotentialGenericSecret` (`APK-SEC-017`), also return false when the literal contains any of these substrings, not only when it starts with them:

- `android.permission.`
- `android.intent.`
- `android.settings.`
- `android.provider.`

The known-prefix regex matches (`AKIA‚Ä¶`, `AIza‚Ä¶`, `sk_live_‚Ä¶`, Slack, PEM, Square) stay as they are. Do not add a filter for base64-shaped strings, strings that end in `=`, or strings with no digits.

**Why.** The tentative entropy branch (length 28..80, Shannon entropy > 4.5) is what made ShareKaro unreadable: 5,003 of 5,210 findings. The current denylist only checks prefixes (`android.intent.`, `android.permission.`, `androidx.`, `java.`, `kotlin.`, plus URLs and dotted `.com` / `.java` / `.kt`). Wispr‚Äôs own package still produced hits that are action strings:

- `com.wispr.flowapp.service.OnboardingService` ‚Äî masked `com....NTED` (a permission-granted action)
- `com.wispr.ui.home.HomeScreenKt` ‚Äî masked `andr...SION`
- `com.wispr.ui.protection.DeviceProtectionManager` ‚Äî masked `andr...IONS`

Those are `android.settings.*` / permission action names. They do not start with the prefixes the rule already ignores, so they fall through to the entropy check and come out as medium findings at confidence tentative.

**Why it is safe.** A cloud key, a PEM block, or a bearer token does not contain `android.permission.`, `android.intent.`, `android.settings.`, or `android.provider.`. The known-key regexes run first, so a real AWS or Google key embedded in a longer string is still reported at high / certain. ShareKaro‚Äôs 5,003 hits look like tokens (`VeE5‚Ä¶qGw=`). They do not contain those substrings, so they stay. Dropping ‚Äúno digits‚Äù or ‚Äúhigh entropy base64‚Äù would also drop a real alphabetic or base64 secret. That cut is not in this change.

## 3. Skip documentation URLs, and report the cleartext flag once

**Change.** In `CleartextTrafficRule` (`APK-SEC-018`), extend the existing URL skip list. It already drops `localhost`, `127.0.0.1`, `schemas.android.com`, `w3.org`, and `apache.org`. Also skip literals whose host is a reserved or namespace name:

- `example.com` (and `www.example.com`)
- `ns.adobe.com`
- `javax.xml.XMLConstants`
- `purl.org`
- `www.w3.org` is already covered by `w3.org`

Do not skip `10.0.2.2`.

When `attackSurface.usesCleartextTraffic == true`, or the network security config‚Äôs base config allows cleartext, emit one finding whose evidence is that flag or config. Keep the per-URL findings only for the URLs that survive the skip list.

**Why.** On Paycor (targetSdk 36, payroll) the manifest sets `android:usesCleartextTraffic=true`. That is the issue. The rule never says so. It only lists hardcoded `http://` strings, and only because cleartext is already permitted. The strings it listed are not servers the app uses:

- `http://www.example.com/showad`
- `http://ns.adobe.com/xap/1.0/`
- `http://javax.xml.XMLConstants/property/accessExternalDTD`
- `http://10.0.2.2:8443/` inside Pendo

The first three are a reserved example host and XML namespace URIs. They burned three of the ten URL slots (`distinctUrls.entries.take(10)`), which can push a real endpoint off the list.

**Why it is safe.** `example.com` is reserved by RFC 2606. The Adobe XMP and `XMLConstants` strings are schema identifiers. No app reaches those hosts for user data. A real `http://` API host does not match that list, so it is still reported. `10.0.2.2` is the Android emulator‚Äôs alias for the host machine. A build that still calls it is a shipped debug endpoint, so it stays. The new flag finding adds the Paycor case the URL list missed. It does not replace the URL findings for real hosts.

## 4. Skip SQL construction only when every appended piece is a constant

**Change.** In `SqlInjectionRule` (`APK-SEC-015`), keep the current gate: the method contains `StringBuilder.append`, `String.concat`, or `String.format`, and it calls `SQLiteDatabase.rawQuery` or `execSQL`. Add one exception. If every `append` / `concat` / `format` argument the analyzer can see is a string constant, do not emit. If any argument is a register `MethodAnalyzer` cannot resolve, emit exactly as today.

**Why.** The rule currently asks only ‚Äúdoes this method contain both a string builder and a SQL call?‚Äù It does not ask whether the built string is the query, or whether any piece is non-constant. Media3 and Play services schema helpers (`androidx.media3.database.StandaloneDatabaseProvider`, `com.google.android.gms.measurement.internal.j`) are flagged high / firm for `CREATE TABLE` style SQL. That is static SQL. On ShareKaro the same rule also hits `share.sharekaro.pro.*` methods whose arguments are not constants. Those are the ones worth a ticket. The static ones bury them: 74 SQL findings in that app, 15 in Wispr, almost all libraries.

**Why it is safe.** Injection needs a non-constant fragment (user input, another register, a return value). A method where every appended piece resolved to a const-string cannot include that. The fail-open side is the important one: an unresolved register still produces the finding, at the same severity and confidence as today. This does not require taint proof. ShareKaro‚Äôs own call sites stay as long as the analyzer cannot show that every piece is a literal. If the analyzer is unsure, the finding remains.

## 5. Attribute one-line intent helpers to the app caller

**Change.** For `APK-SEC-001` (intent redirection), when the sink class is `androidx.core.content.ContextCompat` or `androidx.activity.ComponentActivity` and the sink method is `startActivity` or `startActivityForResult`, look at the caller that reached that helper. If that caller is an application class, emit the finding on the caller, with the helper named in the evidence. If the caller is itself one of those two helpers, walk one more step. If no application caller is visible, emit the helper row exactly as today.

Do not add a package denylist. Do not apply this rewrite to `PendingIntentCompat`, ads SDKs, or WebView rules.

**Why.** On these scans the intent-redirect highs are the helper, not the app. Wispr and Paycor both flag `androidx.core.content.ContextCompat#startActivity` and `androidx.activity.ComponentActivity#startActivityForResult` because the tainted value is ‚Äúa method parameter of type Intent‚Äù. Those methods are one-line forwards. The bug, when there is one, is the app method that passed an attacker-controlled intent in. The report currently stops at the library frame, so the app team sees a framework class they do not own and closes the ticket.

**Why it is safe.** The helper row is dropped only when an application caller was found and reported instead. The same sink, the same taint, and the same rule id are still in the report, on the method the app can actually change. When the scanner cannot see an app caller (the usual case for a library that is only reachable through reflection or a call chain the reachability pass did not recover), the original helper finding stays. No sink is discarded.

## 6. Default reachability to UNKNOWN when the rule did not check it

**Change.** In `Finding`, the default `reachability` is `Reachability.DIRECT`. Change that default to `Reachability.UNKNOWN`. Rules that already set `DIRECT`, `REACHABLE`, or `UNREACHABLE` from a real check keep passing that value explicitly. `APK-SEC-013` does not compute reachability today. It will come out as `UNKNOWN` instead of `DIRECT`.

**Why.** The product docs say `[DIRECT]` means the sink is invoked from an exported component. `InsecureTrustManagerRule` never looks at exported components. It iterates `checkServerTrusted` implementations and tags the result with the default. On Wispr that printed `[DIRECT]` on a gRPC class. A reader treating the badge as the docs define it will treat a library method as a confirmed entry-point bug. That is a false alarm, not a second vulnerability. The severity and the finding stay.

**Why it is safe.** This does not delete a finding, lower a severity, or skip a class. A trust manager that returns without throwing is still critical. A rule that has computed `DIRECT` and passes it in is unchanged. The only thing removed is a default label that the rule did not earn.


## 7. Recognize delegation and forwarding in `X509TrustManager` overloads (`APK-SEC-013`)

**Change.** In `InsecureTrustManagerRule` (`APK-SEC-013`), check if a `checkServerTrusted` overload with fewer arguments invokes a sibling overload (e.g. `checkServerTrusted(chain, authType, socket)` or `checkServerTrusted(chain, authType, engine)`), or invokes an instance field delegate (`checkClientTrusted` / `checkServerTrusted` on a nested `X509TrustManager` field). If the method invokes another `checkServerTrusted` overload or a delegate object, do not emit.

**Why.** `javax.net.ssl.X509ExtendedTrustManager` defines three overloads of `checkServerTrusted`. In standard libraries like Google's gRPC (`io.grpc.util.AdvancedTlsX509TrustManager`), the legacy 2-argument overload (`chain, authType`) forwards directly to the 3-argument overload with a null `Socket` or `SSLEngine`. Because the 2-argument forwarder does not throw directly (the delegate method throws), the current rule flags it as a `CRITICAL` vulnerability with `CERTAIN` confidence. That single false positive deducted 50 points (with duplication) on Wispr Flow.

**Why it is safe.** Real malicious stubs and naive bypasses do not invoke a sibling overload or a delegate; they contain an empty body (`return-void`). If a method contains NO `invoke-*` instructions and returns immediately without throwing, it is an empty stub and will still be flagged as `CRITICAL`. If the sibling overload or delegate being called is itself empty and non-throwing, that sibling method will be analyzed on its own merits and flagged. Only non-empty forwarding adapters are spared.

## 8. Classify public client-side telemetry tokens as `INFO` (`APK-SEC-017`)

**Change.** In `HardcodedSecretsRule` (`APK-SEC-017`), introduce a dedicated `CLIENT_TELEMETRY_TOKEN` category for known public ingest tokens, specifically:

- PostHog project API keys (`^phc_[a-zA-Z0-9_-]{32,64}$`)
- Firebase Web API keys (`^AIzaSy[a-zA-Z0-9_-]{33}$`)
- Sentry public DSN URLs (`https://[a-f0-9]+@o[0-9]+\.ingest\.sentry\.io/[0-9]+`)
- Datadog client tokens (`^pub[a-f0-9]{32}$`)

Report these at severity `INFO` and confidence `CERTAIN`, with guidance on verifying client key write-only scopes in the vendor dashboard. Do not emit them under the generic high-entropy `MEDIUM / TENTATIVE` branch or the high-severity credential leak rule.

**Why.** On Wispr Flow, `phc_...` was flagged under `APK-SEC-017`. In modern Android and web architecture, PostHog project keys, Firebase web keys, and Sentry DSNs are public client-side telemetry endpoints. They are mathematically required to be compiled into the client app to ingest analytics events and crash reports. They have zero read permissions and zero account administrative access. Calling them a credential leak creates friction with engineering teams who know the key is meant to be public.

**Why it is safe.** The finding is not deleted, suppressed, or hidden. It remains visible in CLI summaries and SARIF reports at `INFO` severity, reminding developers to ensure the token has restricted write-only permissions. True private credentials (AWS `AKIA...`, Stripe `sk_live_...`, Google Cloud Service Account JSONs, GitHub personal access tokens, Slack bot tokens, PEM private keys) remain strictly classified as `HIGH` or `CRITICAL` at confidence `CERTAIN`.

## 9. Attribute first-party app code vs. third-party SDKs in scoring and CI gates

**Change.** In `ScanSummary` and the PR diff gating logic, calculate two separate score metrics:

1. **Application Security Score (First-Party):** Evaluates findings in classes starting with `context.appPackageName` (or recognized application packages). This score determines `--fail-on` evaluation for PR gating.
2. **Dependency Risk Score (Third-Party):** Evaluates findings inside third-party libraries (`androidx.*`, `com.google.*`, `com.appsflyer.*`, etc.). Reported in an explicit "Third-Party Dependencies" section.

**Why.** On our three-app benchmark, 99.3% of all findings (5,410 out of 5,445) were inside third-party vendor libraries that application developers did not write and cannot modify. On Paycor, 100% of findings were in libraries (0 in `com.paycor.*`), yet the app received a score of `0/100`. When third-party library noise floors every app's score to zero, CI gating becomes impossible, and developers disable the tool.

**Why it is safe.** No findings are suppressed or omitted. All 5,182 library findings in ShareKaro and 108 in Paycor remain fully recorded in the SARIF report, exported to GitHub Code Scanning, and displayed in the CLI output. The change merely separates the PR failure threshold so developers are held accountable for code they actually own, while dependency vulnerabilities are tracked as supply-chain debt rather than blocking developer feature PRs.

## Not proposed

These would remove more noise, and they would also mute real issues. They are listed so they are not folded into the change above.

- Suppressing `androidx.*`, Play services, gRPC, Facebook, or ads SDKs by package. ShareKaro‚Äôs only critical is `com.facebook.ads.redexgen.X.b9#checkServerTrusted` (one instruction, no throw) inside an SDK the app ships. Paycor‚Äôs WebView findings are in `com.payactiv.aar`, which is product code and looks like a dependency by name.
- Narrowing `APK-SEC-013` to a one-instruction `return-void`. The rule already ignores a method that calls `checkServerTrusted`. The gRPC method is 8 instructions and does not throw. Some real bypasses log and return. They would disappear with that cut.
- Requiring proven taint on the SQL register before `APK-SEC-015` fires. Any call site where the analyzer loses the register, including ShareKaro‚Äôs own, would go quiet.
- Dropping 2-argument `registerReceiver` on targetSdk >= 34 (`APK-SEC-004`). On Android 14 that call throws `SecurityException`. ShareKaro has one in its own package. The ad-SDK copies are noisy, and they are still crash sites if that code runs.
- Filtering base64-looking entropy hits, or moving them out of detection. After change 2, ShareKaro will still be dominated by those strings. They are shaped like keys. A later presentation choice can group them as unverified so they do not own the score. That is not part of this change, because it changes what the score claims, and this list is limited to cuts that do not change what gets detected.

