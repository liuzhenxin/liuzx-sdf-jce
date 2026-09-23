---
last_mapped_commit: 9a02e72e8195e67b54624f6a5d7c701815a9c67b
mapped: 2026-09-23
---

# Concerns — liuzx-sdf-jce

Technical debt, risks, fragile areas, and known issues. Ordered by severity.

---

## HIGH — Security

### C1. Hardcoded keystore password and signing key committed build config
`pom.xml` hardcodes the JAR-signing credentials in plaintext:

```xml
<keystore>${project.basedir}/keystore.jks</keystore>
<alias>dayou</alias>
<storepass>123456</storepass>
<keypass>123456</keypass>
```

- `keystore.jks` itself is gitignored, but the password is public and trivially weak.
- The same password is duplicated in the Antrun `signjar` block for JNA/Gson.
- `.feisuan/rules/project_rule.md` documents the same credentials, reinforcing the pattern.
- **Risk**: if `keystore.jks` leaks (it is passed around locally / may be injected into CI),
  anyone can sign a malicious "LiuZX" provider JAR that the JCE framework would accept.
- **Recommendation**: move credentials to `settings.xml`/environment, rotate the key,
  and use a strong passphrase.

### C2. `release.sh` / release flow depends on local secrets not in source control
`RELEASE.md` instructs storing `gpg.passphrase` in `~/.m2/settings.xml` and fetching
`keystore.jks` from outside the repo. There is no CI workflow, so releases are performed
on developer machines — no reproducibility or auditability. (See C1 for the escalated
version of this concern.)

### C3. Private-key / PIN exposure surfaces
- `SMOKE_PIN` is passed as a JVM `-D` argument, so it appears in `ps` output on the HSM
  host. The README acknowledges this. Same pattern applies to internal-key tests.
- `run.sh stress <threads> <seconds> <index> [password]` accepts a password on the command
  line, again visible in process listings.
- Vendor `sdhsm.ini` / `cacipher.ini` are copied into smoke test bundles (`conf/`) which may
  contain device credentials/certificates. README warns not to distribute them, but the
  packaging script default behavior makes accidental leakage easy.

---

## HIGH — Fragility / Correctness

### C4. Vendor-specific RSA struct layout is a landmine
The `rsaKeyLayout: packed` support (Shudun) relies on manually computed byte offsets
inside `RSArefPrivateKey` (`m/e/d[512] + CRT[256]`) and "整体平移" of sub-fields.
`RSAKeyConverter` concentrates this logic, which is good, but:
- It is reverse-engineered behavior, not a spec. A vendor library update could silently
  change semantics and produce wrong crypto results rather than an error.
- 4096-bit keys occupy the full standard struct — edge cases around exactly-4096-bit
  boundaries are fragile.
- Regression protection is limited to `RSAKeyConverterTest` plus on-device tests.

### C5. JCE signing of dependency JARs is version-coupled by hardcoded filenames
`maven-antrun-plugin` signs exactly `jna-5.10.0.jar` and `gson-2.9.0.jar`. Bumping either
dependency **without** updating `pom.xml` yields a runtime
`JCE cannot authenticate the provider LiuZX` — a confusing failure far from the cause.
The `pom.xml` comment warns about this, but nothing enforces it. Consider using
`<fileset>`/`<path refid>` or a `maven-jarsigner` per-dependency execution instead.

### C6. Singleton `SDFSessionManager` is process-global and hard to reset
- One JVM = one pool = one device handle. Tests and applications cannot easily isolate or
  reinitialize it.
- `getInstance()` has no `resetInstance()`; `shutdown()` is irreversible
  (`IllegalStateException` thereafter) and is only triggered by the JVM shutdown hook.
- `SDFSessionManagerLifecycleTest` covers some lifecycle, but any library consumer sharing
  a JVM across vendor switches cannot reconfigure without a restart.

### C7. Device-open fallback depends on unverifiable vendor symbols
`SDFDeviceOpener` probes `SDF_OpenDeviceWithPath` / `SDF_OpenDeviceEx` dynamically and
memoizes missing symbols in a static set with a **test-only** `resetCapabilities()`. If a
vendor library is loaded after a failed probe in the same JVM, the memoized "missing"
result persists. In practice only one library is loaded per JVM, so impact is low, but the
static mutable state is a design smell.

---

## MEDIUM — Build & Release

### C8. Tests skipped by default → regressions can ship
`<skipTests>true</skipTests>` means `mvn clean package` and the release command
(`-DskipTests=true`) never run tests. Most tests need hardware, but the unit tests
(`SDFConfigTest`, `RSAKeyConverterTest`, `SDFLibrarySelectionTest`,
`SDFSessionManagerLifecycleTest`, `SDFDeviceOpenerTest`, ...) are hardware-independent and
**should run in the default build**. Consider splitting unit vs hardware tests and enabling
the former by default.

### C9. No CI
There is no `.github/workflows`. No automated compile, no unit-test gate, no dependency
scanning, no reproducible release. All verification is manual on a dev machine or HSM host.

### C10. Deprecated `SDF_Encrypt_Index` / `SDF_Decrypt_Index` still bound
README 1.1.4 marks these as deprecated vendor extensions "仅保留给按厂商能力门控的调用方
（如 DYSX）". Keeping deprecated vendor-specific paths in the JNA binding increases the
surface for confusion and accidental use. Audit for callers and remove if unused.

### C11. `README.md` version drift
- README "当前版本: 1.1.4"; POM is `1.1.5-SNAPSHOT`.
- README examples reference `liuzx-sdf-jce-1.1.3.jar` in `-cp` commands.
- README says `mvn clean package` "编译+测试"; POM skips tests.
- `AGENTS.md` (a CodeBuddy/agent guidance file) describes an older state: it references
  `populateServices()` / `putService()`, strings-only `sdf-config.json`, and omits
  ECDSA/EdDSA/DSA, internal SM4, packed RSA, and the `Shudun` vendor. It also still uses
  provider name `"liuzx"` in examples instead of `"LiuZX"`.
- `CLAUDE.md` also states provider name fixed as `"liuzx"` — outdated since 1.1.0.

### C12. Mismatched guidance docs
Three overlapping agent-guidance files exist — `AGENTS.md`, `CLAUDE.md`,
`.feisuan/rules/project_rule.md` — with inconsistent content (Java 1.8 vs "JDK 25 主框架",
dependency list, directory tree, provider name). Maintenance burden and risk of an agent
following stale guidance.

---

## MEDIUM — Code Quality

### C13. Indentation inconsistency (tabs vs spaces)
`SDFSessionManager.java` and `ShudunIT.java` use tabs; the rest of the codebase uses
4 spaces. No `.editorconfig`, no formatter plugin (spotless/checkstyle) enforces a style.

### C14. Large configuration/loader classes
- `SDFConfig.java` is 597 lines and mixes OS/arch detection, JSON parsing+validation,
  path validation, SHA-256 verification, and classpath extraction. Candidate for splitting
  (e.g. `ProfileParser`, `ClasspathLibraryExtractor`).
- `SDFSessionManager.java` is 384 lines with device + pool + shutdown responsibilities.

### C15. Classpath native library extraction
`extractClasspathLibrary` extracts `.so`/`.dll` to a temp dir. Robustness concerns:
- Temp cleanup on JVM exit is not evident — repeated runs may accumulate extracted libs.
- Vendors whose library depends on sibling `.so` files cannot work from the single-file
  extraction (README acknowledges this; production must use `liuzx.sdf.library.path`).
- Relies on filesystem permissions for security; extraction correctness depends on
  SHA-256 config being present (it is, for Shudun, but not enforced for all `classpath:`
  specs).

### C16. `SDFException.getErrorDescription` is a large `switch` with bilingual literals
Maintaining a 30+ case switch of hardcoded bilingual strings is brittle; the i18n bundles
(`messages_zh/en.properties`) are used only by the demo, not by exceptions. Consider
centralizing all user-visible text in resources.

### C17. Provider name migration debt
`LegacyLiuZXProvider` exists purely so old consumers using name `"liuzx"` keep working.
It is extra supported surface with no deprecation timeline documented. Decide on a removal
version.

### C18. `System.err` diagnostics in library code
`SDFLibraryLoader` writes directly to `System.err` instead of the custom logger. This
bypasses `log.enabled=false` and may surprise embedders. It runs before logging is
guaranteed initialized, which explains but does not fully justify the choice.

---

## LOW — Housekeeping

### C19. Committed log files and binary artifacts in working tree
`liuzx-jce-2025-12-03.log`, `liuzx-jce-2026-07-25.log`, `liuzx-jce-2026-08-07.log`,
`sm4-index1-hardware-test.pcap`, `keystore.jks`, `sdhsm.ini`, `.DS_Store` are present in the
working directory. They are gitignored, but their presence invites accidental commits and
leaks (`.pcap` may contain device traffic; logs may contain operation details).

### C20. On-site HSM material directory committed as skeleton
`HSM/` contains vendor libs and INI configs that are gitignored individually. The
`.gitignore` rules are broad and correct, but the `.so`/`.ini` files still exist locally.
A `git add -f` or gitignore-rule mistake would leak vendor SDKs and device credentials.

### C21. `AGENTS.md` naming collision
The repo-root `AGENTS.md` is actually an agent-guidance doc (titled "CODEBUDDY.md").
In the PKI workspace, `AGENTS.md` has a different meaning (workspace-level repo guide), so
the filename is confusing.

### C22. Version in `pom.xml` vs git tag
Current `1.1.5-SNAPSHOT` has no corresponding work yet beyond the version bump commit
`9a02e72`. Fine, but note the tag `v1.1.4` does not exist for the preliminary docs commits
between `v1.1.4` and HEAD if any release is made without re-tagging.

---

## Summary of Recommended Priorities

1. **Rotate the JCE signing key and remove hardcoded passwords** (C1, C2).
2. **Enable hardware-independent unit tests in the default build** and add CI (C8, C9).
3. **Harden the dependency-signing mechanism** against version bumps (C5).
4. **Reconcile guidance docs + README with the actual code** (C11, C12, C21).
5. **Reduce release-time secret exposure** (PINs on command line, smoke bundles) (C3).
6. **Refactor `SDFConfig` / `SDFSessionManager`** and clean up static state (C7, C14).
7. **Decide fate of deprecated vendor extensions and legacy provider** (C10, C17).
