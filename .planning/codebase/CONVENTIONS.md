---
last_mapped_commit: 9a02e72e8195e67b54624f6a5d7c701815a9c67b
mapped: 2026-09-23
---

# Conventions — liuzx-sdf-jce

## Language & Comments

- **Code comments are predominantly Chinese**, with bilingual (Chinese + English) text in
  user-facing/error messages (e.g. `SDFException.getErrorDescription`).
- JavaDoc is used on classes with non-obvious contracts — see
  `SDFDeviceOpener`, `SDFLibraryLoader`, `SDFConfig.getRsaKeyLayout`.
- `.feisuan/rules/project_rule.md` states: "所有类、方法、字段需添加注释。注释使用中文。"
  In practice, public API classes and non-trivial methods carry comments; trivial
  accessors often do not.
- Inline comments frequently capture **hardware rationale**, e.g. in `pom.xml`:
  > 若依赖 jar 未签名，运行时 Cipher/Mac/KeyGenerator 会抛 "JCE cannot authenticate the provider LiuZX"

## Naming

| Element | Convention | Example |
|---|---|---|
| Class | `PascalCase` | `SDFSessionManager` |
| Method / field | `camelCase` | `openDeviceIfNeeded()`, `deviceHandle` |
| Constant | `UPPER_SNAKE_CASE` | `DEFAULT_POOL_SIZE`, `PROVIDER_NAME` |
| Package | lowercase, root `org.liuzx.jce` | `org.liuzx.jce.provider.session` |
| SPI classes | `<Alg><Role>Spi` | `SM2SignatureSpi`, `RSACipherSpi`, `SDFHmacSpi` |
| JNA structures | Mirror C struct names | `ECCrefPublicKey`, `RSArefPrivateKey` |
| Vendor variants | `_<VendorOrAlg>` suffix | `ECCrefPublicKey_ECDSA`, `ECCSignature_EDDSA` |
| Parameter specs | `<Alg>InternalKeyGenParameterSpec` | `SM2InternalKeyGenParameterSpec` |
| Tests | `*Test` / hardware `*IT` | `SM2SignatureTest`, `ShudunIT` |
| Scripts | kebab-case `.sh` | `sdf-smoke.sh`, `pack-smoke.sh` |
| System properties | `liuzx.sdf.*` | `liuzx.sdf.library.path` |

## Indentation & Formatting

- Predominant style is **4 spaces**, matching the older `CLAUDE.md`/`.feisuan` rule
  ("使用 4 空格缩进").
- Two files use **tabs** instead: `provider/session/SDFSessionManager.java` and
  `provider/test/ShudunIT.java`. This is an inconsistency to be aware of (no
  formatter/editorconfig enforces one style).
- Line length: no enforced limit; some lines exceed 120 chars (e.g. JNA signatures).
- Import ordering follows the IDE (IntelliJ) default: `com.*`, `org.*`, then `java.*`,
  with `javax.*` mixed into the java group.
- No formatter plugin (spotless/checkstyle) is configured in `pom.xml`.

## Provider Registration Pattern

All algorithm registrations are centralized in
`provider/LiuZXProvider.java → registerServices()`. The pattern is a flat sequence of
`put("<Service>.<Name>", "<fully.qualified.SpiClass>")` calls grouped by comment banners
(`// --- SM2 ---`, `// --- SM4 ---`, ...).

To add an algorithm (from `CLAUDE.md`/`AGENTS.md` checklist, adapted to current code):

1. Register the service in `LiuZXProvider.registerServices()`.
2. Implement the SPI under the matching `provider/asymmetric|symmetric|digest|mac/...` package.
3. Add `XXXInternalKeyGenParameterSpec` if internal-key support is required.
4. Add unit tests (`*Test`).
5. Add i18n keys under `src/main/resources/i18n/` if the demo surfaces it.

> Note: existing guidance documents mention `putService()` / `populateServices()`, but the
> current implementation uses plain `put(...)` inside `registerServices()`. Trust the code.

## SPI Implementation Pattern

Observed across `SM4CipherSpi`, `SM2SignatureSpi`, `RSACipherSpi`:

1. Constructor obtains `SDFSessionManager.getInstance()`.
2. `engineInit` validates key/params and stashes state (e.g. `rawKey`, `iv`, `opmode`)
   **without** holding a session — sessions are borrowed only during the crypto call.
3. `engineUpdate` buffers into a `ByteArrayOutputStream`.
4. `engineDoFinal` borrows an `SDFSession` (try/finally return-to-pool), invokes the JNA
   function, and converts results.
5. Non-zero SDF return codes → `throw new SDFException("<SDF_Function>", rv)`.
6. JCE-mandated exceptions (`InvalidKeyException`, `BadPaddingException`,
   `IllegalBlockSizeException`, `ShortBufferException`) are thrown with correct types.

Cipher variants are implemented as **static nested subclasses** fixed at construction,
because JCE does not call `engineSetMode`/`engineSetPadding` for fully-qualified
transforms. Example (`SM4CipherSpi.java`):

```java
public static class CBC_PKCS5 extends SM4CipherSpi {
    public CBC_PKCS5() { super("CBC", "PKCS5Padding"); }
}
```

## Configuration Conventions

- Every system property name is declared as a `public static final String` constant in
  `SDFConfig` before use (`VENDOR_PROPERTY`, `LIBRARY_PATH_PROPERTY`, ...). Never inline a
  raw property string in other classes.
- Deprecated properties are kept as `@Deprecated` constants with a "Use X" JavaDoc
  (see `CONFIG_PATH_PROPERTY`).
- Constants are trimmed via `trimToNull(...)` before use; absent/blank means unset.
- JSON profiles are strictly validated: unknown fields are rejected, `sha256` must be 64
  hex chars, paths must be portable absolute paths or `classpath:` resources.

## Error Handling

- **Exception type**: `SDFException extends java.security.ProviderException`, carrying
  `functionName` and `errorCode`.
- **Message format**: `"<functionName> failed. Error Code: 0x%08X (<description>)"`.
- **Error codes**: `SDFErrorConstants` (interface, GM/T 0018-2012) — `SDR_BASE = 0x01000000`.
  Vendor extension: `SDR_HSM_NOT_READY = 0x01000403` (Shudun).
- **Recovery policy**: `SDFSessionManager.isSessionLost(rv)` decides between "recover"
  (`SDR_UNKNOWERR`, `SDR_COMMFAIL`, `SDR_HSM_NOT_READY`) and "fail fast".
- **Native load failures**: `SDFLibraryLoader` catches `Throwable`, prints diagnostics to
  `System.err`, and throws `RuntimeException` with `java.library.path` / `jna.library.path`
  in the message. Short-name fallback is off unless explicitly enabled.
- **Optional symbols**: `UnsatisfiedLinkError` from `SDF_OpenDeviceWithPath`/`Ex` is
  treated as "extension unavailable", logged once, and memoized.

## Logging

- `LiuzxProviderLogger.getLogger(Class<?>)` returns a `static final` per-class logger.
- Levels: `DEBUG`, `INFO`, `WARN`, `ERROR`.
- Message style uses `{}` placeholders: `logger.warn("SDF_OpenSession failed: {}", rv)`.
- Logging is disabled by default in the bundled `liuzx-jce.properties`
  (`log.enabled=false`).
- `System.out` / `System.err` are reserved for the CLI demo and native-loader diagnostics
  (`SDFLibraryLoader`), not for library internals.

## Security Conventions

- **Never log private key material.** README records that private-key hex logging was
  removed from the demo in 1.1.2 to satisfy the security constraint.
- **No plaintext key export**: `SDFSM4InternalKey.getEncoded()` intentionally does not
  return raw key bytes.
- Sensitive artifacts are gitignored: `keystore.jks`, `*.jks`, `liuzx-jce.properties`,
  `HSM/**/*.so|dll|ini`, `*.log`, `*.pcap`.
- `classpath:` native libs are SHA-256 pinned and extracted to a permission-restricted
  temp directory.
- System property paths are validated (existence, regular-file, readability) before use.

## Git Commit Conventions

Observed history mixes Chinese summaries and Conventional Commits; the recent dominant
style is:

```
<type>(<scope>): <中文说明>
```

Examples:
- `chore(release): 回到 1.1.5-SNAPSHOT`
- `fix(session): 全局共享单一设备句柄并修正冒烟 MAC 输入`
- `test(smoke): 新增 aarch64/x86_64 自包含测试包打包脚本`
- `docs: 新增 KMC/CA 集成验收清单`

Types seen: `fix`, `feat`, `chore`, `docs`, `test`, `style`, `refactor`. Scopes seen:
`release`, `session`, `smoke`, `hsm`, `scripts`, `dsy`, `version`. Commits are expected to
be atomic (one logical change each) per `.feisuan` / `CLAUDE.md`.

## Build/Release Conventions

- Build: `mvn clean package` (signs the JAR; requires `keystore.jks`).
- Release: `mvn clean deploy -Prelease,gpg-signing -DskipTests=true`, documented step by
  step in `RELEASE.md`.
- The `release` profile must never be combined with a locally modified `pom.xml` version
  prefix (`-SNAPSHOT` is stripped/re-added by `release.sh`).
