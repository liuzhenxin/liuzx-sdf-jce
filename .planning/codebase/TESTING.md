---
last_mapped_commit: 9a02e72e8195e67b54624f6a5d7c701815a9c67b
mapped: 2026-09-23
---

# Testing — liuzx-sdf-jce

## Framework

| Item | Value |
|---|---|
| Framework | JUnit 5 (`junit-jupiter-api` + `junit-jupiter-engine` 5.8.2) |
| Runner | `maven-surefire-plugin` 2.22.2 |
| Default behavior | **Tests are skipped** — `pom.xml:53` sets `<skipTests>true</skipTests>` |
| Test source root | `src/test/java` |
| Test annotation | `@Test` (JUnit Jupiter) |
| Conditional enablement | `@EnabledIfSystemProperty` |

## Running Tests

```bash
# Default build: tests are skipped
mvn clean package

# Run everything (requires a real SDF device for most tests)
mvn test -DskipTests=false

# Run a single class
mvn test -Dtest=SM2SignatureTest -DskipTests=false

# Run a single method
mvn test -Dtest=SM2SignatureTest#methodName -DskipTests=false

# Hardware integration test profile (only ShudunIT)
mvn test -Pshudun-it
```

> `skipTests` is a *property*, not a hardcoded skip, so `-DskipTests=false` re-enables the
> suite. The `shudun-it` profile sets `skipTests=false` and restricts `includes` to
> `**/*ShudunIT.java`.

## Test Inventory

### Unit / config tests (runnable without hardware)

These were added in 1.1.3 to make configuration and loader logic testable in isolation:

| Test | Path | Cover |
|---|---|---|
| `SDFConfigTest` | `src/test/java/org/liuzx/jce/provider/SDFConfigTest.java` | Profile parsing/validation |
| `SDFLibrarySelectionTest` | `src/test/java/org/liuzx/jce/jna/SDFLibrarySelectionTest.java` | Library selection policy (uses `SDFLibraryLoader.NativeLoader` seam) |
| `RSAKeyConverterTest` | `src/test/java/org/liuzx/jce/provider/asymmetric/rsa/RSAKeyConverterTest.java` | `standard` vs `packed` RSA layout conversion |
| `SM2PublicKeyEncodingTest` | `src/test/java/org/liuzx/jce/provider/asymmetric/sm2/SM2PublicKeyEncodingTest.java` | X.509 public key encoding |
| `SDFDeviceOpenerTest` | `src/test/java/org/liuzx/jce/provider/session/SDFDeviceOpenerTest.java` | Standard-first/extension-fallback open logic |
| `SDFSessionManagerLifecycleTest` | `src/test/java/org/liuzx/jce/provider/session/SDFSessionManagerLifecycleTest.java` | Pool lifecycle/shutdown |
| `SDFInternalKeyHandleResolverTest` | `src/test/java/org/liuzx/jce/provider/symmetric/SDFInternalKeyHandleResolverTest.java` | Internal SM4 handle resolution |
| `SDFSM4InternalKeyTest` | `src/test/java/org/liuzx/jce/provider/symmetric/SDFSM4InternalKeyTest.java` | Internal SM4 key model (no encoded material) |
| `I18nTest` | `src/test/java/org/liuzx/jce/demo/I18nTest.java` | Message bundle loading |

`SDFDeviceOpener` exposes `static void resetCapabilities()` explicitly documented as a
"Test hook" — the pattern for making native-adjacent logic testable.

### Hardware-facing tests (`provider/test/`)

All require a real SDF device/library; they are the functional acceptance suite.

| Test | `@Test` count | Notes |
|---|---:|---|
| `ShudunIT` | 3 | `@EnabledIfSystemProperty(named="shudun.it.enabled", matches="true")`; device probe + hardware random, SM2 key material, RSA 2048/4096 |
| `SM2InternalKeyTest` | 4 | Parameterized key index + PIN |
| `SM2InternalKeyUsageTest` | 4 | Internal sign/verify/encrypt/decrypt |
| `SDFSecureRandomTest` | 3 | `SecureRandom("SDF")` |
| `SM4CipherTest` | 2 | ECB/CBC encrypt/decrypt round trips |
| `RSAFullFeatureTest` | 2 | Full RSA feature matrix |
| `RSAExternalKeyGenTest` | 1 | External key generation (2048/4096) |
| `RSAInternalKeyCipherTest` | 1 | Internal RSA cipher |
| `RSAInternalKeyUsageTest` | 1 | Internal RSA sign |
| `SM2CipherTest` | 1 | SM2 encrypt/decrypt |
| `SM2SignatureTest` | 1 | SM2 sign/verify |
| `SM3DigestTest` | 1 | SM3 known-answer vector |

`SM3DigestTest` is notable: it asserts a **verified vector** and documents that the original
expected value was wrong and was corrected against `openssl dgst -sm3` and the Shudun device:

```java
String expectedHash = "44F0061E69FA6FDFC290C494654A05DC0C053DA7E5C52B84EF93A9D67D3FFF88";
```

## Test Structure & Patterns

- Package mirrors production under `org.liuzx.jce.provider.test` (legacy location for the
  hardware tests) plus focused packages (`session`, `symmetric`, `asymmetric.rsa`, ...).
- Provider registration idiom:
  ```java
  if (Security.getProvider(LiuZXProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new LiuZXProvider());
  }
  ```
  `ShudunIT` additionally sets `System.setProperty("liuzx.sdf.vendor", "Shudun")` in
  `@BeforeAll`.
- Hardware tests are **not isolated**: they share a process-wide `SDFSessionManager`
  singleton and a real device. Always close/return sessions; there is no test-side
  teardown of the JVM singleton.
- No mocking framework (no Mockito). Testability is achieved via constructor/factory seams
  (`SDFLibraryLoader.NativeLoader`, `SDFConfig` injection) rather than mocks.
- `@DisplayName` is recommended by `.feisuan`/`CLAUDE.md` for clarity, though coverage is
  inconsistent in the current tests.

## Coverage

- **No coverage tooling** (no JaCoCo, no Sonar) is configured.
- Effective coverage strategy is layered:
  1. Pure logic (config parsing, RSA layout, library selection, device open fallback) has
     no-hardware unit tests.
  2. Cryptographic behavior is validated against real hardware (functional/acceptance).
  3. End-to-end on a remote HSM host is validated by shell-driven smoke scripts.

## Hardware / Smoke Test Tooling (outside Surefire)

### `scripts/sdf-smoke.sh`
Non-interactive smoke test driving `org.liuzx.jce.demo.SdfSmokeTest`. Prints
`[PASS]/[FAIL]/[SKIP]` per check and the effective device-open strategy; exit code 0 iff
all required checks pass.

Environment variables: `SMOKE_VENDOR` (default `Shudun`), `SMOKE_LIBRARY_PATH`,
`SMOKE_CONFIG_PATH`, `SMOKE_EXPECT_STRATEGY`, `SMOKE_SM2_SIGN_INDEX`,
`SMOKE_RSA_SIGN_INDEX`, `SMOKE_SM4_KEY_INDEX`, `SMOKE_PIN`, `SMOKE_SKIP_BUILD`,
`SMOKE_MAVEN_OPTS`.

### `scripts/pack-smoke.sh`
Builds a self-contained `target/liuzx-sdf-jce-smoke-<vendor>-<arch>.tar.gz` containing the
JAR, JNA/Gson, vendor native libs, editable device config, and a generated `run-smoke.sh`.
Env: `PACK_VENDOR`, `PACK_ARCH` (`aarch64`/`x86_64`), `PACK_LIBRARY_PATH`,
`PACK_CONFIG_PATH`, `PACK_OUT_DIR`, `PACK_SKIP_BUILD`.

### `scripts/accept-kmc.sh` / `scripts/accept-ca.sh`
Integration probes simulating downstream KMC/CA usage.

### Documented acceptance evidence
- `doc/SHUDUN-AARCH64-ACCEPTANCE.md` — records **14/14 PASS** on real Shudun aarch64
  hardware (2026-09-17).
- `doc/KMC-CA-INTEGRATION-CHECKLIST.md` — integration acceptance items.

## Conventions for New Tests

1. Name unit tests `*Test`; hardware integration tests `*IT` and gate them with
   `@EnabledIfSystemProperty` (follow `ShudunIT`).
2. Keep hardware-independent logic in `SDFConfig`, `SDFLibraryLoader`, `SDFDeviceOpener`,
   `RSAKeyConverter` so it can be unit-tested without a device.
3. Use reproducible vectors for digest/cipher tests; cross-check with `openssl`.
4. Do not assert on logging side effects or create log files unintentionally
   (`log.enabled=false` in bundled config).
5. Do not commit device configs, PINs, or keys used by tests — HSM material lives under
   gitignored `HSM/` and Pins are passed via `-D`/env only.

## Known Gaps

- `README.md` "构建与运行" still says `mvn clean package` runs tests, while the POM skips
  them — documentation drift.
- Hardware tests cannot run in generic CI (no CI workflow exists).
- Very few negative-path tests exist for SPI classes (invalid key sizes, bad padding,
  wrong key type) — most coverage is happy-path against hardware.
