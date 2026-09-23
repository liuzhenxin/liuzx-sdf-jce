---
last_mapped_commit: 9a02e72e8195e67b54624f6a5d7c701815a9c67b
mapped: 2026-09-23
---

# Integrations — liuzx-sdf-jce

## Overview

The library has exactly **one external runtime integration: the SDF native dynamic
library** loaded through JNA. There is no database, no HTTP client, no message queue, no
auth provider, and no webhook. All other integrations are build/release-time
(Maven Central, GPG) or downstream-consumer (KMC / CA / NAS) integrations.

## 1. Native SDF Library (JNA) — primary integration

**Boundary:** `org.liuzx.jce.jna.SDFLibrary` (JNA `Library` interface, 257 lines) exposes
the GM/T 0018-2012 C ABI. Structures live in `org.liuzx.jce.jna.structure` (16 classes).

Representative functions (`src/main/java/org/liuzx/jce/jna/SDFLibrary.java`):

| Group | Functions |
|---|---|
| Device/session | `SDF_OpenDevice`, `SDF_CloseDevice`, `SDF_OpenSession`, `SDF_CloseSession`, `SDF_GetDeviceInfo`, `SDF_OpenDeviceEx`, `SDF_OpenDeviceWithPath` |
| Random | `SDF_GenerateRandom`, `SDF_GenerateRandomExt` |
| Key access | `SDF_GetPrivateKeyAccessRight`, `SDF_ReleasePrivateKeyAccessRight`, `SDF_GetSymmKeyHandle` |
| SM2/ECC | `SDF_ExportSignPublicKey_ECC`, `SDF_GenerateKeyPair_ECC`, `SDF_GenerateKeyWithIPK_ECC/EPK_ECC`, `SDF_ImportKeyWithISK_ECC`, `SDF_ExternalSign_ECC`, `SDF_InternalSign_ECC`, `SDF_ExternalEncrypt_ECC`, `SDF_InternalEncrypt_ECC`, ECDH agreement/`SDF_GenerateKeyWithECC` |
| RSA | `SDF_GenerateKeyPair_RSA`, `SDF_ExportSignPublicKey_RSA`, `SDF_InternalSign_RSA`, `SDF_ExternalPublicKeyOperation_RSA`, `SDF_ExternalPrivateKeyOperation_RSA`, `SDF_InternalPrivateKeyOperation_RSA`, `SDF_InternalEncrypt_RSA`, `SDF_InternalDecrypt_RSA` |
| Symmetric | `SDF_ImportKey`, `SDF_ImportKEK`, `SDF_ImportKeyWithKEK`, `SDF_GenerateKeyWithKEK`, `SDF_DestroyKey` |
| ECDSA/EdDSA/DSA | `SDF_GenerateKeyPair_ECDSA/EDDSA`, `SDF_InternalSign_ECC_ECDSA/EDDSA`, `SDF_ExternalSign_ECC_ECDSA/EDDSA` |

### Library resolution
`SDFConfig` → `SDFLibraryLoader` → `Native.load(path, SDFLibrary.class)`.

Priority: explicit `liuzx.sdf.library.path` → external profile → bundled profile →
(optional) short-name fallback `sdcrypto4j` when
`liuzx.sdf.library.fallback-enabled=true`.

### Device open strategy
`SDFDeviceOpener.open()` implements **standard-first, extension-fallback**:

1. Always call standard `SDF_OpenDevice` (exported by all vendors).
2. Only if it fails **and** `liuzx.sdf.vendor-config.path` is set, probe
   `SDF_OpenDeviceWithPath` (Shudun aarch64 / SanSec, takes config dir) then
   `SDF_OpenDeviceEx` (DYSX, takes INI path).
3. Missing symbols raise `UnsatisfiedLinkError`; these are memoized in a
   `ConcurrentHashMap.newKeySet()` and ignored.
4. `getLastSuccessfulOperation()` reports which entry point actually opened the device
   (used by `scripts/sdf-smoke.sh`).

### Session lifecycle
`SDFSessionManager` (384 lines) is a **process-wide singleton** with double-checked
locking (native library loaded first to avoid `JNI_OnLoad` recursion). Key invariant:
**one global `deviceHandle`, many `SDF_OpenSession` sessions** (Shudun requires a single
device open per application). Pool is `ArrayBlockingQueue` (default 16) with borrow
timeout (default 5000 ms). On `isSessionLost(rv)` the device handle is reset/closed and
reopened once; a JVM shutdown hook closes everything.

## 2. Vendor-Specific Quirks (integration constraints)

| Vendor | Library name | Config | Notes |
|---|---|---|---|
| **Shudun (数盾)** | `libsdhsmcrypto.so` / `sdhsmsdf_x64.dll` | `sdhsm.ini` (directory) | Bundled in JAR via `classpath:`; **variable-length (packed) RSA struct layout**, `rsaKeyLayout=packed`; HSM-not-ready code `0x01000403` triggers session self-heal; **does not export ECDSA/EdDSA/DSA keypair functions** |
| **DYSX (大云/德阳?)** | `libsdf.so` | `cacipher.ini` (file) | Standard fixed-size RSA layout; supports ECDSA/EdDSA/DSA; `SDF_Encrypt_Index`/`SDF_Decrypt_Index` are deprecated vendor extensions |
| **SanSec (三未信安)** | `libswsds.so` | `swsds.ini` (directory) | `SDF_OpenDeviceWithPath` accepted as fallback; not bundled in JAR |

RSA ABI differs per vendor (`RsaKeyLayout.STANDARD` vs `PACKED`); conversion is
centralized in `org.liuzx.jce.provider.asymmetric.rsa.RSAKeyConverter`. Max RSA size
supported: 4096 bits.

## 3. Downstream Consumers (outbound integrations)

- **liuzx-kmc** — key management centre; consumes 1.1.4 for hardware key operations.
- **liuzx-ca** — certificate authority; integration probe `scripts/accept-ca.sh`.
- **liuzx-nas** — provided the original SM4-internal-key / keyIndex use case
  (`SDFSM4Keys.internalKey(index)`).
- Integration acceptance checklist: `doc/KMC-CA-INTEGRATION-CHECKLIST.md`.
- `scripts/install-to.sh` installs the built artifact into a remote Maven `~/.m2`.

## 4. Distribution / Release Integrations

| Integration | Where | Details |
|---|---|---|
| Maven Central (Sonatype Central Portal) | `pom.xml` `release` profile | `central-publishing-maven-plugin`, server id `central` |
| GPG signing | `pom.xml` `release` profile | `maven-gpg-plugin` with `gpg.keyname` / `gpg.passphrase` |
| JAR signing (JCE requirement) | `pom.xml` `package` phase | `keystore.jks`, alias `dayou` |
| RFC 3161 timestamping | `maven-jarsigner-plugin` / `signjar` | `http://timestamp.sectigo.com` |
| GitHub Pages | `index.html` | Project landing page |
| GitHub repo | SCM block in `pom.xml` | `github.com/liuzhenxin/liuzx-sdf-jce` |

## 5. What Is NOT Integrated

- No logging framework (Log4j/SLF4J) — custom logger only.
- No JDBC/ORM/database.
- No HTTP/REST client or server.
- No dependency injection framework.
- No CI workflow files (`.github/workflows` absent) — releases are driven manually by
  `release.sh` / `RELEASE.md`.
- No `liuzx-sdf-jce` dependency on `liuzx-sdf-jce`-external PKI modules; it is a leaf
  library.
