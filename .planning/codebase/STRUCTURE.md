---
last_mapped_commit: 9a02e72e8195e67b54624f6a5d7c701815a9c67b
mapped: 2026-09-23
---

# Structure — liuzx-sdf-jce

## Repository Layout

```
liuzx-sdf-jce/
├── pom.xml                       # Maven build, signing, release profile
├── keystore.jks                  # JCE JAR signing keystore (gitignored)
├── run.sh / run.bat              # Demo launchers (Linux/macOS, Windows)
├── release.sh                    # Automated release driver
├── sdhsm.ini                     # Local device config (gitignored)
├── src/
│   ├── main/
│   │   ├── libsdf.h              # Reference SDF C header (ABI source of truth)
│   │   ├── java/org/liuzx/jce/
│   │   │   ├── demo/             # CLI demo, smoke test, stress testers, i18n
│   │   │   ├── jna/              # SDFLibrary, SDFLibraryLoader
│   │   │   │   └── structure/    # 16 JNA structures mirroring C structs
│   │   │   └── provider/
│   │   │       ├── LiuZXProvider.java        # Provider + service registry
│   │   │       ├── LegacyLiuZXProvider.java  # legacy "liuzx" name
│   │   │       ├── SDFConfig.java            # profile/library/RSA-layout config
│   │   │       ├── asymmetric/
│   │   │       │   ├── sm2/      # 7 files: KPG, Signature, Cipher, KeyAgreement, keys, spec
│   │   │       │   ├── rsa/      # 6 files: KPG, Signature, Cipher, converter, SDFRSAPrivateKey, spec
│   │   │       │   ├── ecdsa/    # 4 files: KPG, Signature, keys
│   │   │       │   ├── eddsa/    # 4 files: KPG, Signature, keys
│   │   │       │   └── dsa/      # 4 files: KPG, Signature, keys
│   │   │       ├── symmetric/    # 6 files: SM4 cipher/KG/keys, internal key, handle resolver
│   │   │       ├── digest/       # SM3Digest, SDFDigest (SHA family + MD5)
│   │   │       ├── mac/          # SDFMacSpi (SM4MAC), SDFHmacSpi (HMAC family)
│   │   │       ├── random/       # SDFSecureRandomSpi
│   │   │       ├── session/      # SDFSession, SDFSessionManager, SDFDeviceOpener
│   │   │       ├── exception/    # SDFException, SDFErrorConstants
│   │   │       ├── log/          # LiuzxProviderLogger
│   │   │       └── util/         # ASN1Util, SM3Util, HexUtil, GMObjectIdentifiers, DeviceInfoUtil
│   │   └── resources/
│   │       ├── sdf-config.json   # Bundled vendor profile
│   │       ├── liuzx-jce.properties  # Logging config
│   │       ├── i18n/             # messages_en.properties, messages_zh.properties
│   │       └── native/shudun/    # Bundled native libs (linux-x86_64, linux-aarch64, windows-x86_64)
│   └── test/java/org/liuzx/jce/
│       ├── demo/I18nTest.java
│       └── provider/
│           ├── SDFConfigTest.java
│           ├── asymmetric/rsa/RSAKeyConverterTest.java
│           ├── asymmetric/sm2/SM2PublicKeyEncodingTest.java
│           ├── jna/SDFLibrarySelectionTest.java
│           ├── session/SDFDeviceOpenerTest.java
│           ├── session/SDFSessionManagerLifecycleTest.java
│           ├── symmetric/SDFInternalKeyHandleResolverTest.java
│           ├── symmetric/SDFSM4InternalKeyTest.java
│           └── test/             # 12 hardware-facing tests incl. ShudunIT
├── scripts/                      # Acceptance + packaging tooling
│   ├── sdf-smoke.sh              # Non-interactive hardware smoke test
│   ├── pack-smoke.sh             # Self-contained test bundle for HSM host
│   ├── install-to.sh             # Install artifact to remote ~/.m2
│   ├── accept-kmc.sh             # KMC integration probe
│   └── accept-ca.sh              # CA integration probe
├── doc/
│   ├── SHUDUN-AARCH64-ACCEPTANCE.md
│   └── KMC-CA-INTEGRATION-CHECKLIST.md
├── HSM/                          # On-site vendor materials (libs gitignored)
│   ├── README.md
│   ├── sdf-profile.json
│   ├── DYSX/2.0/...
│   ├── SanSec/1.3.87/...
│   └── SHUDUN/...
└── index.html                    # GitHub Pages landing page
```

## Package Responsibilities

| Package | Path | Responsibility |
|---|---|---|
| `org.liuzx.jce.provider` | `provider/` | Provider entry + configuration |
| `...provider.asymmetric.sm2` | `provider/asymmetric/sm2/` | SM2 sign/verify/cipher/agreement, internal+external keys |
| `...provider.asymmetric.rsa` | `provider/asymmetric/rsa/` | RSA sign/cipher, packed/standard conversion, internal keys |
| `...provider.asymmetric.ecdsa` | `provider/asymmetric/ecdsa/` | ECDSA (internal keys only; vendor-dependent) |
| `...provider.asymmetric.eddsa` | `provider/asymmetric/eddsa/` | EdDSA (internal keys only; vendor-dependent) |
| `...provider.asymmetric.dsa` | `provider/asymmetric/dsa/` | DSA (internal keys only; vendor-dependent) |
| `...provider.symmetric` | `provider/symmetric/` | SM4 cipher modes, key generation, internal keys, KEK handle resolution |
| `...provider.digest` | `provider/digest/` | SM3 and SHA/MD5 hardware digests |
| `...provider.mac` | `provider/mac/` | SM4-MAC and HMAC SPIs |
| `...provider.random` | `provider/random/` | Hardware `SecureRandom` |
| `...provider.session` | `provider/session/` | Device/session lifecycle, pooling, fallback open |
| `...provider.exception` | `provider/exception/` | SDF error codes and exception type |
| `...provider.log` | `provider/log/` | Zero-dependency logger |
| `...provider.util` | `provider/util/` | ASN.1, hex, OIDs, device info helpers |
| `...jna` | `jna/` | C ABI binding + library loader |
| `...jna.structure` | `jna/structure/` | JNA `Structure` subclasses for SDF structs |
| `...demo` | `demo/` | CLI demo, smoke, stress, i18n |

## Package Size (Java files)

```
16  jna/structure
 7  provider/asymmetric/sm2
 6  provider/symmetric
 6  provider/asymmetric/rsa
 6  demo
 5  provider/util
 4  provider/asymmetric/eddsa
 4  provider/asymmetric/ecdsa
 4  provider/asymmetric/dsa
 3  provider/session
 3  provider
 2  provider/mac
 2  provider/exception
 2  provider/digest
 2  jna
 1  provider/random
 1  provider/log
```

## Key Locations Quick Reference

| Need to change... | Edit |
|---|---|
| Which algorithms are exposed | `provider/LiuZXProvider.java` → `registerServices()` |
| Vendor library paths / SHA-256 / RSA layout | `src/main/resources/sdf-config.json` |
| Config precedence or validation rules | `provider/SDFConfig.java` |
| Device open fallback logic | `provider/session/SDFDeviceOpener.java` |
| Session/device pooling & recovery | `provider/session/SDFSessionManager.java` |
| JNA C ABI additions | `jna/SDFLibrary.java` + `jna/structure/` |
| Native library loading failure behavior | `jna/SDFLibraryLoader.java` |
| Logging behavior | `log/LiuzxProviderLogger.java` + `liuzx-jce.properties` |
| Error code → message mapping | `provider/exception/SDFException.java` |
| Build/signing/release | `pom.xml`, `release.sh`, `RELEASE.md` |

## Naming Conventions (observed)

- Algorithm implementations: `SDF<Alg><Role>` or `<Alg><Role>Spi`
  (e.g. `SDFSM4InternalKey`, `SM2SignatureSpi`, `RSACipherSpi`).
- JNA structs mirror C names exactly: `ECCrefPublicKey`, `RSArefPrivateKey`, `ECCCipher`.
- Variant structs use a suffix: `ECCrefPublicKey_ECDSA`, `ECCSignature_EDDSA`.
- Parameter specs: `<Alg>InternalKeyGenParameterSpec`.
- Tests: `*Test` for unit tests; `ShudunIT` for hardware integration.
- Scripts: kebab-case `.sh` with `SMOKE_*` / `PACK_*` environment variables.
- Docs: `UPPER-KEBAB.md` in `doc/`.

## Generated / Ignored Directories

- `target/` — build output, `target/lib` (runtime deps), signed JAR.
- `HSM/**/*.so|dll|dylib|a|ini|pdf` — vendor material, never committed (except
  `*.ini.example`, `sdf-profile.json`, `README.md`).
- `*.log`, `*.pcap`, `keystore.jks`, `*.jks`, `liuzx-jce.properties`, `.idea/`,
  `.claude/settings.local.json` — gitignored.
