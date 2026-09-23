---
last_mapped_commit: 9a02e72e8195e67b54624f6a5d7c701815a9c67b
mapped: 2026-09-23
---

# Technology Stack — liuzx-sdf-jce

## Overview

`liuzx-sdf-jce` is a **Java JCE (Java Cryptography Extension) Provider** that exposes
GM/T 0018-2012 SDF hardware cryptographic devices through the standard `java.security`
API. It is a single-module Maven library (no Spring, no app server) intended to be
published to Maven Central and consumed inside the PKI platform (KMC / CA / NAS).

- **GroupId / ArtifactId**: `org.liuzx:liuzx-sdf-jce`
- **Version**: `1.1.5-SNAPSHOT` (`liuzx-sdf-jce/pom.xml:9`); last released tag `v1.1.4`
- **Git**: repo `github.com/liuzhenxin/liuzx-sdf-jce`, branch `main`
- **HEAD**: `9a02e72` — `chore(release): 回到 1.1.5-SNAPSHOT`

## Language & Runtime

| Item | Value | Source |
|---|---|---|
| Language | Java | `src/main/java` |
| Source/target level | **1.8** (`maven.compiler.source/target=1.8`) | `pom.xml:49-50` |
| Build JDK observed on dev host | JDK 25 (LTS) | `java -version` |
| Build tool | Apache Maven 3.9.11 | `pom.xml`, `.mvn/` |
| Encoding | UTF-8 | `pom.xml:51` |
| Packaging | JAR (+ `target/lib` runtime deps) | `pom.xml` |

Java 1.8 source level is deliberate for downstream compatibility, but the build runs on
modern JDKs. The `release` profile pins `<source>8</source>` for javadoc because JDK 25
would otherwise reject `source/target 1.8` (`pom.xml`, `release` profile).

## Core Dependencies

| Dependency | Version | Scope | Purpose |
|---|---|---|---|
| `net.java.dev.jna:jna` | 5.10.0 | runtime | Native FFI to the vendor `libsdf`/`libsdhsmcrypto`/`libswsds` C library |
| `com.google.code.gson:gson` | 2.9.0 | runtime | Parse `sdf-config.json` vendor/profile configuration |
| `org.junit.jupiter:junit-jupiter-api` | 5.8.2 | test | JUnit 5 test API |
| `org.junit.jupiter:junit-jupiter-engine` | 5.8.2 | test | JUnit 5 engine |

There is **no third-party logging dependency** — the project ships its own logger
(`src/main/java/org/liuzx/jce/provider/log/LiuzxProviderLogger.java`).

## Build Phases (`mvn clean package`)

`pom.xml` wires these plugins into the `package` phase (order matters):

1. `maven-dependency-plugin:3.3.0` — `copy-dependencies` to `target/lib` (runtime scope).
2. `maven-jar-plugin:3.2.2` — manifest with `mainClass=org.liuzx.jce.demo.Main`,
   **`addClasspath=false`** (intentional; see comment in `pom.xml`). JCE at runtime only
   validates the provider JAR itself, so JNA/Gson resolve as normal Maven deps.
3. `maven-jarsigner-plugin:3.0.0` — signs the main JAR with `keystore.jks`
   (alias `dayou`, storepass/keypass `123456`, TSA `http://timestamp.sectigo.com`).
4. `maven-antrun-plugin:3.1.0` — signs `target/lib/jna-5.10.0.jar` and
   `target/lib/gson-2.9.0.jar` with the same keystore. **JCE `JarVerifier` walks
   the manifest Class-Path and refuses unsigned dependency JARs**, causing
   `JCE cannot authenticate the provider LiuZX`.
   > Version change hazard: these filenames are hardcoded; bumping JNA/Gson requires
   > updating `pom.xml` accordingly.
5. `maven-surefire-plugin:2.22.2` — `skipTests` bound to `${skipTests}` property,
   **default `true`** (`pom.xml:53`).

## Maven Profiles

| Profile | Purpose | Key config |
|---|---|---|
| `shudun-it` | Enable real-hardware integration tests | `skipTests=false`, includes `**/*ShudunIT.java` |
| `release` | Publish to Maven Central | source + javadoc JARs, GPG signing, `central-publishing-maven-plugin:0.11.0` |

Release command (from `RELEASE.md`): `mvn clean deploy -Prelease,gpg-signing -DskipTests=true`.

## Configuration Surface

### Bundled profile — `src/main/resources/sdf-config.json`

Vendor → OS → arch → library spec. Values may be a plain path string or an object with
`path`, optional `sha256`, and `rsaKeyLayout` (`standard` | `packed`).

- Vendors declared: `Dysx` (default), `Shudun`.
- `Shudun` uses `classpath:native/shudun/...` and ships native libs inside the JAR
  (linux-x86_64, linux-aarch64, windows-x86_64) with SHA-256 pinning.

### System properties (read in `SDFConfig.java`)

| Property | Effect |
|---|---|
| `liuzx.sdf.library.path` | Explicit absolute native library path (highest priority) |
| `liuzx.sdf.profile.path` | External SDF profile JSON (absolute, readable) |
| `liuzx.sdf.vendor` | Override `defaultVendor` |
| `liuzx.sdf.library.fallback-enabled` | Opt-in short-name (`sdcrypto4j`) fallback (default false) |
| `liuzx.sdf.vendor-config.path` | Config **file** (DYSX `.ini`) or **directory** (Shudun/SanSec) for open extensions |
| `liuzx.sdf.rsa-key-layout` | `standard` / `packed` override |
| `liuzx.sdf.session.pool-size` | Session pool size (default 16) |
| `liuzx.sdf.session.borrow-timeout-ms` | Session borrow timeout (default 5000) |
| `liuzx.sdf.config.path` | **Deprecated** alias of `vendor-config.path` |

Resolution priority for the library: `liuzx.sdf.library.path` → external profile
(`liuzx.sdf.profile.path`) → bundled profile.

### Logging — `src/main/resources/liuzx-jce.properties`

```properties
log.enabled=false   # bundled default (README documents true)
log.level=INFO      # DEBUG|INFO|WARN|ERROR
log.file=liuzx-jce.log   # %d{yyyy-MM-dd} rotation injected automatically
```

`LiuzxProviderLogger` reads `/liuzx-jce.properties` in a static block, uses a
`LinkedBlockingQueue(1024)` + dedicated writer thread, and rolls files by date.

## Native Artifacts

| Location | Content |
|---|---|
| `src/main/resources/native/shudun/linux-x86_64/libsdhsmcrypto.so` | Bundled Shudun lib |
| `src/main/resources/native/shudun/linux-aarch64/libsdhsmcrypto.so` | Bundled Shudun lib (added 1.1.4) |
| `src/main/resources/native/shudun/windows-x86_64/sdhsmsdf_x64.dll` | Bundled Shudun lib |
| `HSM/DYSX/2.0/.../libsdf.so` | On-site vendor material (gitignored) |
| `HSM/SanSec/1.3.87/.../libswsds.so` | On-site vendor material (gitignored) |
| `HSM/SHUDUN/.../libsdhsmcrypto.so` | On-site vendor material (gitignored) |
| `src/main/libsdf.h` | Reference C header for the SDF ABI |

`classpath:` libraries are SHA-256 verified, then extracted to a permission-restricted
temp directory and reused per-JVM. See `SDFConfig.java` (`extractClasspathLibrary`).

## Version / Packaging Metadata

`pom.xml` declares Apache-2.0 license, developer `liuzhenxin`, SCM, and GitHub issue
management. `index.html` is the GitHub Pages landing page; `PROMOTION.md` / `RELEASE.md`
document the Central publication flow.
