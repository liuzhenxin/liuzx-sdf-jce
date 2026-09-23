---
last_mapped_commit: 9a02e72e8195e67b54624f6a5d7c701815a9c67b
mapped: 2026-09-23
---

# Architecture — liuzx-sdf-jce

## Pattern

A **layered JCE Provider** implementing the standard Java Security SPI architecture.
There is no application framework; the entire library is a `java.security.Provider`
subclass plus SPI implementations that delegate to hardware through JNA.

```
Application
   │  standard JCE API: Signature / Cipher / KeyPairGenerator / MessageDigest / Mac / SecureRandom
   ▼
JCE Provider registration         org.liuzx.jce.provider.LiuZXProvider
   │  put("Signature.SM3withSM2", "...SM2SignatureSpi")
   ▼
Provider SPI layer                provider/asymmetric/*, symmetric/*, digest/*, mac/*, random/*
   │  (converts JCE calls <-> SDF structures, handles internal vs external keys)
   ▼
Session management layer          provider/session/SDFSessionManager, SDFSession, SDFDeviceOpener
   │  (single global device handle, pooled sessions, self-healing, thread safety)
   ▼
Config layer                      provider/SDFConfig  (vendor/arch -> native library path, RSA layout)
   ▼
JNA binding layer                 jna/SDFLibrary, jna/SDFLibraryLoader, jna/structure/*
   │  (C ABI + memory structures)
   ▼
Native SDF library                libsdhsmcrypto.so / libsdf.so / libswsds.so
   ▼
Hardware cryptographic device
```

## Entry Points

| Entry point | Class | Notes |
|---|---|---|
| Provider registration | `org.liuzx.jce.provider.LiuZXProvider` | `Security.addProvider(new LiuZXProvider())` |
| Legacy provider alias | `org.liuzx.jce.provider.LegacyLiuZXProvider` | Registers name `liuzx` for backward compatibility |
| CLI demo | `org.liuzx.jce.demo.Main` | `mainClass` in the JAR manifest; launched via `run.sh`/`run.bat` |
| Smoke test | `org.liuzx.jce.demo.SdfSmokeTest` | Driven by `scripts/sdf-smoke.sh` |
| Stress tests | `demo.StressTester`, `demo.KeyPairGenStressTester`, `demo.SM4InternalKeyHardwareTest` | Performance tooling |

`LiuZXProvider` (`provider/LiuZXProvider.java`, 79 lines) registers all services in a
single `registerServices()` method. **Every supported algorithm must be registered here.**

## Service Registry (`LiuZXProvider.registerServices()`)

| Category | Registered names |
|---|---|
| SecureRandom | `SDF` |
| MessageDigest | `SM3`, `SHA-1`, `SHA-224`, `SHA-256`, `SHA-384`, `SHA-512`, `MD5` |
| SM2 | `KeyPairGenerator.SM2`, `Signature.SM3withSM2`, `Cipher.SM2`, `KeyAgreement.SM2` |
| SM4 | `KeyGenerator.SM4`, `Cipher.SM4`, `SM4/ECB|CBC|CFB|OFB/PKCS5Padding`, `SM4/CFB|OFB/NoPadding`, `Mac.SM4MAC` |
| RSA | `KeyPairGenerator.RSA`, `Signature.SHA1|SHA256|SHA512|MD5 withRSA`, `Cipher.RSA`, `RSA/ECB/PKCS1Padding`, `RSA/None/NoPadding` |
| ECDSA | `KeyPairGenerator.ECDSA`, `Signature.SHA256withECDSA` |
| EdDSA | `KeyPairGenerator.EdDSA`, `Signature.EdDSA` |
| DSA | `KeyPairGenerator.DSA`, `Signature.SHA1withDSA` |
| HMAC | `Mac.HmacSM3`, `Mac.HmacSHA1`, `Mac.HmacSHA256`, `Mac.HmacSHA512` |

## Key Abstractions

### Internal vs External keys
The central architectural distinction. "Internal" keys live in the HSM and are addressed
by index; private material never leaves the device. "External" keys are software-side
structures passed into SDF calls.

- Internal SM2: `SM2InternalKeyGenParameterSpec`, produced key pair references the index.
- Internal RSA: `RSAInternalKeyGenParameterSpec` + `SDFRSAPrivateKey` (index + password + public key).
- Internal SM4: `SDFSM4Keys.internalKey(index)` → `SDFSM4InternalKey`; `getEncoded()` never
  returns raw key bytes. A KEK index derives a session key handle via SDF.
- Key-handle resolution is factored into `symmetric/SDFInternalKeyHandleResolver.java`.

### Config resolution
`SDFConfig` is a singleton (`getInstance()`) that:
1. Detects OS (`detectOS()`) and arch (`detectArch()`).
2. Loads and **validates** the bundled profile at class-init time
   (`loadBundledConfig()` → `parseAndValidate()`).
3. Validates every configured path (`classpath:` syntax rules vs portable absolute paths).
4. Rejects unknown JSON fields, malformed SHA-256, and invalid `rsaKeyLayout`.
5. On `classpath:` specs, verifies SHA-256 then extracts to a restricted temp dir, cached
   in `EXTRACTED_LIBRARIES` (`ConcurrentHashMap`) behind `EXTRACTION_LOCK`.

### RSA ABI portability
`RsaKeyLayout` (`standard` / `packed`) is resolved per selected vendor. `RSAKeyConverter`
is the **single place** that translates between the standard fixed-size
`RSArefPublicKey(m[512]/e[512])` / `RSArefPrivateKey(m/e/d[512] + CRT[256])` structures and
vendor variable-length ("packed") layouts. Both cipher and signature paths share it.

### Session self-healing
`SDFSessionManager` treats `SDR_UNKNOWERR` / `SDR_COMMFAIL` (and Shudun `SDR_HSM_NOT_READY`)
as "session lost" (`isSessionLost(int)`). Recovery: close the global device handle, reopen,
retry once. `synchronous` device open is guarded by `deviceLock`; the session pool and
`allSessions` set are thread-safe collections.

## Data Flow Example — SM2 internal-key signature

1. App: `Signature.getInstance("SM3withSM2", "LiuZX")` → `SM2SignatureSpi`.
2. App: `initSign(privateKey)` where key came from `SM2InternalKeyGenParameterSpec(index, SIGN)`.
3. SPI borrows an `SDFSession` from the pool.
4. SPI calls `SDF_InternalSign_ECC(session, index, data, len, ecsSignature)`.
5. JNA marshals data; hardware computes; result returned as `ECCSignature`.
6. SPI converts to DER via `util/ASN1Util` and returns bytes to JCE.
7. Session returned to pool. On hardware/comm fault, `SDFException` with hex code is raised.

## Error Handling Model

- `SDFException extends ProviderException` carries `functionName` + `errorCode` and
  formats `"<FN> failed. Error Code: 0x%08X (<description>)"`.
- `SDFErrorConstants` is an interface of GM/T 0018-2012 error codes plus the Shudun
  extension `SDR_HSM_NOT_READY = 0x01000403`.
- Descriptions are bilingual (Chinese + English) in `SDFException.getErrorDescription(int)`.
- SPI code converts non-zero SDF return codes to `SDFException`; JCE wraps into
  `ProviderException` / `SignatureException` / `InvalidKeyException` as appropriate.

## Threading & Concurrency

- Provider instance is effectively stateless; per-operation state lives in SPI instances.
- `SDFSessionManager` singleton with DCL; session pool bounded.
- `allSessions` uses `Collections.synchronizedSet(new LinkedHashSet<>())`.
- Logger uses a bounded `LinkedBlockingQueue` (1024) drained by one writer thread.
- `SDFDeviceOpener.MISSING_SYMBOLS` uses `ConcurrentHashMap.newKeySet()` and
  `lastSuccessfulOperation` is `volatile`.

## Design Decisions (from code comments / README)

1. **Standard-first device open** — never special-case a vendor by name; probe capabilities.
2. **One device handle per JVM** — Shudun requires it; simplifies lifecycle.
3. **No `Class-Path` in the JAR manifest** — JCE only validates the provider JAR; consumers
   resolve JNA/Gson via Maven. Local portable runs use `-cp target/lib/*`.
4. **Signed dependencies at package time** — unavoidable consequence of JCE authentication.
5. **Hardware-first, no software fallback** — SM3/SM4/SM2 always execute in the device.
   Software helpers (`SM3Util`, `ASN1Util`) only do encoding/wrapping.
6. **Provider name `LiuZX`** with `LegacyLiuZXProvider` preserving the old `liuzx` name.
