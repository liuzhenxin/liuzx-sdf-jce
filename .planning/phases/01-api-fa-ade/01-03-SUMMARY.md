---
phase: 01-api-fa-ade
plan: 03
subsystem: api
tags: [jce, sm2, rsa, signature, digest, pin]

requires:
  - phase: 01-api-fa-ade
    provides: "SdfDevice 接口与 SdfDeviceImpl 骨架、withPrivateKeyAccess"
provides:
  - "signSm2 返回 64 字节 r||s"
  - "signSm2Digest 直接把入参作为 e，不二次哈希"
  - "signRsa 输出模长字节并保留前导零"
  - "SM2 默认 UserID 单一来源"
affects: [01-04]

tech-stack:
  added: []
  patterns:
    - "SM2 签名经 JCE SPI 产出 DER 后还原为 r||s"
    - "摘要签名绕过 JCE SPI，直连 SDF_InternalSign_ECC"
    - "长度守卫包私有静态方法，可在无硬件下测试"

key-files:
  created:
    - src/test/java/org/liuzx/jce/api/SdfCapabilitiesTest.java
    - src/test/java/org/liuzx/jce/api/SdfDeviceSignatureSemanticsTest.java
  modified:
    - src/main/java/org/liuzx/jce/api/SdfDeviceImpl.java

key-decisions:
  - "signSm2 通过 SM2PrivateKey(keyIndex, pin, eccPublicKey) + SM3withSM2 SPI 复用已测链路，再把 DER 还原为 r||s"
  - "signSm2Digest 不经 JCE SPI（SPI 会再哈希），直接调用 SDF_InternalSign_ECC"
  - "signRsa 通过 SDFRSAPrivateKey(keyIndex, pin, RSAPublicKey) + SHA256withRSA，复用 RSASignatureSpi 的 PKCS#1 编码"

patterns-established:
  - "门面签名方法统一在 finally/withPrivateKeyAccess 中释放私钥访问权"
  - "产物长度不变量：SM2 64 字节、RSA 模长字节"

requirements-completed: [API-05, API-09, API-10, API-11]

duration: 25min
completed: 2026-09-23
---

# Phase 1 Plan 03: 签名语义 Summary

**SM2 原文签名与摘要签名统一返回 64 字节 r||s，摘要签名不再二次哈希；RSA 签名输出模长字节并保留前导零。**

## Performance

- **Duration:** ~25 min
- **Completed:** 2026-09-23
- **Tasks:** 3
- **Files modified:** 1 modified, 2 created

## Accomplishments

- `signSm2`：导出内部公钥 → `SM2PrivateKey(keyIndex, pin, pub)` → `SM3withSM2` SPI → DER 还原为 `r[32]‖s[32]`
- `signSm2Digest`：长度必须为 32，直接以入参为 `e` 调 `SDF_InternalSign_ECC`，无任何哈希调用
- `signRsa`：`SHA256withRSA` + `SDFRSAPrivateKey`，校验输出长度等于模长字节数
- `validateDigestLength` 包私有守卫 + `SdfCapabilities` 不可变性测试

## Task Commits

1. **Task 1: 能力指纹与 UserID 单一来源** - `1a553dc` (feat)
2. **Task 2+3: 三个签名方法与长度守卫** - `d2b71e8` (feat)

## Files Created/Modified

- `src/main/java/org/liuzx/jce/api/SdfDeviceImpl.java` — signSm2 / signSm2Digest / signRsa 实现
- `src/test/java/org/liuzx/jce/api/SdfCapabilitiesTest.java` — UserID 与不可变集合
- `src/test/java/org/liuzx/jce/api/SdfDeviceSignatureSemanticsTest.java` — 摘要长度守卫 + 真机产物形态

## Decisions Made

- **摘要签名绕过 JCE SPI**：`SM2SignatureSpi` 会对输入做 `SDF_HashInit/Update/Final`，与规格要求的“直接把入参作为 `e`”冲突，故 `signSm2Digest` 直连 `SDF_InternalSign_ECC`。
- **SM2 原文签名复用 SPI**：SPI 已实现设备端 Z/e 计算与 UserID 处理，门面只需把 DER 还原为 `r||s`。
- **RSA 复用 `RSASignatureSpi`**：避免在门面重写 EMSA-PKCS1 v1.5 编码，天然保留前导零与模长输出。

## Deviations from Plan

**[Rule 3 - Plan reorder] 01-03 Task 1 的 UserID 常量提取已在 01-02 完成**
- `SM2SignatureSpi.DEFAULT_USER_ID_STRING` 在 01-02 引入（`capabilities()` 需要单一来源），本计划只补 `SdfCapabilitiesTest` 验证。

**[Rule 1 - Bug] 类名拼写**
- **Found during:** Task 2
- **Issue:** 误写 `ECCrePublicKey`，实际类型为 `ECCrefPublicKey`
- **Fix:** 全量替换并重新编译
- **Verification:** `mvn -o test` BUILD SUCCESS

**Total deviations:** 2（1 reorder, 1 Rule 1 auto-fixed）。**Impact:** 无。

## Issues Encountered

None remaining.

## User Setup Required

真机签名验收需设备与 `SMOKE_SM2_SIGN_INDEX` / `SMOKE_RSA_SIGN_INDEX`。

## Next Phase Readiness

Plan 01-04 可在门面之上做递归反射审计硬门禁、扩展冒烟与真机验收。

## Self-Check: PASSED

- [x] `mvn -o test -DskipTests=false -Dtest='org.liuzx.jce.api.*Test'` → 25 tests, 0 failures, 3 skipped（硬件）
- [x] `SdfDeviceImpl` 中无 `SDF_Hash*` / `MessageDigest`
- [x] `validateDigestLength(null)` / `new byte[31]` / `new byte[33]` 均抛 `OPERATION_FAILED`
- [x] `SdfDeviceImpl` 无 `char[]` 字段
