---
phase: 01-api-fa-ade
plan: 04
subsystem: api
tags: [jce, facade, acceptance, smoke, openssl, svs-contract]

requires:
  - phase: 01-api-fa-ade
    provides: "SdfDevice/SdfDeviceImpl 门面与签名实现"
provides:
  - "递归反射审计硬门禁"
  - "冒烟覆盖门面签名与四类错误分类"
  - "两台真机（数盾/DYSX）验收证据"
  - "OpenSSL 与自研 raw-EC SM2 独立验签"
  - "SVS DeviceDependencyContractTest 7/7 通过"
affects: [phase-04-testing, liuzx-svs]

tech-stack:
  added: []
  patterns:
    - "容器化真机验收（OrbStack + eclipse-temurin + 厂商库 + 远程 HSM）"
    - "独立验签：OpenSSL 3.5 + 自研 raw-EC SM2 verifier"
    - "跨仓库契约测试：本地 install provider 后注入 SVS 测试类路径"

key-files:
  created:
    - doc/SVS-FACADE-1.1.5-ACCEPTANCE.md
    - src/test/java/org/liuzx/jce/api/SdfDeviceSignatureSemanticsTest.java
    - src/test/java/org/liuzx/jce/api/SdfCapabilitiesTest.java
  modified:
    - src/main/java/org/liuzx/jce/api/SdfErrorMapper.java
    - src/test/java/org/liuzx/jce/api/ApiSurfaceAuditTest.java
    - src/test/java/org/liuzx/jce/api/SdfErrorCategoryMappingTest.java
    - src/main/java/org/liuzx/jce/demo/SdfSmokeTest.java
    - scripts/sdf-smoke.sh
    - doc/SVS-FACADE-1.1.5-CHECKLIST.md
    - .planning/phases/01-api-fa-ade/01-RESEARCH.md

key-decisions:
  - "SDR_KEYERR(0x15) → KEY_NOT_FOUND：数盾对范围内缺失索引返回 0x15（真机探测）"
  - "AUTHORIZATION_FAILED 采用「省略 PIN」确定性触发，不猜测错误口令"
  - "SM2 验收改用 DYSX 设备（数盾 SM2 索引口令未获通过）"
  - "OpenSSL SM2 验签必须显式 distid:1234567812345678"

patterns-established:
  - "真机验收先跑冒烟，再用独立验签器验证密码学产物"
  - "错误分类必须用真机错误码验证，不能只靠单测"

requirements-completed: [API-01, API-12]

duration: 120min
completed: 2026-09-24
---

# Phase 1 Plan 04: 真机验收与契约 Summary

**在两台真实密码机上完成 façade 验收：数盾 17 PASS、DYSX 17 PASS，API-06…API-12 全部达标，独立验签通过，SVS 契约测试 7/7 通过并解除 BLOCKED。**

## Performance

- **Duration:** ~2h（含容器搭建与真机调试）
- **Completed:** 2026-09-24
- **Tasks:** 3（Task 3 为人工验收检查点，已执行）
- **Files modified:** 3 created, 7 modified

## Accomplishments

- 递归反射审计硬门禁（≥6 公开类型、无序列号访问器、无 JNA/Path/File/Pointer/PrivateKey）
- 冒烟新增 9 项门面检查：open / export / signSm2 / signSm2Digest / signRsa / 四类错误码
- **数盾 211.88.20.91**：17 PASS / 0 FAIL；`api-export-public`、`api-sign-rsa`、`api-error-*` 通过
- **DYSX 10.10.10.61**：17 PASS / 0 FAIL；`api-sign-sm2`、`api-sign-sm2-digest` 通过
- **独立验签**：OpenSSL `Verified OK`（RSA 与 SM2 原文），自研 raw-EC SM2 verifier `VALID`（摘要签名）
- **SVS `DeviceDependencyContractTest` 7/7 通过**，`BLOCKED on liuzx-sdf-jce 1.1.5` 解除

## Task Commits

1. **Task 1: 反射审计硬门禁** - `8ea3042` (test)
2. **Task 2: 冒烟覆盖门面与错误码** - `ca1dd1d` (test)
3. **真机修正与验收** - `48d9ab4` (fix), `f0f3ba2` (fix), `0188664` (docs)

## Files Created/Modified

- `doc/SVS-FACADE-1.1.5-ACCEPTANCE.md` — 两台设备 + 独立验签 + SVS 契约验收记录
- `src/main/java/org/liuzx/jce/api/SdfErrorMapper.java` — `SDR_KEYERR → KEY_NOT_FOUND`
- `src/main/java/org/liuzx/jce/demo/SdfSmokeTest.java` — 门面检查、PIN 传递、无口令鉴权触发
- `scripts/sdf-smoke.sh` — `SMOKE_CHECK_API_FACADE`、`SMOKE_BAD_PIN`、`SMOKE_EXPECT_AUTH_FAIL_WITHOUT_PIN`
- `doc/SVS-FACADE-1.1.5-CHECKLIST.md` — 勾选实施清单

## Decisions Made

- **`SDR_KEYERR(0x15) → KEY_NOT_FOUND`**：真机探测显示数盾对范围内缺失索引返回 `0x15` 而非 `SDR_KEYNOTEXIST`；`SDR_KEYTYPEERR(0x14)` 仍为 `KEY_USAGE_MISMATCH`。
- **`AUTHORIZATION_FAILED` 用「省略 PIN」触发**：受保护密钥不带 PIN 时设备返回 `0x18`，避免猜测错误口令导致锁定。
- **SM2 验收改用 DYSX**：数盾索引 1–10 的 SM2 密钥对提供的三个口令均返回 `0x18`，改由 DYSX（索引 1 + 已确认口令）完成，结论等价。
- **OpenSSL SM2 需显式 `distid`**：OpenSSL 3.5 不指定时验签失败；指定 `1234567812345678` 后 `Verified OK`，同时印证默认 UserID 正确。

## Deviations from Plan

**[Rule 1 - Bug] 冒烟门面签名未传 PIN**
- **Found during:** Task 3 真机
- **Fix:** `runFacadeChecks` 读取 `liuzx.sdf.smoke.pin` 并传入签名调用
- **Commit:** `f0f3ba2`

**[Rule 1 - Bug] 数盾缺失索引分类错误**
- **Found during:** Task 3 真机（`api-error-key-not-found` SKIP）
- **Fix:** 映射 `SDR_KEYERR → KEY_NOT_FOUND`
- **Commit:** `48d9ab4`

**[Deviation] 数盾 SM2 内部签名无法验收**
- **Issue:** 索引 1–10 对三个口令均返回 `0x18`
- **Resolution:** 改用 DYSX 设备完成 API-09；数盾 SM2 口令待确认，不影响结论

**[Deviation] API-13 的 Central 发布未执行**
- **Issue:** 发布需要 GPG 与 Central User Token（用户凭据）
- **Partial completion:** 本地 `1.1.5-SNAPSHOT` 已 `install`，SVS 契约测试基于该产物 7/7 通过
- **Remaining:** 由用户按 `RELEASE.md` 发布正式 `1.1.5`

**Total deviations:** 4（2 Rule 1 auto-fixed，2 环境/凭据受限）。**Impact:** 无功能面缺陷。

## Issues Encountered

- SVS 契约测试需要 provider 在测试类路径：以本地 install + 临时注入目标类目录方式运行，SVS 源码零改动，运行后已清理。

## User Setup Required

- Maven Central 发布凭据（GPG + Central Token）以完成 API-13。

## Next Phase Readiness

Phase 1 需求 API-01…API-12 已达标；API-13 仅剩正式发布。Phase 2（凭据与密钥安全）可直接开始。

## Self-Check: PASSED

- [x] `mvn -o test -DskipTests=false -Dtest='org.liuzx.jce.api.*Test'` → 0 failures（硬件相关用例按需跳过）
- [x] 数盾 17 PASS / 0 FAIL；DYSX 17 PASS / 0 FAIL
- [x] OpenSSL `Verified OK`（RSA、SM2 原文）；raw-EC SM2 `VALID`（摘要）
- [x] SVS `DeviceDependencyContractTest` 7/7 PASS
- [x] 四类错误分类真机可触发
