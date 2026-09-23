---
phase: 1
slug: api-fa-ade
status: draft
nyquist_compliant: true
wave_0_complete: false
created: 2026-09-23
---

# Phase 1 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | JUnit 5 (jupiter 5.8.2) |
| **Config file** | `pom.xml` (surefire 2.22.2) — Phase 4 才修正默认 skipTests；Phase 1 用 `-DskipTests=false -Dtest=...` 显式运行 |
| **Quick run command** | `mvn -q test -DskipTests=false -Dtest='org.liuzx.jce.api.**'` |
| **Full suite command** | `mvn -q verify -DskipTests=false` |
| **Estimated runtime** | ~30–90 秒（硬件无关）/ 真机验证另计 |

---

## Sampling Rate

- **After every task commit:** Run `mvn -q test -DskipTests=false -Dtest='org.liuzx.jce.api.**'`
- **After every plan wave:** Run `mvn -q verify -DskipTests=false`（硬件无关部分）
- **Before `$gsd-verify-work`:** 全量套件 + 真机验收证据齐备
- **Max feedback latency:** ~90 秒

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 01-01-01 | 01 | 1 | API-01 | T-1-01 / — | 公开类型只用 JDK 类型，无 JNA 泄漏 | reflection | `mvn -q test -DskipTests=false -Dtest=ApiSurfaceAuditTest` | ❌ W0 | ⬜ pending |
| 01-01-02 | 01 | 1 | API-02, API-03 | — | 错误分类不泄漏路径/PIN/KeyId | unit | `-Dtest=SdfErrorCategoryMappingTest` | ❌ W0 | ⬜ pending |
| 01-01-03 | 01 | 1 | API-04, API-05 | T-1-04 / — | 脱敏信息不含序列号/路径/库名 | unit | `-Dtest=SdfDeviceInfoSafeStringTest` | ❌ W0 | ⬜ pending |
| 01-02-01 | 02 | 2 | API-06, API-07 | — | 工厂不要求 JNA 句柄 | reflection | `-Dtest=ApiSurfaceAuditTest` | ❌ W0 | ⬜ pending |
| 01-02-02 | 02 | 2 | API-08, API-11 | T-1-08 / — | PIN 不缓存，公钥为 X.509 | unit | `-Dtest=SdfDeviceExportKeyTest` | ❌ W0 | ⬜ pending |
| 01-03-01 | 03 | 3 | API-09, API-10 | T-1-09 / — | digest 不再哈希；RSA 保留前导零 | unit | `-Dtest=SdfDeviceSignatureSemanticsTest` | ❌ W0 | ⬜ pending |
| 01-03-02 | 03 | 3 | API-05, API-11 | — | UserID 单一来源；PIN finally 释放 | unit | `-Dtest=SdfCapabilitiesTest` | ❌ W0 | ⬜ pending |
| 01-04-01 | 04 | 4 | API-01 | T-1-01 / — | 反射审计最终通过 | reflection | `mvn -q verify -DskipTests=false` | ❌ W0 | ⬜ pending |
| 01-04-02 | 04 | 4 | API-12 | — | 四类错误码真机可触发 | hardware | `scripts/sdf-smoke.sh`（扩展） | ❌ W0 | ⬜ pending |
| 01-04-03 | 04 | 4 | API-13 | — | 独立验签器验证通过并发布 | hardware + build | `mvn -q verify` + SVS `DeviceDependencyContractTest` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `src/test/java/org/liuzx/jce/api/ApiSurfaceAuditTest.java` — 反射审计骨架（API-01）
- [ ] `src/test/java/org/liuzx/jce/api/SdfErrorCategoryMappingTest.java` — 错误码→分类映射（API-02）
- [ ] `src/test/java/org/liuzx/jce/api/SdfDeviceInfoSafeStringTest.java` — 脱敏断言（API-04）
- [ ] `src/test/java/org/liuzx/jce/api/SdfDeviceSignatureSemanticsTest.java` — digest/RSA 语义（API-09/10）
- [ ] JUnit 5 已在 `pom.xml`，无需安装；Phase 1 用 `-Dtest=` 显式调用

*Wave 0 就是 Plan 01-01，其任务本身就创建这些测试骨架。*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| 真机签名可被独立软件验签器验证 | API-10, API-13 | 需要真实密码设备与外部验签工具 | 连接设备，设置 `SMOKE_SM2_SIGN_INDEX`/`SMOKE_RSA_SIGN_INDEX`，运行 `scripts/sdf-smoke.sh`，用 `openssl`/`gmssl` 对导出公钥验签 |
| SVS `DeviceDependencyContractTest` 解除 BLOCKED | API-13 | 验收方在 `liuzx-svs` 仓库 | 在 `liuzx-svs` 执行其契约测试，确认不再报 `BLOCKED on liuzx-sdf-jce 1.1.5` |
| 四类错误码真机触发 | API-12 | 需要构造设备侧错误条件 | 用不存在的索引（`KEY_NOT_FOUND`）、错误 PIN（`AUTHORIZATION_FAILED`）、未连接设备（`DEVICE_UNAVAILABLE`）、不支持算法（`ALGORITHM_UNSUPPORTED`） |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 90s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
