---
phase: 02-credential-security
plan: 04
subsystem: security
tags: [signing, keystore, rotation, deferred]

requires:
  - phase: 02-credential-security
    provides: "签名凭据外置（jce-signing profile）"
provides:
  - "密钥生成/轮换文档 doc/SIGNING-KEY-ROTATION.md"
  - "轮换后打包与 JCE 认证的验证方法"
affects: [phase-03, release]

tech-stack:
  added: []
  patterns:
    - "密钥库与口令分离：keystore 在仓库外/被忽略，口令在 settings.xml"

key-files:
  created:
    - doc/SIGNING-KEY-ROTATION.md
  modified:
    - RELEASE.md

key-decisions:
  - "用户决定暂缓密钥库轮换，暂时以现有口令配置 jce-signing 恢复打包；SEC-02 标记为未完成"

patterns-established:
  - "轮换清单：备份 → keytool 生成 → settings 更新 → 打包 → jarsigner 校验 → JCE 认证"

requirements-completed: []

duration: 20min
completed: 2026-09-25
---

# Phase 2 Plan 04: 密钥轮换 Summary

**轮换文档与验证方法已就绪；用户选择暂缓轮换并以现有口令恢复打包，SEC-02 未完成。**

## Performance

- **Duration:** ~20 min
- **Tasks:** 3（Task 2 人工检查点以「暂缓轮换」结束）
- **Files modified:** 2

## Accomplishments

- `doc/SIGNING-KEY-ROTATION.md`：keytool 生成命令、强口令要求、`settings.xml` 配置、8 步轮换清单、注意事项
- 在 `~/.m2/settings.xml` 添加并激活 `jce-signing` profile（当前口令为历史值）
- 验证：`mvn -o clean package -DskipTests` 成功；主 jar 与 `jna`/`gson` 依赖均 `jar 已验证`
- 验证：受限 JCE 运算认证通过
  - `KeyGenerator SM4: JCE auth OK`
  - `Cipher SM4/CBC: JCE auth OK`
  - `SecureRandom SDF: JCE auth OK`

## Task Commits

1. **Task 1: 轮换文档** - `4e90ba4` (docs)
2. **Task 2: 人工检查点** - 用户选择暂缓轮换（未提交代码）
3. **Task 3: 签名与 JCE 认证验证** - 无代码变更（验证证据见上）

## Deviations from Plan

**[Deferred] SEC-02 密钥库轮换未执行**
- **Decision:** 用户选择「只把 `jce.storepass`/`jce.keypass` 设为现有口令以恢复打包」
- **Impact:** CONCERNS C1（弱口令）**仍未消除**；`keystore.jks` 口令仍为历史弱值
- **Mitigation:** 轮换文档与验证流程已就绪，可在任意时间执行；`pom.xml` 已不含明文口令（SEC-01 已达成）
- **Follow-up:** 见 STATE 的 Blockers 与待办

**Total deviations:** 1（用户决策）。**Impact:** SEC-02 未达标，Phase 2 需求未全覆盖。

## Self-Check: PARTIAL

- [x] `doc/SIGNING-KEY-ROTATION.md` 含 keytool / jce-signing / 强口令要求，且无明文口令
- [x] `mvn -o clean package -DskipTests` 成功
- [x] 主 jar、`jna-5.10.0.jar`、`gson-2.9.0.jar` 均 `jar 已验证`
- [x] 受限 JCE 运算不抛 `JCE cannot authenticate the provider LiuZX`
- [ ] SEC-02：密钥库仍为弱口令（**未完成**）
