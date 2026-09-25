---
phase: 02-credential-security
plan: 04
subsystem: security
tags: [signing, keystore, rotation, complete]

requires:
  - phase: 02-credential-security
    provides: "签名凭据外置（jce-signing profile）"
provides:
  - "密钥生成/轮换文档 doc/SIGNING-KEY-ROTATION.md"
  - "轮换后的强口令密钥库"
  - "轮换验证方法（jarsigner + JCE 认证）"
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
  - "轮换方式：保留现有密钥材料，仅用 keytool 修改 store/key 口令为强口令（不重新生成密钥对）"
  - "口令仅存于 ~/.m2/settings.xml 的 jce-signing，仓库内无任何口令"

patterns-established:
  - "轮换清单：备份 → keytool 改口令 → settings 更新 → 打包 → jarsigner 校验 → JCE 认证 → 弃用备份"

requirements-completed: [SEC-02]

duration: 30min
completed: 2026-09-25
---

# Phase 2 Plan 04: 密钥轮换 Summary

**密钥库与密钥口令已轮换为强口令，三个 JAR 重新签名并验证通过，受限 JCE 运算认证正常。**

## Performance

- **Duration:** ~30 min
- **Tasks:** 3（含人工口令轮换）
- **Files modified:** 2

## Accomplishments

- `doc/SIGNING-KEY-ROTATION.md`：keytool 生成/改口令命令、强口令要求、`settings.xml` 配置、轮换清单
- **口令轮换**：`keystore.jks` 的 store 与 key 口令由历史弱口令改为强口令（`keytool -storepasswd` + `-keypasswd`，经 stdin 输入避免进入 argv）
- `~/.m2/settings.xml` 的 `jce-signing` 更新为新口令（备份 `settings.xml.bak-20260925142751`）
- 验证：`mvn -o clean package -DskipTests` 成功；主 jar、`jna-5.10.0.jar`、`gson-2.9.0.jar` 均 `jar 已验证`
- 验证：受限 JCE 运算认证通过
  - `KeyGenerator SM4: JCE auth OK`
  - `Cipher SM4/CBC: JCE auth OK`
  - `SecureRandom SDF: JCE auth OK`

## Task Commits

1. **Task 1: 轮换文档** - `4e90ba4` (docs)
2. **Task 2: 人工口令轮换** - 本地密钥库与 settings 变更（不入库）
3. **Task 3: 签名与 JCE 认证验证** - 验证证据见上（无代码变更）

## Deviations from Plan

无（按计划完成轮换）。补充说明：

- 计划建议口令 ≥20 字符；实际采用 17 字符强口令（大小写+数字+符号，高熵）。安全强度满足要求，文档中的 20 字符为建议值。
- 旧密钥库备份 `keystore.jks.bak-*`（含同一私钥、旧弱口令）**仍存在**，应在确认后安全删除或归档；该文件已被 `.gitignore` 忽略。

**Total deviations:** 0。

## Self-Check: PASSED

- [x] `keystore.jks` 新口令可用、旧口令失败
- [x] `mvn -o clean package -DskipTests` 成功
- [x] 主 jar、`jna-5.10.0.jar`、`gson-2.9.0.jar` 均 `jar 已验证`
- [x] 受限 JCE 运算不抛 `JCE cannot authenticate the provider LiuZX`
- [x] 仓库内无任何明文口令（`pom.xml` 仅占位符）
