---
phase: 02-credential-security
plan: 01
subsystem: build
tags: [maven, signing, secrets, jce, enforcer]

requires: []
provides:
  - "JCE 签名凭据属性化（${jce.storepass}/${jce.keypass}）"
  - "缺凭据时的清晰构建失败"
  - "pom 无明文口令的静态门禁"
affects: [02-04, phase-03]

tech-stack:
  added: ["maven-enforcer-plugin 3.5.0"]
  patterns:
    - "凭据经 settings.xml profile 注入（与 gpg-signing 一致）"

key-files:
  created:
    - src/test/java/org/liuzx/jce/provider/SigningCredentialConfigTest.java
  modified:
    - pom.xml
    - RELEASE.md

key-decisions:
  - "用 maven-enforcer-plugin 在 package 阶段强制要求 jce.storepass/jce.keypass，给出可诊断的失败信息"
  - "jce.keystore/jce.keystore.alias/jce.tsa 保留非敏感默认值，口令无默认值"

patterns-established:
  - "签名口令只来自 settings.xml/-D，pom 仅引用占位符"

requirements-completed: [SEC-01]

duration: 25min
completed: 2026-09-25
---

# Phase 2 Plan 01: 外部化签名凭据 Summary

**`pom.xml` 不再含任何明文 JCE 签名口令；凭据经 `settings.xml` 的 `jce-signing` profile 注入，缺凭据时由 enforcer 给出可诊断错误。**

## Performance

- **Duration:** ~25 min
- **Tasks:** 3
- **Files modified:** 3

## Accomplishments

- `maven-jarsigner-plugin` 与 `maven-antrun-plugin` 的 keystore/alias/storepass/keypass/tsa 全部属性化
- 新增 `jce-signing` profile 文档与轮换文档链接
- `SigningCredentialConfigTest` 静态断言 pom 无明文口令
- `maven-enforcer-plugin` 在 `package` 阶段报 `JCE signing credentials missing: 'jce.storepass'`

## Task Commits

1. **Task 1+2: 属性化签名凭据** - `073c76c` (feat)
2. **Task 3: 文档与静态门禁** - `56cff17` (docs)

## Deviations from Plan

**[Rule 2 - Missing critical] 增加 enforcer 校验**
- **Found during:** Task 1
- **Issue:** 计划仅要求文档说明缺凭据症状，但未提供清晰的失败信息（Maven 会把未解析占位符当口令）
- **Fix:** 新增 `maven-enforcer-plugin` 的 `requireProperty` 规则，绑定 `package` 阶段
- **Verification:** `mvn -o package -DskipTests` 输出 `JCE signing credentials missing: 'jce.storepass'`
- **Impact:** 提升可诊断性；`mvn test` 不受影响

**Total deviations:** 1（Rule 2 auto-fixed）。**Impact:** 正向。

## Self-Check: PASSED

- [x] `grep -nE 'storepass>123456<|keypass="123456"|>123456<' pom.xml` → NONE
- [x] `mvn -o test -DskipTests=false -Dtest=SigningCredentialConfigTest` → 3 tests, 0 failures
- [x] 缺凭据时 `mvn package` 报清晰错误
