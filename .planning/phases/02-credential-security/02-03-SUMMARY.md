---
phase: 02-credential-security
plan: 03
subsystem: build
tags: [packaging, secrets, smoke, sanitization]

requires: []
provides:
  - "冒烟打包默认脱敏（占位模板，无真实 IP/凭据）"
  - "PACK_INCLUDE_CONF=1 显式开关 + 醒目告警"
affects: []

tech-stack:
  added: []
  patterns:
    - "便携测试包默认脱敏，真实配置需显式 opt-in"

key-files:
  modified:
    - scripts/pack-smoke.sh
    - README.md

key-decisions:
  - "用实际文件系统类型判断复制方式，而非 CONF_KIND（后者描述 vendor 打开方式）"

patterns-established:
  - "默认安全：打包产物不含真实设备配置"

requirements-completed: [SEC-04]

duration: 20min
completed: 2026-09-25
---

# Phase 2 Plan 03: 打包脱敏 Summary

**`pack-smoke.sh` 默认只生成脱敏占位模板（`<HOST>`/`<PORT>`），真实设备配置需 `PACK_INCLUDE_CONF=1` 显式启用并打印醒目告警。**

## Performance

- **Duration:** ~20 min
- **Tasks:** 3
- **Files modified:** 2

## Accomplishments

- 默认产物无真实 IP/凭据（tar 内 `conf/sdhsm.ini` 为 `<HOST>` 占位）
- `PACK_INCLUDE_CONF=1` 复制真实配置并打印 `WARNING: including real device config`
- 顺带修复既有缺陷：`CONF_KIND` 与实际目录类型不符导致 opt-in 复制落空

## Task Commits

1. **Task 1+2:** `04ddf6a`
2. **Task 3:** `074b64f`

## Deviations from Plan

**[Rule 1 - Bug] `CONF_KIND` 与真实文件类型混淆**
- **Found during:** Task 2 验证
- **Issue:** Shudun/SanSec 的 `CONF_KIND="dir"`（vendor 打开方式）但 `CONF_SOURCE` 是**文件**；按 CONF_KIND 判断复制会导致 opt-in 复制空目录、真实配置丢失
- **Fix:** 新增 `IS_CONF_DIR`（基于 `[[ -d ]]`）决定复制方式，`CONF_KIND` 仅用于 `vendor-config.path`
- **Verification:** 默认 tar → `IP = <HOST>`；opt-in tar → `IP = 10.0.0.1` 且打印告警
- **Commit:** `04ddf6a`

**Total deviations:** 1（Rule 1 auto-fixed）。

## Self-Check: PASSED

- [x] `bash -n scripts/pack-smoke.sh` 成功
- [x] 默认 tar 仅含占位模板；`tar -xzOf ... | grep '^IP'` → `<HOST>`
- [x] `PACK_INCLUDE_CONF=1` 含真实配置且打印 WARNING
- [x] `README.md` 含 `PACK_INCLUDE_CONF` 与 `LIUZX_SMOKE_PIN`
