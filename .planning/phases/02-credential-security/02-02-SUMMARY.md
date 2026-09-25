---
phase: 02-credential-security
plan: 02
subsystem: security
tags: [pin, argv, smoke, stress, env]

requires: []
provides:
  - "冒烟 PIN 经 LIUZX_SMOKE_PIN 环境变量传递"
  - "压力测试 PIN 经 LIUZX_STRESS_PIN 或交互输入"
  - "scripts/verify-no-secret-in-argv.sh 回归防护"
affects: [02-03]

tech-stack:
  added: []
  patterns:
    - "敏感值经环境变量传递，禁止进入 java argv"

key-files:
  created:
    - scripts/verify-no-secret-in-argv.sh
  modified:
    - src/main/java/org/liuzx/jce/demo/SdfSmokeTest.java
    - src/main/java/org/liuzx/jce/demo/Main.java
    - scripts/sdf-smoke.sh
    - scripts/pack-smoke.sh
    - README.md

key-decisions:
  - "旧系统属性 liuzx.sdf.smoke.pin/badPin 不再被读取，仅打印弃用告警"
  - "pack-smoke 生成的 run-smoke.sh 同样改为 export LIUZX_SMOKE_PIN"

patterns-established:
  - "argv 泄漏回归：scripts/verify-no-secret-in-argv.sh"

requirements-completed: [SEC-03]

duration: 25min
completed: 2026-09-25
---

# Phase 2 Plan 02: PIN 入口迁移 Summary

**冒烟与压力测试的 PIN 改经环境变量（`LIUZX_SMOKE_PIN` / `LIUZX_STRESS_PIN`）传递，不再出现在 `java` 命令行中，并有自动回归脚本守护。**

## Performance

- **Duration:** ~25 min
- **Tasks:** 3
- **Files modified:** 6

## Accomplishments

- `SdfSmokeTest` 读取 `LIUZX_SMOKE_PIN` / `LIUZX_SMOKE_BAD_PIN`，忽略旧 `-D` 属性并告警
- `sdf-smoke.sh` 与 `pack-smoke.sh` 生成的 `run-smoke.sh` 均改为 `export`
- `Main` 压力测试移除 `args[4]`，改用 `LIUZX_STRESS_PIN` 或交互输入
- `verify-no-secret-in-argv.sh`：静态 + 运行期 argv 断言，均 PASS

## Task Commits

1. **Task 1:** `8e150f0`
2. **Task 2:** `44efae9`
3. **Task 3:** `b01fb9d`

## Deviations from Plan

**[Rule 2 - Missing critical] pack-smoke 生成的 runner 仍用 -D 传 PIN**
- **Found during:** Task 2 验收 grep
- **Fix:** `scripts/pack-smoke.sh` 生成的 `run-smoke.sh` 改为 `export LIUZX_SMOKE_PIN`
- **Verification:** `grep -rn 'Dliuzx.sdf.smoke.pin=' scripts/` → NONE
- **Impact:** 避免打包产物继续以 argv 泄漏 PIN

**Total deviations:** 1（Rule 2 auto-fixed）。

## Self-Check: PASSED

- [x] `mvn -o -q compile` 成功
- [x] `bash -n` 三个脚本均通过
- [x] `./scripts/verify-no-secret-in-argv.sh` → RESULT: PASS（含运行期 argv 检查）
- [x] `grep -rn 'Dliuzx.sdf.smoke.pin=' scripts/ src/` → NONE
