---
phase: 01-api-fa-ade
plan: 02
subsystem: api
tags: [jce, facade, factory, x509, pin-lifecycle]

requires:
  - phase: 01-api-fa-ade
    provides: "SdfErrorCategory/SdfException/SdfDeviceInfo/SdfCapabilities 类型基础"
provides:
  - "SdfDevice 门面接口"
  - "SdfDevices.open()/open(Properties) 入口工厂"
  - "SdfDeviceImpl 包私有实现（deviceInfo/capabilities/exportSignPublicKey/close）"
  - "按需 PIN 访问权辅助方法 withPrivateKeyAccess"
affects: [01-03, 01-04]

tech-stack:
  added: []
  patterns:
    - "门面通过 JCE KeyPairGenerator 复用已测内部密钥加载路径"
    - "门面边界把 LinkageError/配置静态初始化失败统一归一为 SdfException"
    - "PIN 只作为局部变量 + finally 释放，无字段缓存"

key-files:
  created:
    - src/main/java/org/liuzx/jce/api/SdfDevice.java
    - src/main/java/org/liuzx/jce/api/SdfDevices.java
    - src/main/java/org/liuzx/jce/api/SdfDeviceImpl.java
    - src/test/java/org/liuzx/jce/api/SdfDeviceLifecycleTest.java
    - src/test/java/org/liuzx/jce/api/SdfDeviceExportKeyTest.java
  modified:
    - src/main/java/org/liuzx/jce/provider/asymmetric/sm2/SM2SignatureSpi.java

key-decisions:
  - "exportSignPublicKey 经 JCE KeyPairGenerator + *InternalKeyGenParameterSpec 实现，而非直接调用包私有的 RSAKeyConverter（api 包无法访问）"
  - "SM2 DEFAULT_USER_ID_STRING 常量在 01-02 提前提取（capabilities() 需要单一来源），01-03 只需补测试"
  - "SdfDevices.open() 捕获 LinkageError 并归一为 NATIVE_DEPENDENCY_UNAVAILABLE，避免 ExceptionInInitializerError 逃逸到调用方"

patterns-established:
  - "门面实现类包私有，公开边界只暴露 api 包类型"
  - "厂商/原生异常沿 cause 链提取 SDFException 错误码再映射"

requirements-completed: [API-06, API-07, API-08, API-11]

duration: 30min
completed: 2026-09-23
---

# Phase 1 Plan 02: 门面接口与公钥导出 Summary

**交付不泄漏 JNA 的 SdfDevice 门面、SdfDevices 入口工厂与包私有实现，内部签名公钥可导出为 X.509，PIN 按需申请并在 finally 释放。**

## Performance

- **Duration:** ~30 min
- **Completed:** 2026-09-23
- **Tasks:** 3
- **Files modified:** 5 created, 1 modified

## Accomplishments

- `SdfDevice` 接口 + `SdfDevices.open()`/`open(Properties)` 工厂，调用方无需 JNA 句柄
- `SdfDeviceImpl` 实现 `deviceInfo()`（脱敏）、`capabilities()`（含生效 UserID）、`exportSignPublicKey()`、`close()`（幂等）
- `withPrivateKeyAccess` 按需申请/`finally` 释放私钥访问权，PIN 无字段缓存
- 工厂校验白名单与凭据键，拒绝 `pin`/`password`/`passwd`

## Task Commits

1. **Task 1+3: 门面、工厂、生命周期与 PIN 辅助** - `1607690` (feat)
2. **Task 2: X.509 公钥导出验证** - `e090054` (feat)

## Files Created/Modified

- `src/main/java/org/liuzx/jce/api/SdfDevice.java` — 门面接口与 PIN/生命周期契约
- `src/main/java/org/liuzx/jce/api/SdfDevices.java` — 入口工厂与属性白名单
- `src/main/java/org/liuzx/jce/api/SdfDeviceImpl.java` — 包私有实现
- `src/test/java/org/liuzx/jce/api/SdfDeviceLifecycleTest.java` — 状态机与工厂校验
- `src/test/java/org/liuzx/jce/api/SdfDeviceExportKeyTest.java` — DER 前缀验收（无设备时跳过）
- `src/main/java/org/liuzx/jce/provider/asymmetric/sm2/SM2SignatureSpi.java` — 新增 `DEFAULT_USER_ID_STRING`

## Decisions Made

- **导出走 JCE 而非直接调用 `RSAKeyConverter`**：`RSAKeyConverter` 是 `org.liuzx.jce.provider.asymmetric.rsa` 的包私有类，`api` 包不可访问。改用 `KeyPairGenerator.getInstance("SM2"/"RSA", "LiuZX")` + `*InternalKeyGenParameterSpec`，内部即复用 `RSAKeyConverter` 的布局转换，无需重写。
- **SM2 UserID 常量提前到 01-02**：`capabilities()` 必须返回单一来源的生效 UserID，故 `SM2SignatureSpi.DEFAULT_USER_ID_STRING` 在 01-02 引入（原计划 01-03 Task 1）。
- **`SdfDevices.open()` 归一 LinkageError**：macOS/无库环境下 `SDFConfig` 静态初始化会抛 `IllegalArgumentException` → `ExceptionInInitializerError`，原本会逃逸；现在统一转成 `SdfException(NATIVE_DEPENDENCY_UNAVAILABLE/DEVICE_UNAVAILABLE)`。

## Deviations from Plan

**[Rule 1 - Bug] `open()` 泄漏 ExceptionInInitializerError**
- **Found during:** Task 1 verification
- **Issue:** `SDFConfig` 静态初始化校验内置 profile 路径失败，`ExceptionInInitializerError` 在 `warmUp()` 之外抛出
- **Fix:** 把 `SDFSessionManager.getInstance()` + `warmUp()` 一起纳入 try，捕获 `LinkageError`/`RuntimeException` 并归一为 `SdfException`
- **Verification:** `SdfDeviceLifecycleTest.opensRealDeviceWhenAvailable` 由 ERROR 变为 SKIP
- **Commit:** `1607690`

**[Rule 3 - Missing critical] sign* 方法暂为占位**
- **Found during:** Task 1
- **Issue:** 接口要求声明三个签名方法，实现留给 01-03
- **Fix:** 暂时抛 `UnsupportedOperationException("implemented in plan 01-03")`，已由生命周期测试覆盖关闭状态
- **Impact:** 不违反公开契约；01-03 替换实现

**Total deviations:** 2（1 Rule 1 auto-fixed，1 Rule 3 planned seam）。**Impact:** 无功能面回归。

## Issues Encountered

None remaining.

## User Setup Required

None（真机导出验收需 `SMOKE_SM2_SIGN_INDEX`）。

## Next Phase Readiness

Plan 01-03 可直接在 `SdfDeviceImpl` 上实现 `signSm2`/`signSm2Digest`/`signRsa`。

## Self-Check: PASSED

- [x] `mvn -o test -DskipTests=false -Dtest='org.liuzx.jce.api.*Test'` → 20 tests, 0 failures, 2 skipped（硬件相关）
- [x] `SdfDevices` 公开方法仅 `open()` / `open(Properties)`
- [x] `SdfDeviceImpl` 无 `char[]` 字段
- [x] 工厂拒绝凭据键与未知键
