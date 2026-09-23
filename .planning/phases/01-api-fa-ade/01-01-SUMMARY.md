---
phase: 01-api-fa-ade
plan: 01
subsystem: api
tags: [jce, facade, error-category, reflection-audit, java8]

requires: []
provides:
  - "org.liuzx.jce.api 稳定公开包"
  - "SdfErrorCategory / SdfErrorMapper 错误分类"
  - "SdfException 脱敏公开异常"
  - "SdfDeviceInfo / SdfCapabilities / AlgorithmFamily 不可变值对象"
  - "ApiSurfaceAuditTest 反射审计骨架"
affects: [01-02, 01-03, 01-04, phase-04-testing]

tech-stack:
  added: []
  patterns:
    - "Java 8 兼容的不可变值对象（替代 record）"
    - "反射审计公开 API 边界（递归 + visited 去环）"
    - "厂商错误码 → 稳定分类映射"

key-files:
  created:
    - src/main/java/org/liuzx/jce/api/SdfErrorCategory.java
    - src/main/java/org/liuzx/jce/api/SdfErrorMapper.java
    - src/main/java/org/liuzx/jce/api/SdfException.java
    - src/main/java/org/liuzx/jce/api/SdfDeviceInfo.java
    - src/main/java/org/liuzx/jce/api/SdfCapabilities.java
    - src/main/java/org/liuzx/jce/api/AlgorithmFamily.java
    - src/test/java/org/liuzx/jce/api/ApiSurfaceAuditTest.java
    - src/test/java/org/liuzx/jce/api/SdfErrorCategoryMappingTest.java
    - src/test/java/org/liuzx/jce/api/SdfDeviceInfoSafeStringTest.java
  modified: []

key-decisions:
  - "规格要求的 record 与 pom 的 Java 1.8 源码级别冲突，采用 Java 8 兼容的不可变 final 类（Rule 4 决策，用户批准方案 B）"
  - "错误映射放在包私有 SdfErrorMapper，避免污染公开门面"
  - "反射审计以生产 classes 目录（code source）为基准，而非 test-classes 资源路径"

patterns-established:
  - "公开值对象：private final 字段 + 无 get 前缀访问器 + requireNonNull 校验"
  - "公开边界审计：递归解析数组/泛型/通配符/类型变量上界，并用 IdentityHashMap 去环"

requirements-completed: [API-01, API-02, API-03, API-04, API-05]

duration: 35min
completed: 2026-09-23
---

# Phase 1 Plan 01: 公开类型骨架 Summary

**建立 `org.liuzx.jce.api` 稳定公开包：九类错误分类、脱敏公开异常、两个不可变设备值对象，以及可递归校验公开边界的反射审计测试。**

## Performance

- **Duration:** ~35 min
- **Completed:** 2026-09-23
- **Tasks:** 3
- **Files modified:** 9 created

## Accomplishments

- `SdfErrorCategory` 九类稳定分类与 `SdfErrorMapper`（仅 `DEVICE_UNAVAILABLE`/`DEVICE_BUSY` 可重试）
- `SdfException` 只暴露分类、操作名与十六进制 `internalDetail()`，不泄漏路径/PIN/索引
- `SdfDeviceInfo`（无序列号访问器）与 `SdfCapabilities`（不可变集合）值对象
- `ApiSurfaceAuditTest` 递归审计公开签名，确认无 JNA / `Path` / `File` / `Pointer` / `PrivateKey`

## Task Commits

1. **Task 1: 错误分类枚举与映射器** - `2465e2d` (feat)
2. **Task 2: 脱敏公开异常** - `14ad44f` (feat)
3. **Task 3: 设备值对象与反射审计** - `dc653c0` (feat)

## Files Created/Modified

- `src/main/java/org/liuzx/jce/api/SdfErrorCategory.java` — 九类稳定分类
- `src/main/java/org/liuzx/jce/api/SdfErrorMapper.java` — 包私有厂商码映射器
- `src/main/java/org/liuzx/jce/api/SdfException.java` — 脱敏公开异常
- `src/main/java/org/liuzx/jce/api/SdfDeviceInfo.java` — 脱敏设备信息值对象
- `src/main/java/org/liuzx/jce/api/SdfCapabilities.java` — 能力指纹值对象
- `src/main/java/org/liuzx/jce/api/AlgorithmFamily.java` — 算法族枚举
- `src/test/java/org/liuzx/jce/api/ApiSurfaceAuditTest.java` — 公开边界反射审计
- `src/test/java/org/liuzx/jce/api/SdfErrorCategoryMappingTest.java` — 映射表测试
- `src/test/java/org/liuzx/jce/api/SdfDeviceInfoSafeStringTest.java` — 脱敏断言

## Decisions Made

- **Rule 4 决策（用户批准方案 B）**：SVS 规格要求 `record`，但 `pom.xml` 为 Java 1.8（`javac -source 8` 不支持 record，且 `Set.copyOf` 需 Java 10+）。改为 Java 8 兼容的不可变 `final class`，保留 record 等价的访问器命名（`issuerName()`、`families()` 等）。功能契约不变。
- 反射审计基准改为生产 classes 目录，因为 `ClassLoader.getResource("org/liuzx/jce/api")` 在 surefire 下解析到 `target/test-classes`（测试类非 public，导致审计对象为空）。
- 递归类型检查加入 `IdentityHashMap` visited 集合，修复自引用泛型上界导致的 `StackOverflowError`。

## Deviations from Plan

**[Rule 4 - Architectural] record 不可用于 Java 8**
- **Found during:** Task 3
- **Issue:** 规格 §4.3/4.4 要求 `record`，与 `maven.compiler.source=1.8` 冲突
- **Fix:** 改为不可变 final 类 + 同名访问器 + `Collections.unmodifiableSet`
- **Verification:** `mvn -o test -DskipTests=false -Dtest='org.liuzx.jce.api.*Test'` → 14 tests, 0 failures
- **Impact:** 公开方法契约不变；若 SVS 依赖 `Class.isRecord()` 需另行反馈

**[Rule 1 - Bug] 反射审计在 surefire 下扫描到空集合**
- **Found during:** Task 3 verification
- **Fix:** 以生产 code source 为基准解析包目录
- **Verification:** ApiSurfaceAuditTest 通过并报告 ≥5 个公开类型

**[Rule 1 - Bug] 自引用泛型上界导致 StackOverflowError**
- **Fix:** 递归检查增加 visited 去环
- **Verification:** ApiSurfaceAuditTest 通过

**Total deviations:** 3 (1 Rule 4 architectural, 2 Rule 1 auto-fixed). **Impact:** 无功能面影响。

## Issues Encountered

None remaining.

## User Setup Required

None.

## Next Phase Readiness

Plan 01-02（门面接口/工厂/公钥导出/PIN 生命周期）已具备全部类型基础。

## Self-Check: PASSED

- [x] `mvn -o test -DskipTests=false -Dtest='org.liuzx.jce.api.*Test'` → 14 tests, 0 failures
- [x] 公开类型无 JNA / `Path` / `File` / `Pointer` / `PrivateKey`
- [x] `SdfDeviceInfo` 无序列号访问器
- [x] 9 个公开包文件 + 3 个测试已提交
