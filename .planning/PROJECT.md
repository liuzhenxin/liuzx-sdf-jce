# liuzx-sdf-jce

## What This Is

`liuzx-sdf-jce` 是一个基于 **GM/T 0018-2012《密码设备应用接口规范》** 的 Java JCE Provider，通过 JNA 调用厂商 SDF 动态库，让 Java 应用可以用标准 `java.security` API 与真实密码设备（加密机、UKey）交互。它作为一个独立的 Maven 库发布到 Maven Central，被 PKI 平台内的 KMC、CA、NAS 等模块复用，是平台“私钥不出硬件”能力的底座。

本次项目包含两条主线：① 为 `liuzx-svs` Phase 2 解除外部阻塞，新增稳定公开包 `org.liuzx.jce.api` 作为消费方 façade（见 `doc/SVS-FACADE-1.1.5-CHECKLIST.md`）；② 对该库进行**安全与质量加固**，把代码库映射发现的技术债（`.planning/codebase/CONCERNS.md` 中的 22 项）转化为受控、可验证、可长期发布的改进路线。

## Core Value

**硬件密码运算必须正确且私钥永不离开设备，同时该 Provider 必须能被安全、可复现地构建与发布。**

当取舍发生时，优先保证：① 不明文暴露密钥材料；② 构建/发布不依赖公开的弱凭据；③ 行为对下游 KMC/CA/NAS 保持兼容。

## Requirements

### Validated

<!-- 已由现有代码实现并被下游依赖的能力（来自 .planning/codebase 映射）。 -->

- ✓ 标准 JCE Provider（名称 `LiuZX`，兼容旧名 `liuzx`），支持 SM2/SM3/SM4/RSA/ECDSA/EdDSA/DSA/HMAC 与硬件 `SecureRandom` — existing
- ✓ 内部密钥运算：SM2/SM4/RSA 私钥驻留硬件，仅通过索引使用（`SDFSM4Keys.internalKey`、`*InternalKeyGenParameterSpec`） — existing
- ✓ 多厂商适配：数盾（packed RSA 布局）、DYSX、SanSec，覆盖 Linux x86_64/aarch64 与 Windows x86_64 — existing
- ✓ 随 JAR 内置数盾原生库（`classpath:` + SHA-256 校验 + 受限权限提取） — existing
- ✓ 零第三方依赖日志系统与 demo 国际化 — existing
- ✓ JCE 认证所需的 JAR 签名（主 JAR 与 JNA/Gson 依赖 JAR）与 Maven Central 发布 profile — existing
- ✓ 硬件验收工具链：`scripts/sdf-smoke.sh`、`pack-smoke.sh`、`accept-kmc.sh`、`accept-ca.sh`，数盾 aarch64 真机 14/14 PASS — existing
- ✓ 会话管理：全局单设备句柄 + 会话池 + 失效自愈（含 HSM 未就绪 `0x01000403`） — existing

### Active

<!-- 本次加固的范围。每项都必须可验证。 -->

- [ ] **API-01**: 新增稳定公开包 `org.liuzx.jce.api`，仅使用 JDK 类型；反射审计确认公开签名无 JNA / `Path` / `File` / `Pointer` / `PrivateKey`
- [ ] **API-02**: `SdfErrorCategory` 九类枚举与 SVS 稳定分类 1:1 对应（`DEVICE_UNAVAILABLE` … `NATIVE_DEPENDENCY_UNAVAILABLE`）
- [ ] **API-03**: 公开 `SdfException`，携带 `category` / `operation` / 仅十六进制码的 `internalDetail` / `isRetryable`
- [ ] **API-04**: `SdfDeviceInfo` 脱敏 record，无序列号访问器，`toSafeString()` 不含序列号/路径/库文件名
- [ ] **API-05**: `SdfCapabilities` record，公开实际生效的 `sm2DefaultUserId` 与会话池状态
- [ ] **API-06**: `SdfDevice` 接口实现全部语义：`exportSignPublicKey` / `signSm2` / `signSm2Digest` / `signRsa` / `close`（`close()` 幂等，关闭后调用抛 `IllegalStateException`）
- [ ] **API-07**: `SdfDevices` 入口工厂 `open()` / `open(Properties)`，内部完成设备打开与会话预热，不要求调用方提供 `SDFLibrary` / `Pointer` / 会话句柄
- [ ] **API-08**: `exportSignPublicKey(int)` 返回 X.509 SubjectPublicKeyInfo，可被标准解析器解析（解除 SVS 阻塞）
- [ ] **API-09**: `signSm2Digest` 直接把入参作为 `e` 交给 `SDF_InternalSign_ECC`，不得再次哈希；长度非 32 抛 `OPERATION_FAILED`
- [ ] **API-10**: `signRsa` 输出长度等于模长字节数并保留前导零，真机输出可被独立软件验签器验证
- [ ] **API-11**: PIN 按需申请、`finally` 释放，不得按会话或索引缓存，也不得存入任何字段
- [ ] **API-12**: 九类错误分类至少可被真机触发 `KEY_NOT_FOUND`、`AUTHORIZATION_FAILED`、`DEVICE_UNAVAILABLE`、`ALGORITHM_UNSUPPORTED`
- [ ] **API-13**: 发布 1.1.5，`mvn -q verify` 通过，且 `liuzx-svs` 的 `DeviceDependencyContractTest` 由 BLOCKED 转为通过
- [ ] **SEC-01**: JAR 签名凭据不再硬编码在 `pom.xml`，改由 `~/.m2/settings.xml` 或环境变量注入
- [ ] **SEC-02**: JCE 签名密钥库口令轮换为强口令，并文档化密钥生成/轮换步骤
- [ ] **SEC-03**: 内部密钥 PIN / 密码不再通过命令行 `-D` 或位置参数传递，改用受限环境变量或交互输入
- [ ] **SEC-04**: 冒烟测试打包默认不携带设备凭据配置，或提供显式开关并告警
- [ ] **BUILD-01**: 与硬件无关的单元测试默认在 `mvn test` 中运行，不需要 `-DskipTests=false`
- [ ] **BUILD-02**: 依赖 JAR 签名机制不再硬编码 `jna-5.10.0.jar` / `gson-2.9.0.jar` 文件名，依赖版本升级时不破坏 JCE 认证
- [ ] **BUILD-03**: 增加 CI 流水线，至少执行编译与硬件无关单元测试
- [ ] **BUILD-04**: 发布流程脚本化且可复现，凭据通过外部注入
- [ ] **TEST-01**: 为 SPI 补充负路径测试（非法密钥长度、错误填充、错误密钥类型）
- [ ] **TEST-02**: 明确划分单元测试与硬件测试的分组及运行方式并写入文档
- [ ] **DOCS-01**: `README.md` 的版本号、示例 JAR 名、测试描述与实际代码一致
- [ ] **DOCS-02**: `AGENTS.md`、`CLAUDE.md`、`.feisuan/rules/project_rule.md` 三份指导文档内容对齐
- [ ] **DOCS-03**: 消除仓库根 `AGENTS.md` 的语义冲突（改为明确的 agent 指导文件名）
- [ ] **QUAL-01**: 统一缩进风格（消除 tab），加入 `.editorconfig`
- [ ] **QUAL-02**: 拆分 `SDFConfig`（解析、校验、classpath 提取分离）
- [ ] **QUAL-03**: 降低 `SDFSessionManager` 职责耦合，并提供可重置/可测试的初始化入口
- [ ] **QUAL-04**: `classpath:` 原生库提取的临时文件在 JVM 退出时被清理
- [ ] **QUAL-05**: 用户可见文案统一到 i18n 资源，移除 `SDFException` 中的硬编码双语 switch
- [ ] **QUAL-06**: 库代码不再直写 `System.err`，统一走自带 logger
- [ ] **COMPAT-01**: 审计并移除或显式门控废弃的 `SDF_Encrypt_Index` / `SDF_Decrypt_Index`
- [ ] **COMPAT-02**: 为 `LegacyLiuZXProvider` 确定弃用时间表并标注

### Out of Scope

- 新增密码算法或新厂商支持 — 本次是加固，不扩功能面
- 引入 Spring / DI / SLF4J 等框架 — 该库定位为零框架 leaf library，下游自行组装
- 支持数盾未导出的 ECDSA/EdDSA/DSA 密钥对生成 — 硬件能力限制，非本库缺陷
- 用 JNI 重写 JNA 绑定 — 无收益且引入巨大回归风险
- 重写或替换既有硬件验收脚本 — 它们是现有验证资产，只做适配

## Context

- **代码库映射**：`.planning/codebase/` 已包含 STACK / INTEGRATIONS / ARCHITECTURE / STRUCTURE / CONVENTIONS / TESTING / CONCERNS 七份文档，映射提交为 `9a02e72`。
- **消费方阻塞**：`liuzx-svs` Phase 2 的适配层禁止触碰 `org.liuzx.jce.jna..` 与 `SDFSessionManager.getSdfLibrary()`，而 1.1.4 导出内部密钥公钥的唯一路径是 JNA，因此无法在不破坏安全边界的前提下完成真机签名。需求副本见 `doc/SVS-FACADE-1.1.5-CHECKLIST.md`。
- **问题清单**：`.planning/codebase/CONCERNS.md` 记录了 22 项问题，按 HIGH / MEDIUM / LOW 分级，并给出推荐优先级。
- **当前版本**：`pom.xml` 为 `1.1.5-SNAPSHOT`，最近发布标签 `v1.1.4`。
- **下游集成**：KMC、CA、NAS 依赖本库；`doc/KMC-CA-INTEGRATION-CHECKLIST.md` 记录集成验收项。
- **构建环境**：开发机 JDK 25 + Maven 3.9.11，源码级别 Java 1.8。
- **验证现实**：多数功能测试需要真实 SDF 硬件，通用 CI 无法覆盖；硬件无关逻辑必须被抽出来可单测。

## Constraints

- **Security**: 不得明文暴露私钥/PIN；JAR 签名凭据不得进入版本库 — 这是本库的存在前提
- **Compatibility**: JCE `JarVerifier` 会校验 provider JAR 及其依赖 JAR 的签名 — 改动构建流程不能破坏认证
- **Compatibility**: 源码级别保持 Java 1.8，发布需产出 sources/javadoc JAR
- **Compatibility**: Provider 名称 `LiuZX` 与旧名 `liuzx` 的兼容现状不能被破坏
- **Dependencies**: JNA 5.10.0、Gson 2.9.0 的版本升级必须与签名机制解耦
- **Verification**: 涉及密码运算正确性的改动必须有硬件验收证据，不能只靠单元测试
- **API**: `org.liuzx.jce.api` 只允许 JDK 类型，不得出现 JNA、`Path`、`File`、`Pointer`、`PrivateKey` — 这是消费方安全边界
- **API**: 不得暴露路径、库文件名、序列号、私钥字节、原生句柄、密钥枚举/导入/删除/生成/备份能力
- **Compatibility**: 公开 API 遵循语义化版本，兼容新增走次版本，破坏性变更走主版本

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| 以独立 GSD 项目治理本库技术债 | 该库是独立 Maven 项目且在 PKI 工作区有独立 git 历史，不属于 liuzx-hsm 的路线图 | — Pending |
| 加固优先于扩功能 | 现有 22 项问题中 HIGH 级集中在密钥安全与构建脆弱性，风险高于功能缺口 | — Pending |
| 保持零框架 leaf library 定位 | 下游按需组装，引入框架会扩大传递依赖与冲突面 | — Pending |
| 采用 Standard 粒度（7 个阶段） | 需求需要可独立验证的阶段边界，过粗无法验收，过细管理成本高 | — Pending |
| SVS 消费方 façade 作为 Phase 1 | 它是外部团队 Phase 2 的硬阻塞，且有独立验收门禁（`DeviceDependencyContractTest`），优先解除 | — Pending |
| façade 与加固分开成不同阶段 | 新功能面与安全/构建修复的验证方式不同，混在一个阶段会让验收标准互相污染 | — Pending |
| API 值对象用不可变 final 类而非 `record` | 规格要求 `record`，但本库源码级别为 Java 1.8（`javac -source 8` 不支持 record，`Set.copyOf` 需 Java 10+）；保持 Java 8 兼容，保留 record 等价的访问器命名 | — Pending |
| 反射审计以生产 classes 目录为基准 | surefire 下 `ClassLoader.getResource("org/liuzx/jce/api")` 解析到 `target/test-classes`，导致审计对象为空 | ✓ Good |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `$gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `$gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-09-23 after initialization*
