# Requirements: liuzx-sdf-jce

**Defined:** 2026-09-23
**Core Value:** 硬件密码运算必须正确且私钥永不离开设备，同时该 Provider 必须能被安全、可复现地构建与发布

## v1 Requirements

本次加固的初始发布范围。每项映射到路线图的一个阶段。

### 凭据与密钥安全

- [ ] **SEC-01**: JAR 签名凭据不再硬编码在 `pom.xml`，改由 `~/.m2/settings.xml` 或环境变量注入
- [ ] **SEC-02**: JCE 签名密钥库口令轮换为强口令，并文档化密钥生成/轮换步骤
- [ ] **SEC-03**: 内部密钥 PIN / 密码不再通过命令行 `-D` 或位置参数传递，改用受限环境变量或交互输入
- [ ] **SEC-04**: 冒烟测试打包默认不携带设备凭据配置，或提供显式开关并告警

### 可复现构建与依赖签名

- [ ] **BUILD-04**: 发布流程脚本化且可复现，凭据通过外部注入
- [ ] **BUILD-02**: 依赖 JAR 签名机制不再硬编码 `jna-5.10.0.jar` / `gson-2.9.0.jar` 文件名，依赖版本升级时不破坏 JCE 认证

### 测试基线与 CI 门禁

- [ ] **BUILD-01**: 与硬件无关的单元测试默认在 `mvn test` 中运行，不需要 `-DskipTests=false`
- [ ] **BUILD-03**: 增加 CI 流水线，至少执行编译与硬件无关单元测试
- [ ] **TEST-01**: 为 SPI 补充负路径测试（非法密钥长度、错误填充、错误密钥类型）
- [ ] **TEST-02**: 明确划分单元测试与硬件测试的分组及运行方式并写入文档

### 文档与指导一致性

- [ ] **DOCS-01**: `README.md` 的版本号、示例 JAR 名、测试描述与实际代码一致
- [ ] **DOCS-02**: `AGENTS.md`、`CLAUDE.md`、`.feisuan/rules/project_rule.md` 三份指导文档内容对齐
- [ ] **DOCS-03**: 消除仓库根 `AGENTS.md` 的语义冲突（改为明确的 agent 指导文件名）

### 配置与会话层重构

- [ ] **QUAL-02**: 拆分 `SDFConfig`（解析、校验、classpath 提取分离）
- [ ] **QUAL-03**: 降低 `SDFSessionManager` 职责耦合，并提供可重置/可测试的初始化入口
- [ ] **QUAL-04**: `classpath:` 原生库提取的临时文件在 JVM 退出时被清理
- [ ] **QUAL-06**: 库代码不再直写 `System.err`，统一走自带 logger

### 兼容性收敛与代码风格

- [ ] **QUAL-01**: 统一缩进风格（消除 tab），加入 `.editorconfig`
- [ ] **QUAL-05**: 用户可见文案统一到 i18n 资源，移除 `SDFException` 中的硬编码双语 switch
- [ ] **COMPAT-01**: 审计并移除或显式门控废弃的 `SDF_Encrypt_Index` / `SDF_Decrypt_Index`
- [ ] **COMPAT-02**: 为 `LegacyLiuZXProvider` 确定弃用时间表并标注

## v2 Requirements

后续版本处理，当前不进入路线图。

### 硬件扩展

- **HARD-01**: 补充 SanSec / DYSX 的 aarch64 真机验收记录（与数盾对齐）
- **HARD-02**: 为 packed RSA 布局增加基于结构体快照的回归向量测试

### 工程质量

- **ENG-01**: 引入 JaCoCo 覆盖率统计并设定阈值
- **ENG-02**: 依赖漏洞扫描（OWASP dependency-check）纳入 CI

## Out of Scope

明确排除，防止范围蔓延。

| Feature | Reason |
|---------|--------|
| 新增密码算法 / 新厂商支持 | 本次是加固，不扩功能面；新增能力应另立里程碑 |
| 引入 Spring / DI / SLF4J 框架 | 保持零框架 leaf library，避免扩大下游传递依赖 |
| 支持数盾未导出的 ECDSA/EdDSA/DSA 密钥对生成 | 硬件能力限制，非本库缺陷 |
| 用 JNI 重写 JNA 绑定 | 无收益，回归风险极高 |
| 重写既有硬件验收脚本 | 它们是现有验证资产，只做适配 |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| SEC-01 | Phase 1 | Pending |
| SEC-02 | Phase 1 | Pending |
| SEC-03 | Phase 1 | Pending |
| SEC-04 | Phase 1 | Pending |
| BUILD-04 | Phase 2 | Pending |
| BUILD-02 | Phase 2 | Pending |
| BUILD-01 | Phase 3 | Pending |
| BUILD-03 | Phase 3 | Pending |
| TEST-01 | Phase 3 | Pending |
| TEST-02 | Phase 3 | Pending |
| DOCS-01 | Phase 4 | Pending |
| DOCS-02 | Phase 4 | Pending |
| DOCS-03 | Phase 4 | Pending |
| QUAL-02 | Phase 5 | Pending |
| QUAL-03 | Phase 5 | Pending |
| QUAL-04 | Phase 5 | Pending |
| QUAL-06 | Phase 5 | Pending |
| QUAL-01 | Phase 6 | Pending |
| QUAL-05 | Phase 6 | Pending |
| COMPAT-01 | Phase 6 | Pending |
| COMPAT-02 | Phase 6 | Pending |

**Coverage:**
- v1 requirements: 21 total
- Mapped to phases: 21
- Unmapped: 0 ✓

---
*Requirements defined: 2026-09-23*
*Last updated: 2026-09-23 after initial definition*
