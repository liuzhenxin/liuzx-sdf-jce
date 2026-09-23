# Roadmap: liuzx-sdf-jce

## Overview

本路线图把 `.planning/codebase/CONCERNS.md` 中的 22 项技术债转化为 6 个可独立验证的加固阶段。先解决最高风险的安全凭据问题（Phase 1）与构建脆弱性（Phase 2），随后建立测试与 CI 门禁（Phase 3）以保护后续重构；在行为被测试锁定后，统一文档（Phase 4）并重构配置/会话层（Phase 5）；最后收敛兼容性与代码风格（Phase 6）。每一阶段都以“可观察的验证结果”收口，涉及密码运算的改动必须有硬件验收证据。

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

- [ ] **Phase 1: 凭据与密钥安全** - 移除硬编码签名凭据，轮换密钥，收敛 PIN/配置暴露面
- [ ] **Phase 2: 可复现构建与依赖签名** - 发布流程脚本化，依赖签名与版本解耦
- [ ] **Phase 3: 测试基线与 CI 门禁** - 硬件无关单测默认运行，补负路径测试，接入 CI
- [ ] **Phase 4: 文档与指导一致性** - README 与三份指导文档对齐代码现状
- [ ] **Phase 5: 配置与会话层重构** - 拆分 SDFConfig/SDFSessionManager，清理临时文件与 System.err
- [ ] **Phase 6: 兼容性收敛与代码风格** - 统一缩进，文案 i18n 化，废弃扩展与旧 Provider 收敛

## Phase Details

### Phase 1: 凭据与密钥安全
**Goal**: 让签名密钥、PIN 与设备配置不再以公开弱凭据形式存在，且发布路径可审计
**Depends on**: Nothing (first phase)
**Requirements**: [SEC-01, SEC-02, SEC-03, SEC-04]
**Success Criteria** (what must be TRUE):
  1. `pom.xml` 中不再出现任何明文 `storepass`/`keypass`/`alias` 口令值，签名凭据从 `settings.xml` 或环境变量读取
  2. JCE 签名密钥库使用新的强口令，且存在一份可复现的密钥生成/轮换步骤文档
  3. 内部密钥测试与压力测试不再通过命令行 `-D` 或位置参数接收 PIN
  4. 冒烟打包默认不包含真实设备凭据配置，或需显式开关且打印告警
**Plans**: TBD

### Phase 2: 可复现构建与依赖签名
**Goal**: 依赖升级不再悄悄破坏 JCE 认证，发布流程可在干净环境复现
**Depends on**: Phase 1
**Requirements**: [BUILD-04, BUILD-02]
**Success Criteria** (what must be TRUE):
  1. 依赖 JAR 签名改为按 `target/lib/*.jar` 批量处理，`pom.xml` 中不再出现带版本号的文件名
  2. 将 JNA 或 Gson 版本提升一个补丁版本后，`mvn clean package` 产出的 Provider 仍能被 JCE 认证
  3. 发布流程可在无预置本地状态的环境按文档步骤复现，凭据全部外部注入
**Plans**: TBD

### Phase 3: 测试基线与 CI 门禁
**Goal**: 让回归在合并前被自动捕获，硬件无关逻辑有可运行的保护网
**Depends on**: Phase 2
**Requirements**: [BUILD-01, BUILD-03, TEST-01, TEST-02]
**Success Criteria** (what must be TRUE):
  1. `mvn test` 默认执行 `SDFConfigTest`、`RSAKeyConverterTest`、`SDFLibrarySelectionTest`、`SDFDeviceOpenerTest`、`SDFSessionManagerLifecycleTest` 等硬件无关测试并通过
  2. 硬件相关测试通过 profile/标签显式选择，默认构建不会因缺少硬件而失败
  3. SPI 负路径测试存在并能在无硬件条件下验证参数校验分支
  4. CI 流水线在提交/PR 上执行编译与硬件无关单元测试
**Plans**: TBD

### Phase 4: 文档与指导一致性
**Goal**: 人（和 AI agent）阅读的文档与代码现状一致，不再引导出错误做法
**Depends on**: Phase 3
**Requirements**: [DOCS-01, DOCS-02, DOCS-03]
**Success Criteria** (what must be TRUE):
  1. `README.md` 的版本号、示例 JAR 名、测试描述与 `pom.xml` 及实际行为一致
  2. 三份指导文档对 Provider 名称、算法清单、配置格式、Java 版本、目录结构的描述一致
  3. 仓库根指导文件命名不再与工作区级 `AGENTS.md` 语义冲突
**Plans**: TBD

### Phase 5: 配置与会话层重构
**Goal**: 在测试保护下拆分高复杂度类，消除隐藏的静态状态与资源泄漏
**Depends on**: Phase 4
**Requirements**: [QUAL-02, QUAL-03, QUAL-04, QUAL-06]
**Success Criteria** (what must be TRUE):
  1. `SDFConfig` 的解析、校验、classpath 提取职责被拆分到独立类，原有单测全部通过
  2. `SDFSessionManager` 提供可重置的初始化入口，生命周期测试可重复运行而不互相污染
  3. `classpath:` 提取的临时文件在 JVM 退出后被清理，重复运行不累积
  4. 库代码中不再有 `System.err` 直写，诊断信息走自带 logger
**Plans**: TBD

### Phase 6: 兼容性收敛与代码风格
**Goal**: 清理历史包袱，使代码风格与用户可见文案统一、可长期维护
**Depends on**: Phase 5
**Requirements**: [QUAL-01, QUAL-05, COMPAT-01, COMPAT-02]
**Success Criteria** (what must be TRUE):
  1. 全仓库无 tab 缩进，`.editorconfig` 生效
  2. `SDFException` 不再有硬编码双语 switch，用户可见文案来自 i18n 资源
  3. `SDF_Encrypt_Index` / `SDF_Decrypt_Index` 要么被移除，要么被显式门控并标注
  4. `LegacyLiuZXProvider` 有明确的弃用时间表或保留理由
**Plans**: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 → 5 → 6

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. 凭据与密钥安全 | 0/0 | Not started | - |
| 2. 可复现构建与依赖签名 | 0/0 | Not started | - |
| 3. 测试基线与 CI 门禁 | 0/0 | Not started | - |
| 4. 文档与指导一致性 | 0/0 | Not started | - |
| 5. 配置与会话层重构 | 0/0 | Not started | - |
| 6. 兼容性收敛与代码风格 | 0/0 | Not started | - |
