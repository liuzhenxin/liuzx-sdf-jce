---
phase: 2
slug: credential-security
status: draft
nyquist_compliant: true
wave_0_complete: false
created: 2026-09-25
---

# Phase 2 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | JUnit 5（jupiter 5.8.2）+ shell 断言 |
| **Config file** | `pom.xml`（surefire 2.22.2） |
| **Quick run command** | `mvn -q test -DskipTests=false -Dtest='org.liuzx.jce.api.*Test'` |
| **Full suite command** | `mvn -q verify -DskipTests=false`（含真机时另计） |
| **Estimated runtime** | ~30–90 秒（硬件无关） |

---

## Sampling Rate

- **After every task commit:** Run the plan-level quick command
- **After every plan wave:** Run `mvn -q package -DskipTests`（验证打包与签名仍可用）
- **Before `$gsd-verify-work`:** 全量套件 + 真机冒烟（可选）+ 发布演练（dry-run）
- **Max feedback latency:** ~120 秒

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 02-01-01 | 01 | 1 | SEC-01 | T-2-01 | pom 无明文签名口令 | static | `! grep -E "storepass>[^$]|keypass>[^$]|>123456<" pom.xml` | ❌ W0 | ⬜ pending |
| 02-01-02 | 01 | 1 | SEC-01 | T-2-01 | 缺凭据时构建失败且信息可诊断 | build | `mvn -q -DskipTests package 2>&1 \| grep -q "jce.storepass"`（无 settings 场景） | ❌ W0 | ⬜ pending |
| 02-01-03 | 01 | 1 | SEC-01 | T-2-01 | 有凭据时可打包并签名 | build | `mvn -q clean package -DskipTests` 退出 0 | ❌ W0 | ⬜ pending |
| 02-02-01 | 02 | 1 | SEC-03 | T-2-03 | 冒烟 PIN 不经 argv | shell | `! ps -o command= -p <pid> \| grep -q "$PIN"`（运行期断言） | ❌ W0 | ⬜ pending |
| 02-02-02 | 02 | 1 | SEC-03 | T-2-03 | 演示压力测试无位置 PIN | static | `! grep -n "args\[4\]" src/main/java/org/liuzx/jce/demo/Main.java` | ❌ W0 | ⬜ pending |
| 02-03-01 | 03 | 1 | SEC-04 | T-2-04 | 默认包不含真实 ini | shell | `tar -tzf target/*.tar.gz \| grep -vq "conf/.*\.ini$"`（example 除外） | ❌ W0 | ⬜ pending |
| 02-03-02 | 03 | 1 | SEC-04 | T-2-04 | 显式开关才包含真实配置 | shell | `PACK_INCLUDE_CONF=1` 时包含且打印警告 | ❌ W0 | ⬜ pending |
| 02-04-01 | 04 | 2 | SEC-02 | T-2-02 | 新密钥库口令为强口令且已文档化 | manual | 见 `/gsd-verify-work` 检查清单 | ❌ W0 | ⬜ pending |
| 02-04-02 | 04 | 2 | SEC-02 | T-2-02 | 轮换后 JCE 认证仍通过 | build+run | `mvn -q clean package -DskipTests` 后运行受限 JCE 冒烟 | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `src/test/java/org/liuzx/jce/provider/SigningCredentialConfigTest.java` — 断言 pom 中无明文口令（读取 pom 文本）
- [ ] `scripts/verify-no-secret-in-argv.sh` — 运行冒烟并断言 `ps` 不含 PIN
- [ ] `scripts/pack-smoke.sh` 默认脱敏分支的 shell 断言（可在 pack 脚本内自检）

*若已有基础设施覆盖，则无需新建。*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| 新密钥库强口令轮换 | SEC-02 | 需人工生成密钥库并设置口令，不得进版本库 | 按 `RELEASE.md` 的轮换章节生成新 `keystore.jks`（强口令），配置 `settings.xml`，`mvn clean package` 后验证 JCE 受限运算可用 |
| CI/发布环境凭据配置 | SEC-01, SEC-02 | 依赖部署系统密钥管理 | 在发布机配置 `settings.xml` 的 `jce-signing` profile 并演练 `mvn clean deploy -Prelease,gpg-signing -DskipTests=true --dry-run` |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 120s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
