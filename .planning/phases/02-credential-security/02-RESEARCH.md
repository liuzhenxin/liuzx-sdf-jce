# Phase 2: 凭据与密钥安全 (credential-security) — Research

**Researched:** 2026-09-25
**Domain:** Maven 构建签名凭据、JCE 认证、测试 PIN 传递、冒烟打包的凭据边界
**Confidence:** HIGH（问题点与现有实现均已定位）

---

## 1. 现状与证据

### SEC-01 — 签名凭据硬编码（HIGH）

`pom.xml` 明文出现签名口令与 TSA：

```xml
<!-- maven-jarsigner-plugin, package 阶段 -->
<keystore>${project.basedir}/keystore.jks</keystore>
<alias>dayou</alias>
<storepass>123456</storepass>
<keypass>123456</keypass>
<tsa>http://timestamp.sectigo.com</tsa>

<!-- maven-antrun-plugin sign-libs，同样明文，且硬编码 jar 文件名 -->
<signjar jar=".../jna-5.10.0.jar" alias="dayou" storepass="123456" keypass="123456"
         keystore="${project.basedir}/keystore.jks" tsaurl="http://timestamp.sectigo.com"/>
<signjar jar=".../gson-2.9.0.jar" .../>
```

`release` profile 已经确立了正确模式：从 `settings.xml` 的 `gpg-signing` profile 读取
`${gpg.keyname}` / `${gpg.passphrase}`。SEC-01 只需把 JCE 签名凭据套用同一模式。

### SEC-02 — 弱口令密钥库（HIGH）

`keystore.jks`（gitignored）口令为 `123456`，别名 `dayou`。JCE 只要求 provider jar 及其依赖 jar
由**同一签名者**签名，不要求受信 CA，因此可以轮换为新密钥库与新强口令，不影响 JCE 认证，
也不影响已发布产物。轮换需重新生成密钥库并更新 `settings.xml`。

### SEC-03 — PIN 经 argv / 系统属性暴露（HIGH）

| 位置 | 现状 |
|---|---|
| `scripts/sdf-smoke.sh` | `JAVA_OPTS+=("-Dliuzx.sdf.smoke.pin=${SMOKE_PIN}")` → `ps` 可见 |
| `SdfSmokeTest` | 读取 `System.getProperty("liuzx.sdf.smoke.pin")` |
| `Main` 压力测试 | `args[4].toCharArray()` 位置参数 → `ps` 可见 |
| 测试 | 通过 `-D` 系统属性传入 PIN |
| `run.sh` | 透传 `"$@"`，不引入 PIN，但 `Main` 仍接受位置参数 |

`SDFSessionManager.passwordToBytes` 已避免 String 驻留，PIN 的**内存**处理是正确的；
问题只在**入口暴露**（argv / `/proc/<pid>/cmdline`）。

### SEC-04 — 打包默认携带设备凭据（MEDIUM/HIGH）

`scripts/pack-smoke.sh` 把 `conf/`（vendor `*.ini`，可能含设备地址、凭据、证书）整目录/整文件
复制进发布包，仅打印一行警告（`conf/ may contain device credentials`）。默认行为即泄露风险。

## 2. 可复用的既有模式

- `pom.xml` 的 `release` profile + `settings.xml` 的 `gpg-signing` profile：**属性化凭据**的现成范例。
- `SDFSessionManager.passwordToBytes` / `getPrivateKeyAccessRight`：PIN 的安全内存处理已就绪。
- `SdfSmokeTest` 已有 `liuzx.sdf.smoke.*` 属性面；改造入口不影响内部逻辑。
- `pack-smoke.sh` 已有 `PACK_CONFIG_PATH` 覆盖与警告文案；可加默认排除与显式开关。

## 3. 关键约束

- **JCE 认证**：主 jar 与 `target/lib` 下每个依赖 jar 都必须签名，且签名者一致。轮换密钥库后
  必须重新验证 `Cipher` / `KeyGenerator` / `Mac` / `SecureRandom` 不再抛
  `JCE cannot authenticate the provider LiuZX`。
- **本地构建可用性**：凭据外置后，未配置 `settings.xml` 的开发者执行 `mvn package` 必须得到
  **清晰可诊断**的失败，而不是含糊的签名错误。
- **Java 8**：源码级别不变。
- **不扩大范围**：依赖 jar 文件名的硬编码属于 BUILD-02（Phase 3），TSA 可配置化属于 Phase 3；
  本阶段只处理凭据与 PIN/配置暴露。

## 4. 设计选项

### SEC-01 凭据注入

| 选项 | 做法 | 评价 |
|---|---|---|
| A（推荐） | pom 用 `${jce.keystore}` / `${jce.storepass}` / `${jce.keypass}` / `${jce.alias}`；`settings.xml` 定义常驻 `jce-signing` profile 提供口令，pom `<properties>` 只保留非敏感默认（路径、别名） | 与 `gpg-signing` 一致；本地/CI 都走 settings |
| B | 环境变量 `JCE_KEYSTORE_PASS` 等经 `-D` 注入 | 仍进 argv |
| C | 外部 `.mvn/maven.config` 或 CI secret 文件 | 依赖 CI，本地不便 |

采用 A，并允许 `-D` 覆盖（便于 CI），但文档明确推荐 settings。

### SEC-03 PIN 入口

| 选项 | 做法 | 评价 |
|---|---|---|
| A（推荐） | 环境变量 `LIUZX_SMOKE_PIN`，`SdfSmokeTest` 读取 env 并 zero 化；脚本用 `export` 而非 `-D` | 不进 argv；实现简单 |
| B | 从 stdin 读取 | 适合交互，不适合冒烟 |
| C | 从受限权限文件读取 | 需管理文件权限 |

采用 A；`Main` 压力测试改为交互读取或 env，移除位置参数。

### SEC-04 打包

采用「默认排除 + 显式开关 + 显著告警」：默认只复制 `*.ini.example` 并生成脱敏模板；
`PACK_INCLUDE_CONF=1` 才复制真实配置，且打印醒目警告。

## 5. 验证策略

| 需求 | 验证 |
|---|---|
| SEC-01 | 无 settings 凭据时 `mvn package` 失败且信息指明配置项；有凭据时成功 |
| SEC-01 | `grep -R "123456\|storepass" pom.xml` 无明文口令 |
| SEC-02 | 新密钥库签名后，受限 JCE 运算（`Cipher.getInstance("SM4","LiuZX")`）不抛认证异常 |
| SEC-03 | 冒烟运行时的 `java` 进程命令行不含 PIN；`ps` 断言 |
| SEC-04 | 默认产物 `tar -tzf` 不含真实 `.ini` 凭据文件；`PACK_INCLUDE_CONF=1` 才包含 |

## 6. 风险

- 轮换密钥库需要用户提供新强口令（SEC-02 的人工步骤），且旧密钥库不得进入版本库。
- 若 `settings.xml` 的 profile 未激活，构建会失败；需在 `RELEASE.md` 与错误信息中给出修复指引。
- 现有已发布 1.1.5 使用旧签名者；轮换后 1.1.6 起为新签名者，属可接受的过渡。

---

*Research complete. Ready for planning.*
