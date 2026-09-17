# KMC / CA 集成验收清单（liuzx-sdf-jce 1.1.4-SNAPSHOT）

本清单用于验证修复版 `liuzx-sdf-jce-1.1.4-SNAPSHOT` 在 KMC 与 CA 中可用。设备侧单机冒烟
见 [`SHUDUN-AARCH64-ACCEPTANCE.md`](./SHUDUN-AARCH64-ACCEPTANCE.md)。

## 0. 前置（两边共通）

1. **构建产物**：修复版为 `1.1.4-SNAPSHOT`。先在本仓库 `mvn -o install -DskipTests`，或部署到
   Nexus / 私有仓库，使下游构建可解析。向 KMC/CA 构建机分发可用本仓库脚本：
   ```bash
   # 构建并推送到远端 ~/.m2/repository（默认）
   scripts/install-to.sh root@<build-host>
   # 或指定远端仓库根
   scripts/install-to.sh build@<build-host> /opt/maven-repo
   ```
2. **JDK 25**：KMC 与 CA 产物均为 Java 25 字节码，必须用 JDK 25 运行（KMC 镜像
   `eclipse-temurin:25-jre-jammy`，CA 镜像 `ghcr.io/graalvm/jdk-community:25.0.1`）。宿主机
   JDK 11 只能跑单机冒烟包。
3. **厂商材料**：密码机库与配置不入库，只读挂载进容器。

> ✅ **CA 版本已升级**：`liuzx-ca/pom.xml` 的 `dependencyManagement` 已从 **1.1.3** 改为
> **1.1.4-SNAPSHOT**（覆盖 `liuzx-pki-security` 传递的 1.1.2）。构建 CA 前确保该版本已发布到
> 可解析的仓库（本地 `mvn install` 或 Nexus）。

---

## 1. KMC 集成

### 1.1 构建
```bash
# 若构建机还没有该版本：scripts/install-to.sh root@<kmc-build-host>
cd liuzx-kmc
mvn -o -pl liuzx-kmc-start -am package -DskipTests   # 解析到 liuzx-sdf-jce:1.1.4-SNAPSHOT
```

### 1.2 运行（数盾 aarch64 示例）
KMC 用**自有配置**覆盖 `-Dliuzx.sdf.*`，只认环境变量：

```yaml
# docker-compose override 要点
services:
  liuzx-kmc:
    environment:
      KMC_CRYPTO_BACKEND: SDF
      KMC_CRYPTO_REQUIRE_HARDWARE: "true"
      KMC_KEY_PROTECTION_MODE: SDF_INTERNAL
      KMC_ALLOW_SOFTWARE_IN_PROD: "false"
      KMC_SDF_VENDOR: Shudun
      KMC_SDF_LIBRARY_PATH: /opt/hsm/lib/libsdhsmcrypto.so
      KMC_SDF_CONFIG_PATH: /etc/hsm/conf          # 注意：Shudun 这里是“目录”
      KMC_SDF_EXPECTED_SERIAL: ""                 # 可选，填现场序列号做身份校验
    volumes:
      - /path/to/libsdhsmcrypto.so:/opt/hsm/lib/libsdhsmcrypto.so:ro
      - /path/to/conf:/etc/hsm/conf:ro            # 目录内放 sdhsm.ini
```

> **Shudun 配置路径要点**：标准 `SDF_OpenDevice` 读 `./sdhsm.ini`（或 `/etc/sdhsm.ini`）。
> 若标准调用失败，回退 `SDF_OpenDeviceWithPath` 时它期望的是**目录**。所以
> `KMC_SDF_CONFIG_PATH` 要指向**包含 `sdhsm.ini` 的目录**（示例 `/etc/hsm/conf`），
> 不要指到单个 `.ini` 文件；或把 `sdhsm.ini` 放到容器工作目录/`/etc/sdhsm.ini`。
> DYSX 则是 INI **文件**（`SDF_OpenDeviceEx` 语义），两者不要混。

### 1.3 启动检查
可用本仓库脚本自动轮询并断言（readiness 就绪、可选状态接口、日志无失败特征）：

```bash
KMC_BASE_URL=http://127.0.0.1:3443 \
KMC_CONTAINER=pki-kmc \
KMC_TOKEN=<bearer-token> \
  scripts/accept-kmc.sh
```

变量：`KMC_BASE_URL`、`KMC_CONTEXT_PATH`（默认 `/api`）、`KMC_TIMEOUT_SECONDS`、
`KMC_POLL_INTERVAL`、`KMC_TOKEN`（有则查 `/v1/crypto-devices/status`）、
`KMC_CONTAINER`/`KMC_LOG_FILE`（有则做日志断言）。未提供容器/日志时日志检查为 `[SKIP]`。

- 日志**不得**出现 `SDF device probe failed`、`key protection is not ready`、
  `Error looking up function 'SDF_OpenDeviceEx'`。
- 日志**不得**出现数盾 `[FORCE] 应用应仅打开一次设备句柄并全局使用`（多开告警）。
  > 末尾 `[FORCE] 应用应在退出前或不再使用时关闭设备` 为厂商打开时的一次性提示，可忽略，
  > 见验收记录第四节。

### 1.4 健康与状态
```bash
# 上下文路径 /api，端口 3443（HTTP）
curl -s http://127.0.0.1:3443/api/actuator/health/readiness     # 期望 status=UP 且含 hsm
curl -s "http://127.0.0.1:3443/api/v1/crypto-devices/status?refresh=true"   # 需登录态，期望 status=UP
```
`hsm` 指标 bean 为 `@Component("hsm")`，readiness 组已包含它：
- 硬件可用 → `UP`；`KMC_CRYPTO_REQUIRE_HARDWARE=true` 且设备不可用 → `DOWN`。

### 1.5 业务闭环（至少一次）
1. 生成/申请业务密钥；
2. 用内部 wrap key 完成封装/解封装往返（走 `SM4/CBC/PKCS5Padding` + 内部密钥句柄）；
3. 校验审计与数据库状态。

### 1.6 fail-closed 负例
把 `KMC_SDF_LIBRARY_PATH` 指向不存在的文件重启，期望 `readiness` 降级、状态接口
`errorCategory=LIB_LOAD`，依赖硬件的操作拒绝执行（不静默回落软件）。

---

## 2. CA 集成

### 2.1 构建
```bash
# liuzx-ca/pom.xml 已指向 liuzx-sdf-jce:1.1.4-SNAPSHOT（本次修改）
# 若构建机还没有该版本：scripts/install-to.sh root@<ca-build-host>
cd liuzx-ca
mvn -o package -DskipTests
```

### 2.2 JVM 参数与挂载
CA 直接读 JVM 系统属性（**不要**设 `liuzx.sdf.library.path`，用 profile 统管）：

```bash
export JAVA_TOOL_OPTIONS="-Dliuzx.sdf.profile.path=/etc/hsm/sdf-profile.json -Dliuzx.sdf.vendor=Shudun"
# 容器内把厂商库挂到 profile 里配置的路径，例如 /opt/hsm/lib/libsdhsmcrypto.so
# profile 可用 liuzx-sdf-jce/HSM/sdf-profile.json 作为模板
```

### 2.3 先验证底层链路（可选但推荐）
用与 CA 同层的 `liuzx-pki-security` SDF 测试，先排除设备/库问题：
```bash
cd liuzx-pki-parent
mvn -pl liuzx-pki-security -am test \
  -Dtest='SdfRsaSignerTest,SdfCryptorTest,SdfRsaCipherTest,SdfSm4CipherTest' \
  -Dliuzx.sdf.hardwareTests=true -Dliuzx.sdf.pin=$PIN \
  -Dliuzx.sdf.profile.path=/etc/hsm/sdf-profile.json -Dliuzx.sdf.vendor=Shudun
```

### 2.4 CA 签名配置
在 CA 管理侧把 CA 的签名器配为 SDF 内部密钥：

| 项 | 值 |
|---|---|
| `signerType` | `sdf` |
| `signerConf` | `key-index=<内部密钥索引>,algo=RSA_SHA256,password=<PIN>` |

CA 启动时会 `securityFactory.createSigner("sdf", conf, cert)`，内部会
`SDF_ExportSignPublicKey_*` 导出公钥并用硬件私钥签名。

### 2.5 端到端
1. 用该 CA 签发一张证书（或签 CRL）；
2. 用导出的公钥/证书验签通过；
3. 重启 CA 后再签一次，确认无 `No such provider: liuzx` / 设备打开失败。

---

## 3. 通过标准（汇总）

| 项 | KMC | CA |
|---|---|---|
| 版本 | `liuzx-sdf-jce:1.1.4-SNAPSHOT` | 同上（`pom.xml` 已指向 1.1.4-SNAPSHOT） |
| 设备打开 | `SDF_OpenDevice`（标准优先） | 同 |
| 多开告警 | 无 `[FORCE] 应用应仅打开一次…` | 同 |
| 健康 | `readiness` 含 `hsm=UP` | 启动无设备错误 |
| 业务 | 密钥生成 + 封装/解封装闭环 | 签发/CRL + 验签通过 |
| 负例 | 错误库路径 → fail-closed | — |

## 4. 常见坑

- **CA 版本**：已改为 1.1.4-SNAPSHOT；若其他下游仍 pin 旧版，同样需升级才能拿到修复。
- **Shudun 配置路径给了文件**：回退分支期望目录，应给目录或让标准调用读到默认位置。
- **用 JDK 11 跑 KMC/CA**：`UnsupportedClassVersionError`（需 25）。
- **把库/INI 提交进仓库**：属敏感材料，只挂载不提交。
- **DYSX**：标准 `SDF_OpenDevice` 默认读 `./cacipher.ini`；需按现场放到默认位置，或让回退用
  `SDF_OpenDeviceEx` 指向 INI 文件。
