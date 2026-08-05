# CLAUDE.md

本文件为 Claude Code（claude.ai/code）在此仓库中工作时提供指导。

## 项目概述

`liuzx-sdf-jce` 是基于 **GM/T 0018-2012《密码设备应用接口规范》** 的 Java JCE Provider，通过 JNA 调用底层 SDF 动态库（C 库），为 Java 应用提供 SM2/SM3/SM4/RSA/硬件随机数等标准 JCE 能力。Provider 名称固定为 `"liuzx"`。

**核心调用链**: `应用程序 → JCE API → Provider SPI → 会话管理(SDFSessionManager) → JNA(SDFLibrary) → SDF 硬件设备`

注意：本项目是**独立的 Maven 项目**（Java 1.8），不属于 PKI 平台的多模块 Maven 构建体系（JDK 25）。

## 常用命令

```bash
# 构建打包（包含 JAR 签名，签名需要 keystore.jks）
mvn clean package

# 仅编译
mvn compile

# 运行所有测试（需要真实 SDF 硬件，POM 默认 skipTests=true）
mvn test -DskipTests=false

# 运行单个测试
mvn test -Dtest=SM2SignatureTest -DskipTests=false

# 运行演示程序
./run.sh                    # Linux/macOS
run.bat                     # Windows

# 运行压力测试
./run.sh stress <线程数> <持续时间(秒)> <密钥索引> [密码]

# 查看依赖树
mvn dependency:tree
```

## 架构

### 分层结构

| 层 | 包路径 | 职责 |
|---|---|---|
| Demo | `demo/` | 命令行演示程序、压力测试、国际化 |
| JCE Provider | `provider/` | JCE SPI 实现，Provider 注册 |
| 会话管理 | `provider/session/` | 设备连接池（10 个会话，borrow/return 模式） |
| JNA 接口 | `jna/` | SDF C 函数声明、结构体、错误码 |
| 数据结构 | `jna/structure/` | C 结构体的 Java 映射（密钥、签名、密文） |

### Provider 注册的算法

- **SecureRandom**: `SDF` — 硬件随机数
- **MessageDigest**: `SM3`, `SHA-1`, `SHA-224`, `SHA-256`, `SHA-384`, `SHA-512`, `MD5`
- **Signature**: `SM3withSM2`, `SHA1withRSA`, `SHA256withRSA`, `SHA512withRSA`, `MD5withRSA`, `SHA256withECDSA`, `EdDSA`, `SHA1withDSA`
- **Cipher**: `SM2`, `SM4` (ECB/CBC/CFB/OFB + PKCS5Padding), `RSA` (ECB/PKCS1Padding, None/NoPadding)
- **KeyPairGenerator**: `SM2`, `RSA`, `ECDSA`, `EdDSA`, `DSA`
- **KeyGenerator**: `SM4`
- **KeyAgreement**: `SM2` (ECDH)
- **Mac**: `SM4MAC`, `HmacSM3`, `HmacSHA1`, `HmacSHA256`, `HmacSHA512`

### 会话管理

`SDFSessionManager` 是单例，维护一个 `ArrayBlockingQueue`（容量 10）的会话池：
- `borrowSession()`: 从池中取出会话（超时 5 秒），自动懒初始化
- `close()` (SDFSession): **不关闭连接**，而是归还到池中（`AutoCloseable` 语义）
- `destroy()`: 由 shutdown hook 调用，真正关闭设备句柄和会话
- 初始化采用 double-checked locking，先加载 `SDFLibrary` 再创建池，避免 JNA `Native.load()` 期间的 `JNI_OnLoad` 循环回调

### 内部/外部密钥

- **外部密钥**: 通过 `KeyPairGenerator.initialize(keysize)` 生成，密钥在 JVM 内存中
- **内部密钥**: 密钥存储在硬件设备中，通过索引引用。使用 `SM2InternalKeyGenParameterSpec(index, KeyType)` 或 `RSAInternalKeyGenParameterSpec(index)` 初始化，私钥永不离开硬件
- **SM4 内部密钥**: 使用 `SDFSM4Keys.internalKey(index)` 创建，通过 SDF 内部 KEK 索引导入会话密钥句柄

## 配置

### SDF 动态库 (`sdf-config.json`)

- 支持多厂商（Dysx、Shudun），自动检测 OS 和 CPU 架构选择对应库路径
- 系统属性覆盖（优先级从高到低）：
  - `-Dliuzx.sdf.library.path=/path/to/lib.so` — 直接指定路径
  - `-Dliuzx.sdf.vendor=Shudun` — 切换厂商配置
- `classpath:` 前缀：将 JAR 内 native 库解压到临时目录后加载（Shudun 厂商使用此方式）

### 日志 (`liuzx-jce.properties`)

内置无第三方依赖的日志系统，支持 `DEBUG/INFO/WARN/ERROR` 级别、按日轮转（`%d{yyyy-MM-dd}`）。

## 重要注意事项

1. **JAR 必须签名**: JCE Provider 的安全要求，构建时会自动用 `keystore.jks` 签名（alias: `dayou`, 密码: `123456`）。`keystore.jks` 在 `.gitignore` 中，不要提交。
2. **JNA 结构体**: 字段顺序、长度、对齐必须与厂商提供的 `libsdf.h` 头文件完全一致。注意 ECDSA/EdDSA/DSA 使用的是**独立的结构体变体**，与 SM2 的基础结构不同，修改时不要混用：`ECCrefPublicKey_ECDSA`/`ECCrefPublicKey_EDDSA` 的坐标域是 **66 字节**（支持 521 位），而 SM2 的 `ECCrefPublicKey`/`ECCrefPrivateKey` 坐标域是 **64 字节**（512 位）；对应还有 `ECCSignature_ECDSA`/`ECCSignature_EDDSA`、`DSArefPublicKey`/`DSArefPrivateKey`、`DSASignature`。
3. **测试依赖硬件**: 所有密码运算测试需要连接真实的 SDF 密码设备。POM 默认 `skipTests=true`。
4. **SDF 错误码**: 硬件异常要保留原始 SDF 返回码（见 `SDFErrorConstants`），方便定位设备问题。
5. **私钥/密钥索引/PIN/密码**: 绝不能提交到版本控制或输出到日志。
6. **添加新算法**: 在 `LiuZXProvider` 构造函数中 `put()` 注册，实现对应 SPI 类，添加单元测试。
7. **库加载回退**: `SDFLibrary.getInstance()` 优先按 `sdf-config.json` 解析出的路径加载，失败时自动回退到 JNA 短名 `Native.load("sdcrypto4j")`（此时靠 `jna.library.path` 找到库）。排查 "Failed to load native library" 时，先看日志中回退是否成功再继续。
