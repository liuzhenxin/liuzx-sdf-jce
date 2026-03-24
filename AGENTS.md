# LiuZX SDF JCE Provider 项目文档

## 项目概述

这是一个基于 **GM/T 0018-2012《密码设备应用接口规范》** 实现的 Java JCE Provider 项目。项目为 Java 应用程序提供符合标准 JCE 架构的密码学服务，通过标准 API 与支持 SDF 接口的密码设备（如加密机、UKey 等）进行交互。

### 核心特性

- **符合 JCE 标准**: 可通过 `Security.addProvider()` 动态注册，支持标准 JCE API
- **国密算法支持**:
  - **SM2**: 内部/外部密钥对的签名、验签、加密、解密
  - **SM3**: 消息摘要计算
  - **SM4**: ECB 和 CBC 模式的加密与解密
- **RSA 算法支持**:
  - 内部密钥（硬件密钥）的签名、验签、加密、解密
  - 外部密钥对的生成和加密运算
- **硬件密钥支持**: 支持使用存储在密码设备内部的密钥对进行密码运算，私钥永不离开硬件
- **跨平台**: 支持 Linux/Windows/macOS，支持 x86_64/aarch64 架构
- **可配置日志系统**: 内置无第三方依赖的日志系统，支持配置文件控制
- **国际化**: 演示程序支持中英文切换
- **性能测试工具**: 内置多线程压力测试程序

## 架构概览

本项目采用分层架构设计，核心调用链如下：

```
应用程序 → JCE API → Provider SPI → 会话管理 → JNA → SDF 硬件设备
```

### 各层职责

1. **JCE Provider 层** (`provider/`) - 对外提供标准 JCE 接口，实现各种密码学服务
2. **会话管理层** (`session/`) - 管理与密码设备的连接，支持会话复用
3. **JNA 接口层** (`jna/`) - 通过 JNA 调用底层 SDF C 库函数
4. **数据结构层** (`jna/structure/`) - 定义与 C 库交互的数据结构（密钥、签名、密文等）

### 核心设计模式

- **SPI 模式**：遵循 Java Security Provider 架构，每个算法实现对应的 SPI 类
- **会话管理**：通过 `SDFSessionManager` 统一管理设备连接，支持多线程安全
- **内部/外部密钥**：支持使用硬件内部密钥（私钥永不离开设备）或软件生成的外部密钥

### 技术栈

- **Java 版本**: Java 1.8+
- **构建工具**: Apache Maven
- **核心依赖**:
  - JNA 5.10.0（用于调用底层 C 库）
  - Gson 2.9.0（用于配置文件解析）
  - JUnit 5.8.2（用于单元测试）

## 项目结构

```
liuzx-sdf-jce/
├── src/
│   ├── main/
│   │   ├── java/org/liuzx/jce/
│   │   │   ├── demo/                    # 演示程序
│   │   │   │   ├── Main.java            # 主演示程序
│   │   │   │   ├── I18n.java            # 国际化支持
│   │   │   │   ├── StressTester.java    # 压力测试工具
│   │   │   │   └── KeyPairGenStressTester.java
│   │   │   ├── jna/                     # JNA 接口定义
│   │   │   │   ├── SDFLibrary.java      # SDF 接口定义
│   │   │   │   └── structure/           # SDF 数据结构
│   │   │   │       ├── ECCrefPublicKey.java
│   │   │   │       ├── ECCrefPrivateKey.java
│   │   │   │       ├── ECCCipher.java
│   │   │   │       ├── ECCSignature.java
│   │   │   │       ├── RSArefPublicKey.java
│   │   │   │       └── RSArefPrivateKey.java
│   │   │   └── provider/                # JCE Provider 实现
│   │   │       ├── LiuZXProvider.java   # Provider 主类
│   │   │       ├── SDFConfig.java       # 配置管理
│   │   │       ├── asymmetric/          # 非对称加密
│   │   │       │   ├── sm2/             # SM2 算法实现
│   │   │       │   │   ├── SM2KeyPairGenerator.java
│   │   │       │   │   ├── SM2SignatureSpi.java
│   │   │       │   │   ├── SM2CipherSpi.java
│   │   │       │   │   ├── SM2PublicKey.java
│   │   │       │   │   ├── SM2PrivateKey.java
│   │   │       │   │   └── SM2InternalKeyGenParameterSpec.java
│   │   │       │   └── rsa/             # RSA 算法实现
│   │   │       │       ├── RSAKeyPairGeneratorSpi.java
│   │   │       │       ├── RSASignatureSpi.java
│   │   │       │       ├── RSACipherSpi.java
│   │   │       │       ├── SDFRSAPrivateKey.java
│   │   │       │       └── RSAInternalKeyGenParameterSpec.java
│   │   │       ├── digest/              # 摘要算法
│   │   │       │   └── SM3Digest.java
│   │   │       ├── symmetric/           # 对称加密
│   │   │       │   ├── SM4CipherSpi.java
│   │   │       │   ├── SM4KeyGenerator.java
│   │   │       │   └── SM4SecretKey.java
│   │   │       ├── random/              # 随机数生成
│   │   │       │   └── SDFSecureRandomSpi.java
│   │   │       ├── session/             # 会话管理
│   │   │       │   ├── SDFSession.java
│   │   │       │   └── SDFSessionManager.java
│   │   │       ├── exception/           # 异常处理
│   │   │       │   ├── SDFException.java
│   │   │       │   └── SDFErrorConstants.java
│   │   │       ├── log/                 # 日志系统
│   │   │       │   └── LiuzxProviderLogger.java
│   │   │       └── util/                # 工具类
│   │   │           ├── ASN1Util.java
│   │   │           ├── SM3Util.java
│   │   │           └── GMObjectIdentifiers.java
│   │   ├── resources/
│   │   │   ├── sdf-config.json          # SDF 库配置
│   │   │   ├── liuzx-jce.properties     # 日志配置
│   │   │   └── i18n/                    # 国际化资源
│   │   │       ├── messages_en.properties
│   │   │       └── messages_zh.properties
│   │   └── libsdf.h                     # SDF 头文件定义
│   └── test/
│       └── java/org/liuzx/jce/provider/test/
│           ├── SM2InternalKeyTest.java
│           ├── SM2InternalKeyUsageTest.java
│           ├── SM2SignatureTest.java
│           ├── SM2CipherTest.java
│           ├── SM3DigestTest.java
│           ├── SM4CipherTest.java
│           ├── SDFSecureRandomTest.java
│           ├── RSAInternalKeyUsageTest.java
│           ├── RSAInternalKeyCipherTest.java
│           ├── RSAExternalKeyGenTest.java
│           └── RSAFullFeatureTest.java
├── pom.xml                              # Maven 配置
├── run.sh                               # Linux/macOS 运行脚本
├── run.bat                              # Windows 运行脚本
├── keystore.jks                         # JAR 签名密钥库
└── README.md                            # 项目说明
```

## 构建与运行

### 常用开发命令

```bash
# 清理构建
mvn clean

# 仅编译，不运行测试
mvn clean compile

# 打包（跳过测试）
mvn package -DskipTests

# 完整构建（编译+测试+打包）
mvn clean package

# 运行所有测试
mvn test

# 运行单个测试类
mvn test -Dtest=SM2SignatureTest

# 运行单个测试方法
mvn test -Dtest=SM2SignatureTest#testSign

# 查看依赖树
mvn dependency:tree

# 生成 JavaDoc
mvn javadoc:javadoc
```

### 构建项目

```bash
mvn clean package
```

构建过程会：
1. 编译所有 Java 源代码
2. 将依赖项复制到 `target/lib` 目录
3. 将项目打包成 `target/liuzx-sdf-jce-1.0-SNAPSHOT.jar`
4. 使用 `keystore.jks` 对主 JAR 包进行签名（满足 JCE Provider 安全要求）

### 运行演示程序

**Linux/macOS**:
```bash
chmod +x run.sh
./run.sh
```

**Windows**:
```batch
run.bat
```

### 运行测试

```bash
mvn test
```

注意：默认配置中测试被跳过（`<skipTests>true</skipTests>`），如需运行测试需要修改 `pom.xml`。

## 配置说明

### SDF 动态库配置 (`sdf-config.json`)

位于 `src/main/resources/sdf-config.json`，用于配置不同厂商和平台的 SDF 动态库路径：

```json
{
  "defaultVendor": "Dysx",
  "vendors": {
    "Dysx": {
      "platforms": {
        "linux": {
          "x86_64": "/usr/local/lib/sdfso/libsdf_crypto.so",
          "aarch64": "/home/gemotech/soft/libsdf/libsdf.so"
        },
        "windows": {
          "x86_64": "C:/Sansec/windows_x86_64/sdf.dll"
        },
        "macos": {
          "x86_64": "/opt/sansec/macos_x86_64/libsdf.dylib",
          "aarch64": "/opt/sansec/macos_aarch64/libsdf.dylib"
        }
      }
    }
  }
}
```

- `defaultVendor`: 默认使用的厂商配置
- `vendors`: 支持多个厂商配置
- `platforms`: 根据操作系统和 CPU 架构定义动态库路径

### 日志配置 (`liuzx-jce.properties`)

位于 `src/main/resources/liuzx-jce.properties`：

```properties
# 全局启用或禁用日志
log.enabled=true

# 日志级别: DEBUG, INFO, WARN, ERROR
log.level=INFO

# 日志文件路径，支持 %d{yyyy-MM-dd} 格式进行每日轮转
log.file=liuzx-jce.log
```

## 使用示例

### 注册 Provider

```java
import org.liuzx.jce.provider.LiuZXProvider;
import java.security.Security;

// 动态注册 Provider
Security.addProvider(new LiuZXProvider());
```

### SM2 签名示例

```java
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.Signature;

// 生成 SM2 密钥对
KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", "liuzx");
kpg.initialize(256);
KeyPair keyPair = kpg.generateKeyPair();

// 签名
Signature signer = Signature.getInstance("SM3withSM2", "liuzx");
signer.initSign(keyPair.getPrivate());
signer.update("Hello, World!".getBytes());
byte[] signature = signer.sign();

// 验签
Signature verifier = Signature.getInstance("SM3withSM2", "liuzx");
verifier.initVerify(keyPair.getPublic());
verifier.update("Hello, World!".getBytes());
boolean result = verifier.verify(signature);
```

### 使用内部密钥（硬件密钥）

```java
import org.liuzx.jce.provider.asymmetric.sm2.SM2InternalKeyGenParameterSpec;

// 加载内部密钥（密钥索引为 1）
KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", "liuzx");
kpg.initialize(new SM2InternalKeyGenParameterSpec(1, SM2InternalKeyGenParameterSpec.KeyType.SIGN));
KeyPair keyPairRef = kpg.generateKeyPair();

// 使用内部密钥进行签名
Signature signer = Signature.getInstance("SM3withSM2", "liuzx");
signer.initSign(keyPairRef.getPrivate()); // 私钥永不离开硬件
signer.update("Hello, World!".getBytes());
byte[] signature = signer.sign();
```

### SM4 加密示例

```java
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

// 生成 SM4 密钥
KeyGenerator kg = KeyGenerator.getInstance("SM4", "liuzx");
kg.init(128);
SecretKey secretKey = kg.generateKey();

// CBC 模式加密
byte[] iv = new byte[16];
SecureRandom.getInstance("SDF", "liuzx").nextBytes(iv);
IvParameterSpec ivSpec = new IvParameterSpec(iv);

Cipher cipher = Cipher.getInstance("SM4/CBC/PKCS5Padding", "liuzx");
cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
byte[] ciphertext = cipher.doFinal("Hello, World!".getBytes());

// 解密
cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
byte[] plaintext = cipher.doFinal(ciphertext);
```

### RSA 加密示例

```java
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import javax.crypto.Cipher;

// 生成 RSA 密钥对
KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "liuzx");
kpg.initialize(2048);
KeyPair keyPair = kpg.generateKeyPair();

// 加密
Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "liuzx");
cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
byte[] ciphertext = cipher.doFinal("Hello, World!".getBytes());

// 解密
cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
byte[] plaintext = cipher.doFinal(ciphertext);
```

## 开发规范

### 代码风格

- 遵循标准 Java 编码规范
- 使用 4 空格缩进
- 类名使用大驼峰命名法（PascalCase）
- 方法名和变量名使用小驼峰命名法（camelCase）
- 常量使用全大写下划线分隔（UPPER_SNAKE_CASE）

### 测试规范

- 使用 JUnit 5 进行单元测试
- 测试类命名以 `Test` 结尾
- 测试方法使用 `@DisplayName` 注解提供清晰的描述
- 重要测试需要验证输入输出是否匹配

### 提交规范

- 提交信息使用中文，简洁明了
- 每次提交只包含一个逻辑变更
- 提交前确保代码可以正常构建

### 文件修改注意事项

- 修改 Provider 核心类（如 `LiuZXProvider.java`）时需要确保所有服务注册正确
- 修改 JNA 接口定义（`SDFLibrary.java`）时需要与底层 C 库保持一致
- 修改配置文件（`sdf-config.json`）时需要确保路径正确

### 添加新算法时的修改清单

1. 在 `LiuZXProvider.java` 的 `populateServices()` 方法中注册服务（使用 `putService()`）
2. 在对应包下实现 SPI 类（继承对应的 SPI 基类，如 `SignatureSpi`、`CipherSpi` 等）
3. 如需要支持密钥参数规范，在包路径下添加对应的 `XXXGenParameterSpec` 类
4. 如需支持内部密钥，添加对应的 `InternalKeyGenParameterSpec` 类
5. 添加对应的单元测试类
6. 如需国际化支持，在 `i18n/` 目录下添加对应语言的配置

## 关键类说明

### Provider 核心

- `LiuZXProvider`: JCE Provider 主类，注册所有密码学服务
- `SDFConfig`: 配置管理，读取 `sdf-config.json` 并管理多平台库路径
- `SDFSessionManager`: 会话管理，管理设备连接和会话生命周期

### JNA 接口

- `SDFLibrary`: SDF 接口定义，使用 JNA 调用底层 C 函数
- `structure/*`: SDF 数据结构定义（密钥、签名、密文等）

### 算法实现

**SM2**:
- `SM2KeyPairGenerator`: SM2 密钥对生成器
- `SM2SignatureSpi`: SM2 签名实现
- `SM2CipherSpi`: SM2 加密实现
- `SM2PublicKey` / `SM2PrivateKey`: SM2 密钥类

**RSA**:
- `RSAKeyPairGeneratorSpi`: RSA 密钥对生成器
- `RSASignatureSpi`: RSA 签名实现
- `RSACipherSpi`: RSA 加密实现
- `SDFRSAPrivateKey`: RSA 私钥类（支持内部密钥）

**SM3**:
- `SM3Digest`: SM3 摘要实现

**SM4**:
- `SM4KeyGenerator`: SM4 密钥生成器
- `SM4CipherSpi`: SM4 加密实现

### 工具类

- `ASN1Util`: ASN.1 编码/解码工具
- `SM3Util`: SM3 摘要工具
- `LiuzxProviderLogger`: 日志工具

## 常见问题

### 1. 找不到 SDF 动态库

**问题**: 运行时报错找不到库文件

**解决方案**:
- 检查 `sdf-config.json` 中配置的路径是否正确
- 确认当前操作系统和 CPU 架构与配置匹配
- 验证库文件是否存在且具有执行权限

### 2. Provider 注册失败

**问题**: `Security.addProvider()` 抛出异常

**解决方案**:
- 确认 JAR 包已正确签名
- 检查 `keystore.jks` 文件是否存在
- 验证密码配置是否正确（默认：`123456`）

### 3. 内部密钥访问失败

**问题**: 使用内部密钥时报错

**解决方案**:
- 确认密钥索引正确
- 检查是否需要密码访问
- 验证密钥类型（签名/加密）是否匹配

### 4. 性能问题

**问题**: 密码运算速度慢

**解决方案**:
- 使用内部密钥而非外部密钥（内部密钥运算在硬件完成）
- 优化会话管理，避免频繁打开/关闭设备
- 考虑使用批量操作减少通信开销

## 性能测试

项目提供了压力测试工具，可用于测试内部密钥签名和外部密钥对生成的性能：

### 内部密钥签名压力测试

```bash
./run.sh stress <线程数> <持续时间(秒)> <密钥索引> [密码]
```

示例：
```bash
./run.sh stress 10 60 1 mypassword
```

### 密钥对生成压力测试

通过演示程序菜单选项 9 运行。

## 许可证

项目未明确声明许可证，请联系项目维护者获取使用许可。

## 联系方式

- 项目地址: git@github.com:liuzhenxin/liuzx-sdf-jce.git
- 维护者: liuzhenxin