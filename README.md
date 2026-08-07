# LiuZX SDF JCE Provider

📄 **项目介绍页**: [https://liuzhenxin.github.io/liuzx-sdf-jce/](https://liuzhenxin.github.io/liuzx-sdf-jce/)

这是一个基于 **GM/T 0018-2012《密码设备应用接口规范》** 实现的Java JCE Provider。项目旨在提供一个符合标准JCE架构的密码学服务提供者，以便Java应用程序可以通过标准API与支持SDF接口的密码设备（如加密机、UKey等）进行交互。

**注意**: 该项目的核心代码由AI辅助生成，并根据实际的硬件接口规范（`libsdf.h`）和调试结果进行了多次迭代和修正。

---

## ✨ 特性

- **符合JCE标准**: 可通过 `Security.addProvider()` 动态注册，并通过标准JCE API（`Signature`, `Cipher`, `KeyPairGenerator`等）进行调用。
- **国密算法 + RSA/ECDSA/EdDSA/DSA 全面支持**:
  - **SM2**: 内部/外部密钥对的签名、验签、加密、解密，以及 SM2 密钥协商（ECDH）。
  - **SM3**: 消息摘要计算（硬件实现）。
  - **SM4**: **ECB/CBC/CFB/OFB** 四种模式（PKCS5Padding / NoPadding）的加密与解密，支持硬件内部密钥（通过 `SDFSM4Keys.internalKey(index)` 使用），以及 SM4-MAC。
  - **RSA**: 内部/外部密钥对的签名（SHA1/SHA256/SHA512/MD5）、加密、解密。**`RSA/ECB/PKCS1Padding` 为标准 PKCS#1 v1.5 填充**，签名产物与标准 JCE 验签互通。
  - **ECDSA / EdDSA / DSA**: 内部密钥对的签名与验签（`SHA256withECDSA` / `EdDSA` / `SHA1withDSA`）。**注意：实测数盾 SDF 库不导出 `SDF_GenerateKeyPair_ECDSA/EDDSA/DSA` 等函数，这三个算法在数盾设备上不可用**；需使用导出这些函数的厂商库（如 Dysx）。
  - **摘要/HMAC**: SHA-1/SHA-224/SHA-256/SHA-384/SHA-512/MD5（硬件）、HmacSM3/HmacSHA1/HmacSHA256/HmacSHA512。
- **硬件密钥支持**: 支持使用存储在密码设备内部的 SM2/RSA/SM4 密钥进行密码运算，私钥永不离开硬件。
- **数盾 (Shudun) 厂商支持**: 内置数盾 SDF 动态库（Linux x86_64 / Windows x86_64），通过 `classpath:` 机制随 JAR 打包分发，无需手动安装动态库即可使用。**注：数盾 SDF 库按变长布局读写 RSA 结构体**（bits + m[kb] + e[kb] + d[kb] + CRT 子区间），≤2048 位密钥各子区间整体平移，4096 位占满标准 `m[512]/e[512]` 结构；本 Provider 已按该布局适配（转换统一在 `RSAKeyConverter`），支持最大 4096 位。
- **跨平台**: 通过配置文件支持在不同操作系统和CPU架构（Linux/Windows/macOS, x86_64/aarch64）下加载对应的SDF动态库。
- **可配置的日志系统**: 内置一个无第三方依赖的日志系统，支持通过配置文件开关、设置级别和输出路径。
- **国际化**: 演示程序支持中英文切换。
- **性能测试工具**: 内置了针对内部密钥签名和外部密钥对生成的多线程压力测试程序。

---

## 📋 版本说明

**当前版本: 1.1.2**（2026-08-07）

### 1.1.2 (2026-08-07)

- **RSA 结构体合并**：删除 `RSArefPublicKeyEx` / `RSArefPrivateKeyEx`，统一为标准 `RSArefPublicKey`（m[512]/e[512]）与 `RSArefPrivateKey`（m/e/d[512] + CRT[256]），支持最大 4096 位。
- **修正数盾变长 RSA 布局适配**：数盾库将 RSA 结构体按变长布局（bits + m[kb] + e[kb] + d[kb] + prime[2][pb] + coef[pb]）读写，≤2048 位密钥各子区间在 JNA 结构内整体平移。外部加解密、外部密钥生成的 CRT 提取改为按结构体相对偏移定位，修复外部私钥运算失败（错误码 `0x0100000C`）。
- **外部 RSA 密钥支持设备签名**：软件构造 EMSA-PKCS1 v1.5 块，外部密钥走 `SDF_ExternalPrivateKeyOperation_RSA`；抽取 `RSAKeyConverter` 供加解密与签名共用转换逻辑。
- **demo 新增菜单 14**：外部密钥生成 + 签名/验签/加密/解密（2048/4096）。
- 移除 demo 中私钥十六进制日志（遵守安全约束）。
- 设备回归（HSM）：内部签名 idx21/idx11、外部密钥生成、外部加解密往返、外部签名均通过。

### 1.1.1 (2026-08-07)

- **RSA 内部密钥支持 4096 位**：通过外部公钥注入 + Ex 结构体实现，内部私钥不离开硬件。
- **修正数盾内部 SM2 加解密**：JNA 绑定修正，内部密钥 SM2 加密走内部路径，`read()` 同步结构体。
- **测试完善**：内部密钥测试参数化索引与 PIN，修正 SM3 测试向量。

### 1.1.0 (2026-08-07)

- **Provider 主名改为 `LiuZX`**，新增 `LegacyLiuZXProvider` 兼容旧名 `liuzx`。
- **会话池自愈**：HSM 会话失效后自动重建，覆盖 HSM 未就绪错误（`0x01000403`）。
- **修复运行时 JCE 认证失败**：签名 JCE 依赖 jar。
- 配置 Maven Central 发布流程，新增发布清单 `RELEASE.md`。
- 新增 GitHub Pages 项目介绍页。

### 1.0.0 (2026-08-05) — 初始发行

- 基础版本：SM2/SM3/SM4/RSA/ECDSA/EdDSA/DSA、内部/外部密钥、硬件随机数、SM2 密钥协商、多线程压力测试等核心能力。

---

## 🚀 构建与运行

### 1. 构建

本项目使用Apache Maven进行构建。在项目根目录下执行以下命令：

```bash
mvn clean package
```

该命令会完成以下操作：
1. 编译所有Java源代码。
2. 将所有依赖项（如 JNA, Gson）复制到 `target/lib` 目录。
3. 将本项目打包成 `target/liuzx-sdf-jce-1.1.2.jar`。
4. **（重要）** 使用 `keystore.jks` 对主JAR包进行签名，以满足JCE Provider的安全要求。

### 2. 运行演示程序

项目提供了一个可交互的命令行演示程序 `org.liuzx.jce.demo.Main`。

- **Linux / macOS**:
  ```bash
  # 首次运行前，请确保脚本有执行权限
  chmod +x run.sh
  
  ./run.sh
  ```

- **Windows**:
  ```batch
  run.bat
  ```

程序启动后，您可以选择语言，然后根据菜单提示测试各项功能。

---

## ⚙️ 配置

### 1. SDF动态库配置 (`sdf-config.json`)

该文件位于 `src/main/resources` 目录下，用于配置不同厂商、不同平台下的SDF动态库路径。

```json
{
  "defaultVendor": "Dysx",
  "vendors": {
    "Dysx": {
      "platforms": {
        "linux": {
          "aarch64": "/home/gemotech/soft/libsdf/libsdf.so"
        },
        "windows": { ... }
      }
    }
  }
}
```
- **`defaultVendor`**: `run.sh` / `run.bat` 默认使用的厂商配置。
- **`vendors`**: 可以定义多个厂商，每个厂商下根据 `[操作系统]/[CPU架构]` 定义动态库的绝对路径。

运行时可以通过系统属性覆盖默认厂商或动态库路径：

```bash
# 使用 liuzx-nas 工程当前携带的数盾 SDF 动态库
# （主 JAR 不含 Class-Path，依赖放在 target/lib 下，需用 -cp 指定）
java -Dliuzx.sdf.vendor=Shudun \
  -cp target/liuzx-sdf-jce-1.1.2.jar:target/lib/* \
  org.liuzx.jce.demo.Main

# 直接指定某个动态库路径，优先级高于 vendor 配置
java -Dliuzx.sdf.library.path=/usr/lib64/libsdhsmcrypto.so \
  -cp target/liuzx-sdf-jce-1.1.2.jar:target/lib/* \
  org.liuzx.jce.demo.Main
```

`Shudun` 配置的动态库已放在本工程 `src/main/resources/native/shudun/` 下，并会随 JAR 打包。配置使用 `classpath:` 路径，运行时会自动将 JAR 内动态库解压到临时目录后交给 JNA 加载。生产部署也可以使用 `-Dliuzx.sdf.library.path` 显式指定外部固定路径，优先级高于 vendor 配置。

### 2. 日志配置 (`liuzx-jce.properties`)

该文件位于 `src/main/resources` 目录下，用于控制内置的日志系统。

```properties
# 全局启用或禁用日志
log.enabled=true

# 日志级别: DEBUG, INFO, WARN, ERROR
log.level=INFO

# 日志文件路径。支持 %d{yyyy-MM-dd} 格式进行每日轮转
log.file=liuzx-jce.log
```

---

## 💻 使用示例

### 通过 Maven 引入（发布到 Maven Central 后可用）

在 `pom.xml` 中声明依赖即可，`jna`/`gson` 会自动传递解析，无需手动配置：

```xml
<dependency>
    <groupId>org.liuzx</groupId>
    <artifactId>liuzx-sdf-jce</artifactId>
    <version>1.1.2</version>
</dependency>
```

> 注意：本库是**硬件相关**的 JCE Provider，运行时必须连接真实的 SDF 密码设备，
> 并通过 `-Dliuzx.sdf.library.path=<库路径>` 或 `-Dliuzx.sdf.vendor=<厂商>` 指定动态库，
> 或使用 jar 内随包分发的数盾动态库（`classpath:` 方式）。无硬件时仅能注册 Provider，密码运算会失败。

在您的Java项目中，可以像使用任何标准JCE Provider一样使用本库：

```java
import org.liuzx.jce.provider.LiuZXProvider;
import java.security.Security;
import java.security.Signature;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class Example {
    public static void main(String[] args) {
        try {
            // 1. 动态注册Provider（主名 "LiuZX"）
            Security.addProvider(new LiuZXProvider());
            // 如需兼容旧名称 "liuzx"，再注册一个兼容实例：
            // Security.addProvider(new LegacyLiuZXProvider());

            // 2. 通过指定Provider名称来获取服务
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", "LiuZX");
            kpg.initialize(256);
            KeyPair keyPair = kpg.generateKeyPair();

            // 3. 执行签名
            Signature signer = Signature.getInstance("SM3withSM2", "LiuZX");
            signer.initSign(keyPair.getPrivate());
            signer.update("Hello, World!".getBytes());
            byte[] signature = signer.sign();

            System.out.println("Signature generated successfully!");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

### 使用密码机内部 SM4 密钥

如需兼容 `liuzx-nas` 中“密钥在密码机内部，只通过 keyIndex 使用”的 SM4/CBC/PKCS5Padding 场景，可以使用 `SDFSM4InternalKey`：

```java
import org.liuzx.jce.provider.LiuZXProvider;
import org.liuzx.jce.provider.symmetric.SDFSM4Keys;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.Security;

Security.addProvider(new LiuZXProvider());

byte[] iv = "axD8q65LvioMjbNG".getBytes("UTF-8");
SecretKey key = SDFSM4Keys.internalKey(1);

Cipher cipher = Cipher.getInstance("SM4/CBC/PKCS5Padding", "LiuZX");
cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
byte[] encrypted = cipher.doFinal(plainBytes);

cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
byte[] decrypted = cipher.doFinal(encrypted);
```

`SDFSM4InternalKey` 不返回 `getEncoded()` 明文密钥。Provider 初始化时会通过 SDF 内部 KEK 索引导入会话密钥句柄，然后调用 `SDF_Encrypt` / `SDF_Decrypt` 完成运算。

### 使用 RSA 内部密钥签名

通过 `RSAInternalKeyGenParameterSpec` 加载硬件中的 RSA 内部密钥，并使用 `SDFRSAPrivateKey` 进行签名运算：

```java
import org.liuzx.jce.provider.LiuZXProvider;
import org.liuzx.jce.provider.asymmetric.rsa.RSAInternalKeyGenParameterSpec;
import org.liuzx.jce.provider.asymmetric.rsa.SDFRSAPrivateKey;
import java.security.*;

Security.addProvider(new LiuZXProvider());

// 1. 加载硬件中的 RSA 内部密钥（例如索引为 1）
KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "LiuZX");
kpg.initialize(new RSAInternalKeyGenParameterSpec(1));
KeyPair keyPairRef = kpg.generateKeyPair();

// 2. 构建带密码的私钥对象
RSAPublicKey rsaPubKey = (RSAPublicKey) keyPairRef.getPublic();
PrivateKey privateKey = new SDFRSAPrivateKey(1, password, rsaPubKey);

// 3. 使用硬件密钥签名
Signature signer = Signature.getInstance("SHA256withRSA", "LiuZX");
signer.initSign(privateKey);
signer.update("Hello, RSA!".getBytes());
byte[] signature = signer.sign();

// 4. 使用标准 Java 公钥验签
Signature verifier = Signature.getInstance("SHA256withRSA", "LiuZX");
verifier.initVerify(rsaPubKey);
verifier.update("Hello, RSA!".getBytes());
boolean ok = verifier.verify(signature);
```

### 使用 RSA 外部密钥加解密

```java
import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

// 1. 生成 RSA 外部密钥对
KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "LiuZX");
kpg.initialize(2048);
KeyPair keyPair = kpg.generateKeyPair();

// 2. 公钥加密
Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "LiuZX");
cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
byte[] encrypted = cipher.doFinal("Hello, RSA!".getBytes());

// 3. 私钥解密
cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
byte[] decrypted = cipher.doFinal(encrypted);
```
