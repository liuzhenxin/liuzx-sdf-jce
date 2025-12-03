# LiuZX SDF JCE Provider

这是一个基于 **GM/T 0018-2012《密码设备应用接口规范》** 实现的Java JCE Provider。项目旨在提供一个符合标准JCE架构的密码学服务提供者，以便Java应用程序可以通过标准API与支持SDF接口的密码设备（如加密机、UKey等）进行交互。

**注意**: 该项目的核心代码由AI辅助生成，并根据实际的硬件接口规范（`libsdf.h`）和调试结果进行了多次迭代和修正。

---

## ✨ 特性

- **符合JCE标准**: 可通过 `Security.addProvider()` 动态注册，并通过标准JCE API（`Signature`, `Cipher`, `KeyPairGenerator`等）进行调用。
- **国密算法支持**:
  - **SM2**: 内部/外部密钥对的签名、验签、加密、解密。
  - **SM3**: 消息摘要计算。
  - **SM4**: ECB和CBC模式的加密与解密。
- **硬件密钥支持**: 支持使用存储在密码设备内部的密钥对进行密码运算，私钥永不离开硬件。
- **跨平台**: 通过配置文件支持在不同操作系统和CPU架构（Linux/Windows/macOS, x86_64/aarch64）下加载对应的SDF动态库。
- **可配置的日志系统**: 内置一个无第三方依赖的日志系统，支持通过配置文件开关、设置级别和输出路径。
- **国际化**: 演示程序支持中英文切换。
- **性能测试工具**: 内置了针对内部密钥签名和外部密钥对生成的多线程压力测试程序。

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
3. 将本项目打包成 `target/liuzx-sdf-jce-1.0-SNAPSHOT.jar`。
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

在您的Java项目中，可以像使用任何标准JCE Provider一样使用本库。

```java
import org.liuzx.jce.provider.LiuZXProvider;
import java.security.Security;
import java.security.Signature;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class Example {
    public static void main(String[] args) {
        try {
            // 1. 动态注册Provider
            Security.addProvider(new LiuZXProvider());

            // 2. 通过指定Provider名称来获取服务
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", "liuzx");
            kpg.initialize(256);
            KeyPair keyPair = kpg.generateKeyPair();

            // 3. 执行签名
            Signature signer = Signature.getInstance("SM3withSM2", "liuzx");
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
