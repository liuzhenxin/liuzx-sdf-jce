# 🚀 还在为 Java 对接密码机发愁？试试这款符合标准的高性能国密 JCE Provider！

在日常的金融、政务及企业级信息安全开发中，我们经常需要让 Java 应用与硬件密码设备（如加密机、UKey）进行交互，以满足合规性要求并确保密钥的绝对安全。然而，面对底层的 **GM/T 0018-2012《密码设备应用接口规范》（SDF 接口）**，开发者往往需要自己手写 JNA/JNI 封装，不仅开发成本高，而且极易踩坑。

今天，给大家推荐一个能够完美解决这一痛点的开源利器——**`liuzx-sdf-jce`**！

## 🌟 项目简介

**`liuzx-sdf-jce`** 是一个基于 GM/T 0018-2012 标准实现的 Java JCE (Java Cryptography Extension) Provider。它巧妙地将底层的 SDF 接口桥接到了 Java 开发者最熟悉的 JCE 标准 API 上。

这意味着，**你不需要学习复杂的密码机底层指令，只需像平时使用普通 Java 加密库一样，就能直接驱动硬件密码设备！**

## ✨ 核心亮点，为什么选择它？

### 1. 🛡️ 完全拥抱 JCE 标准，零学习成本
通过 `Security.addProvider()` 动态注册后，你可以直接使用 `KeyPairGenerator`、`Signature`、`Cipher` 等原生 Java API。你的业务代码无需感知底层硬件的存在，极大降低了系统耦合度。

### 2. 🇨🇳 全面支持国密算法（及国际算法）
- **SM2**: 支持内部（硬件）/外部密钥对的签名、验签、加密、解密。
- **SM3**: 高效的消息摘要计算。
- **SM4**: 支持 ECB 和 CBC 模式的对称加解密。
- **RSA**: 支持硬件内部密钥的运算及外部密钥对的生成。

### 3. 🔐 真正的“密钥不落地”
支持直接使用存储在密码设备内部的硬件密钥对进行密码运算，**私钥永不离开硬件**，满足最高等级的安全审计要求。

### 4. 💻 极佳的跨平台与跨架构兼容性
无论是部署在 **Linux、Windows 还是 macOS** 上，无论是传统的 **x86_64** 还是当下流行的 **aarch64 (ARM)** 架构，一套代码，随处运行！内置灵活的 `sdf-config.json` 配置体系，轻松适配各大厂商的 SDF 动态库。

### 5. ⚡ 生产级可用保障
- **内置压测工具**：自带多线程压力测试程序，性能瓶颈一测便知。
- **轻量级日志**：内置无第三方依赖的日志系统，支持按日轮转，排查问题更省心。
- **国际化支持**：多语言无缝切换。

## 👨‍💻 代码演示：看看它有多简单！

想要用硬件里的 **SM2 内部密钥** 对数据进行签名？只需短短几行代码：

```java
import org.liuzx.jce.provider.LiuZXProvider;
import org.liuzx.jce.provider.asymmetric.sm2.SM2InternalKeyGenParameterSpec;
import java.security.*;

// 1. 动态注册 Provider
Security.addProvider(new LiuZXProvider());

// 2. 加载硬件内部密钥（例如索引为 1 的签名密钥）
KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", "liuzx");
kpg.initialize(new SM2InternalKeyGenParameterSpec(1, SM2InternalKeyGenParameterSpec.KeyType.SIGN));
KeyPair keyPairRef = kpg.generateKeyPair();

// 3. 使用硬件密钥进行签名（私钥运算全在加密机内完成）
Signature signer = Signature.getInstance("SM3withSM2", "liuzx");
signer.initSign(keyPairRef.getPrivate());
signer.update("Hello, SDF!".getBytes());
byte[] signature = signer.sign();

System.out.println("签名成功！");
```

没有任何晦涩的底层调用，一切都符合 Java 开发者的直觉！

## 🎯 适用场景
- **政务/金融系统**：需要对接加密机进行国密改造的项目。
- **物联网/客户端**：需要调用 UKey 进行身份认证和数据加密的桌面程序。
- **中间件开发**：需要为上层应用提供统一且符合标准的密码学服务。

## 🔗 获取与体验

项目代码结构清晰，严格遵循 Java 编码规范，并提供了完善的单元测试（JUnit 5），非常适合作为学习 JNA 与底层交互、或是深入理解 JCE 架构的参考。

还在等什么？赶紧把这把“国密神兵”收入囊中吧！

👉 **项目主页 / 获取源码：**
https://github.com/liuzhenxin/liuzx-sdf-jce
*(如果觉得项目对您有帮助，别忘了点个 Star ⭐️ 支持一下作者哦！)*

---
**[互动话题]**
你在做国密改造或对接密码机时遇到过哪些“坑”？欢迎在评论区留言交流！