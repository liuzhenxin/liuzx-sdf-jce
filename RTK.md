# RTK.md - liuzx-sdf-jce

## 1. 项目用途

`liuzx-sdf-jce` 是基于 GM/T 0018 SDF 接口的 Java JCE Provider，通过 JNA 调用底层密码设备动态库，为 Java 应用提供 SM2、SM3、SM4、RSA、硬件随机数和内部密钥等标准 JCE 能力。

## 2. 目录结构说明

```text
liuzx-sdf-jce/
├── src/main/java/org/liuzx/jce/demo       # 演示和压力测试
├── src/main/java/org/liuzx/jce/jna        # SDF C 接口和结构体
├── src/main/java/org/liuzx/jce/provider   # JCE Provider、算法 SPI、会话管理
├── src/main/resources/sdf-config.json     # SDF 动态库配置
├── src/main/resources/liuzx-jce.properties# 日志配置
├── src/test/java                          # JUnit 测试
├── run.sh / run.bat                       # Demo 启动脚本
└── pom.xml
```

核心调用链：

```text
应用程序 -> JCE API -> Provider SPI -> 会话管理 -> JNA -> SDF 硬件设备
```

## 3. 如何安装依赖

```bash
mvn clean package
```

构建会生成并签名 JAR，同时复制依赖到 `target/lib`。运行前需确认 `sdf-config.json` 中动态库路径、操作系统和 CPU 架构匹配。

## 4. 如何运行项目

Linux/macOS：

```bash
chmod +x run.sh
./run.sh
```

Windows：

```bat
run.bat
```

也可在 Java 代码中通过 `Security.addProvider(new LiuZXProvider())` 注册 Provider。

## 5. 如何测试

```bash
mvn test
mvn test -Dtest=SM2SignatureTest
mvn test -Dtest=SM2SignatureTest#testSign
```

部分测试依赖真实 SDF 动态库和硬件设备。若默认 POM 跳过测试，运行前需确认 Surefire 配置。

## 6. 主要模块说明

- `provider`: JCE Provider 主体和 SM2/SM3/SM4/RSA/SecureRandom SPI。
- `session`: 设备连接和会话复用。
- `jna`: SDF 函数声明、结构体和错误码。
- `demo`: 演示程序、国际化和压力测试。
- `resources`: 动态库路径、日志和 i18n 配置。

## 7. 常见开发注意事项

- 私钥、内部密钥索引、PIN、设备口令和签名密钥库密码不得提交或输出到日志。
- JNA 结构体字段顺序、长度和对齐必须与厂商头文件一致。
- 不随意改变 JCE 算法名称、Provider 注册项或签名 JAR 流程。
- 硬件异常要保留 SDF 错误码映射，便于定位设备侧问题。
