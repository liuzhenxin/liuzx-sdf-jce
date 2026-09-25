# JCE 签名密钥库生成与轮换

本库的 JCE Provider 要求**主 JAR 及其依赖 JAR（JNA/Gson）由同一签名者签名**，否则运行时
`Cipher` / `KeyGenerator` / `Mac` / `SecureRandom` 会抛
`JCE cannot authenticate the provider LiuZX`。因此签名密钥库属于发布关键资产。

- 密钥库文件：`keystore.jks`（位于项目根，**已被 `.gitignore` 忽略，绝不入库**）
- 别名：`dayou`（可用 `-Djce.keystore.alias` 覆盖）
- 口令：**绝不写入 `pom.xml`**，由 `~/.m2/settings.xml` 的 `jce-signing` profile 注入

---

## 1. 强口令要求

- 长度 ≥ 20 字符，随机生成（可用 `openssl rand -base64 24`）
- 不得复用其他系统的口令，不得出现在任何脚本、CI 变量明文、聊天记录中
- `jce.storepass` 与 `jce.keypass` 可以使用同一强口令，也可分别设置

> 旧版本曾使用已被公开的弱口令。如仍在使用，请立即按本文件轮换。

## 2. 生成新密钥库

```bash
# 在项目根执行（如已有旧库，先备份：mv keystore.jks keystore.jks.bak）
keytool -genkeypair \
  -alias dayou \
  -keyalg RSA -keysize 4096 -sigalg SHA256withRSA \
  -validity 3650 -storetype JKS \
  -keystore keystore.jks \
  -dname "CN=LiuZX JCE Signing, OU=JCE, O=liuzx.org, L=Beijing, ST=Beijing, C=CN"
```

`keytool` 会提示设置 **keystore password** 与 **key password**，请输入强口令。

## 3. 配置 `~/.m2/settings.xml`

添加或更新常驻 profile（无 activation，自动生效）：

```xml
<profile>
  <id>jce-signing</id>
  <properties>
    <jce.storepass>你的强口令</jce.storepass>
    <jce.keypass>你的强口令</jce.keypass>
  </properties>
</profile>
```

可选覆盖（非敏感，默认值见 `pom.xml`）：

```xml
<jce.keystore>/absolute/path/to/keystore.jks</jce.keystore>
<jce.keystore.alias>dayou</jce.keystore.alias>
<jce.tsa>http://timestamp.sectigo.com</jce.tsa>
```

CI 环境可用 `-Djce.storepass=... -Djce.keypass=...`，但请注意 `-D` 会出现在进程命令行中；
更安全的做法是让 CI 注入 `settings.xml` 或使用密钥管理服务。

## 4. 轮换步骤（清单）

1. **备份**旧库：`mv keystore.jks keystore.jks.bak-$(date +%Y%m%d)`
2. **生成**新库（见 §2），使用新的强口令
3. **更新** `~/.m2/settings.xml` 的 `jce-signing` 口令（见 §3）
4. **验证打包**：`mvn clean package -DskipTests`
5. **验证签名**：
   ```bash
   jarsigner -verify target/liuzx-sdf-jce-*.jar
   jarsigner -verify target/lib/jna-5.10.0.jar
   jarsigner -verify target/lib/gson-2.9.0.jar
   ```
   三者均须输出 `jar 已验证`。
6. **验证 JCE 认证**：运行一次受限 JCE 运算（`KeyGenerator.getInstance("SM4","LiuZX")` 或
   `Cipher.getInstance("SM4/CBC/PKCS5Padding","LiuZX")` 的算法解析），不得出现
   `JCE cannot authenticate the provider LiuZX`。
7. **弃用旧库**：确认新库可用后，安全删除 `keystore.jks.bak-*`（或归档到密钥管理设施）
8. **发布**：按 `RELEASE.md` 发布下一个正式版本

## 5. 注意事项

- `keystore.jks`、`keystore.jks.bak-*` 与任何口令**都不得提交**到版本库（`.gitignore` 已覆盖 `*.jks`）。
- 轮换后新版本的签名者与旧版本不同；**已发布**的旧版本产物不受影响，使用者无需处理。
- 缺少 `jce.storepass` / `jce.keypass` 时，`mvn package` 会在 `package` 阶段被
  `maven-enforcer-plugin` 拦截并提示配置 `jce-signing`。
- TSA（时间戳）不可达时构建会失败；`jce.tsa` 可覆盖为其他 RFC 3161 时间戳服务。
