# 发布到 Maven Central 操作清单

本文档描述将 `liuzx-sdf-jce` 发布到 Sonatype **Maven Central Portal** 的完整步骤。

发布命令：`mvn clean deploy -Prelease,gpg-signing -DskipTests=true`

代码侧已就绪：`pom.xml` 已配好 Central 元数据（licenses/scm/developers 等）、主 jar 已去掉 manifest Class-Path，并新增了 `release` profile（sources / javadoc / gpg / central-publishing 插件）。以下是需要手动完成的操作。

## 0. 前提

- 域名 `liuzx.org` 已注册（Cloudflare Registrar），DNS 由 Cloudflare 托管，注册人联系人信息已填全。
- `pom.xml` 中 `<developers><developer><email>` 目前是占位符 `you@example.com`，先改成你的真实邮箱。
- 构建机上有 `keystore.jks`（本地 JCE 签名用；被 gitignore，不在仓库里，CI 需额外注入）。

## 1. 注册 Central Portal 账号并验证命名空间

1. 打开 https://central.sonatype.com ，用常用邮箱注册并登录。
2. 申请命名空间 **`org.liuzx`**（Publish → Namespaces → Add Namespace）。
3. Portal 会要求验证域名所有权，给出一条 **DNS TXT 记录值**。
4. 到 Cloudflare DNS 添加 TXT 记录：
   - dash.cloudflare.com → `liuzx.org` → **DNS → Records → Add record**
   - 类型 `TXT`；Name 按 Portal 提示（通常 `@` 或它指定的子域）；Value 填 Portal 给的代码；TTL 用 Auto。
5. 等生效（几分钟到几小时），本机验证：
   ```bash
   dig TXT liuzx.org
   # 或
   nslookup -type=TXT liuzx.org
   ```
6. 回 Portal 点「验证」。**未验证前发布会被拒绝。**

## 2. 生成 GPG 密钥并上传公钥

```bash
gpg --full-generate-key      # 选 RSA 4096，填名字/邮箱并设置口令
gpg --list-secret-keys --keyid-format=long   # 记下 KEYID（sec rsa4096/<KEYID> 里的十六进制串）
gpg --keyserver keys.openpgp.org --send-keys <KEYID>
```

- keys.openpgp.org 会向密钥里的邮箱发**验证邮件**，确认后才可被检索。不便的话改用：
  `gpg --keyserver keyserver.ubuntu.com --send-keys <KEYID>`
- 发布时 Central 要从公共 keyserver 取到公钥验签，务必确认可检索：
  ```bash
  gpg --keyserver keys.openpgp.org --recv-keys <KEYID>
  ```

## 3. 配置 `~/.m2/settings.xml`

1. 在 Central Portal：右上角头像 → **User Token** → 生成，得到一组 username / password。
2. 编辑 `~/.m2/settings.xml`（没有则新建）：
   ```xml
   <settings xmlns="http://maven.apache.org/SETTINGS/1.2.0"
             xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
             xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.2.0 https://maven.apache.org/xsd/settings-1.2.0.xsd">

     <servers>
       <server>
         <id>central</id>
         <username>你的UserToken用户名</username>
         <password>你的UserToken密码</password>
       </server>
     </servers>

     <profiles>
       <profile>
         <id>gpg-signing</id>
         <properties>
           <gpg.keyname>你的GPG KEYID</gpg.keyname>
           <gpg.passphrase>你的GPG口令</gpg.passphrase>
         </properties>
       </profile>
     </profiles>
   </settings>
   ```
   - `<server id="central">` 必须与 pom release profile 里的 `publishingServerId` 一致。
   - `<profile>` 无 activation 即常驻生效，`${gpg.keyname}` / `${gpg.passphrase}` 自动注入。
3. 安全提示：
   - 该文件含口令，**不要提交到任何仓库**。
   - 更安全的方式：settings.xml 不写 `gpg.passphrase`，改用 gpg-agent 缓存口令（首次发布时弹窗输入），pom 里已带 `--pinentry-mode loopback`。
4. 本地确认 profile 生效（不真正发布）：
   ```bash
   mvn help:effective-pom -Prelease,gpg-signing | grep -A3 "gpg-plugin"
   ```

## 4. 发布

> **推荐：一键脚本**（完成打包 → 发布 → 打 tag → 升级到下一个 `-SNAPSHOT`）
>
> ```bash
> ./release.sh                        # 用 pom.xml 当前版本（须非 SNAPSHOT）发布
> ./release.sh --version 1.2.0        # 先改版本为 1.2.0 再发布（当前是 -SNAPSHOT 时也用此参数）
> ./release.sh --update-docs          # 同步更新 README.md / index.html 版本号与产物名
> ./release.sh --with-tests           # 打包/发布时运行单元测试（需真实 SDF 硬件）
> ./release.sh --dry-run              # 演练：只打印将执行的命令
> ./release.sh --push                 # 发布成功后推送提交与 tag 到 origin
> ```
>
> 脚本会：预检（settings.xml / tag 冲突）→ `mvn clean package` → `mvn clean deploy -Prelease,gpg-signing -DskipTests=true` →
> 提交 `chore(release): 发布 X.Y.Z 到 Maven Central` 并打 `vX.Y.Z` tag → pom 改为 `X.Y.(Z+1)-SNAPSHOT` 并提交。
> 以下手动步骤保留作参考/排错使用。

### 4.1 手动方式

1. 把 `pom.xml` 版本改为**非 SNAPSHOT**（Central 拒收 SNAPSHOT）：
   ```bash
   sed -i '' 's|<version>1.1.0-SNAPSHOT</version>|<version>1.1.0</version>|' pom.xml
   ```
2. 执行发布：
   ```bash
   mvn clean deploy -Prelease,gpg-signing -DskipTests=true
   ```
   - **必须带 `-Prelease,gpg-signing`**：`release` 生成并发布 sources/javadoc/GPG 产物，`gpg-signing` 从本机 Maven settings 注入签名凭据。
   - 测试依赖真实 SDF 硬件，发布时保持 skipTests（pom 已默认 true）。
   - 发布产物 = JCE 签名的瘦 jar + sources + javadoc + 各自的 `.asc` + 签名后的 `.pom`。
3. `autoPublish=true`：校验通过后 Central 自动发布。在 central.sonatype.com → Publish 页观察进度；成功后几分钟内可在 https://repo1.maven.org/maven2/org/liuzx/ 看到。
4. 发布成功，把版本改回开发版本：
   ```bash
   sed -i '' 's|<version>1.1.0</version>|<version>1.1.1-SNAPSHOT</version>|' pom.xml
   ```
5. （可选）提交发布并打 tag：
   ```bash
   git add pom.xml && git commit -m "chore(release): 发布 1.1.0 到 Maven Central"
   git tag v1.1.0
   sed -i '' 's|<version>1.1.0</version>|<version>1.1.1-SNAPSHOT</version>|' pom.xml
   git add pom.xml && git commit -m "chore(release): 回到 1.1.1-SNAPSHOT"
   ```

## 常见问题

| 现象 | 原因 / 处理 |
|---|---|
| 报 401 / 凭证无效 | User Token 填错，或 server id 不是 `central` |
| 报命名空间未验证 | `org.liuzx` 的 DNS TXT 未通过，回 Portal 确认 |
| GPG 找不到密钥 / 签名失败 | `gpg.keyname` 未用 KEYID；或 gpg-agent 未缓存口令 |
| javadoc 报错中断 | release profile 已配 `doclint=none`，仍报错则看具体错误（多为源码注释问题） |
| `mvn deploy` 提示无 distributionManagement | 忘了加 `-Prelease` |
| GPG 显示 `key default` 或等待输入 | 忘了启用 settings 中的 `gpg-signing` profile，或当前进程无权访问 `~/.gnupg` |
| 发布失败被拒 | 检查 Portal 上校验报告，通常是元数据/签名问题，修正后重新 deploy |

## 附：本地运行（不发布）

```bash
mvn clean package
./run.sh        # Linux/macOS
run.bat         # Windows
```

主 jar manifest 已不含 Class-Path，本地 demo 用 `-cp target/liuzx-sdf-jce-<版本>.jar:target/lib/*` 启动（run.sh/run.bat 已内置此方式）。Java 项目引用见 `README.md`「通过 Maven 引入」。
