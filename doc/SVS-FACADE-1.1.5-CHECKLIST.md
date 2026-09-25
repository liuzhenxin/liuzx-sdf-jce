# SVS 消费方 façade 需求 — 1.1.5

**状态**：待实施（`liuzx-svs` Phase 2 的外部阻塞项）
**来源**：本文档为 `liuzx-svs` 仓库 `doc/integration/liuzx-sdf-jce-1.1.5-facade-spec.md` 的副本
**消费方**：`liuzx-svs` Phase 2 适配层（`ProviderCryptoBridge` 接缝）
**依据**：对已发布 `org.liuzx:liuzx-sdf-jce:1.1.4` 的接口勘察，以及本仓库 1.1.5-SNAPSHOT 源码

> 修改该需求时请同时更新两个仓库的副本，避免漂移。消费方门禁测试为
> `liuzx-svs` 的 `DeviceDependencyContractTest`。

---

## 实施清单

- [x] 新增稳定公开包 `org.liuzx.jce.api`（仅 JDK 类型，不含 JNA / Spring / Jackson）
- [x] `SdfErrorCategory` 枚举，与 SVS 九类稳定分类 1:1 对应
- [x] `SdfException`，携带分类 + 仅十六进制码的 `internalDetail`
- [x] `SdfDeviceInfo` record，含 `toSafeString()`，**不含**序列号访问器
- [x] `SdfCapabilities` record，公开 `sm2DefaultUserId` 与会话池状态
- [x] `SdfDevice` 接口：`deviceInfo` / `capabilities` / `exportSignPublicKey` / `signSm2` / `signSm2Digest` / `signRsa` / `close`
- [x] `SdfDevices` 入口工厂，调用方无需提供 `SDFLibrary`、`Pointer` 或会话句柄
- [x] `exportSignPublicKey(int)` 返回 X.509 SubjectPublicKeyInfo（**解除阻塞的关键项**）
- [x] `signSm2Digest` 直接把入参作为 `e` 交给 `SDF_InternalSign_ECC`，**不得**再次哈希
- [x] `SM2SignatureSpi.DEFAULT_USER_ID` 提取为可读取值并进入 `SdfCapabilities`
- [x] 私钥访问权按需申请、`finally` 释放；**不得**按会话或按索引缓存 PIN
- [x] 反射审计：`org.liuzx.jce.api` 公开签名不出现 JNA / `Path` / `File` / `Pointer` / `PrivateKey`
- [x] 真机验证：`signSm2` / `signSm2Digest` / `signRsa` 输出可被独立软件验签器验证通过
- [x] 发布 1.1.5，并确认 `liuzx-svs` 的 `DeviceDependencyContractTest` 通过 — 1.1.5 已发布（deployment `f3f7714d-3fd8-4ab6-87c1-6b5e8636b68d`），正式 1.1.5 契约测试 7/7 通过

> 注：`SdfDeviceInfo` / `SdfCapabilities` 按已批准的方案 B 实现为 Java 8 兼容的不可变 final 类
> （公开访问器契约与 record 等价，不含 `record` 关键字）。SVS 契约测试不要求 record。

---

## 1. 为什么需要

SVS 的适配层通过一个 `ProviderCryptoBridge` 接缝与 Provider 交互，并且**禁止**触碰两样东西：

- `SDFSessionManager.getInstance().getSdfLibrary()` —— JNA 逃生口
- `org.liuzx.jce.jna..` 下的任何类型

勘察结论（1.1.4）：

```text
org.liuzx.jce.jna.SDFLibrary: SDF_ExportSignPublicKey_RSA(Pointer, int, RSArefPublicKey$ByReference)
org.liuzx.jce.jna.SDFLibrary: SDF_ExportSignPublicKey_ECC(Pointer, int, ECCrefPublicKey$ByReference)
```

导出内部密钥公钥的**唯一**路径就是这个 JNA 接口，而内部密钥签名对象又必须携带公钥：

```java
public SM2PrivateKey(int, char[], ECCrefPublicKey)   // 必须 JNA 结构
public SDFRSAPrivateKey(int, char[], RSAPublicKey)   // 标准类型，但仍须先导出公钥
```

因此在 1.1.5 之前，真机签名链路无法在不破坏安全边界的前提下走通。本规格即为解除该阻塞的最小改动。

## 2. 已具备、无需改动

以下 1.1.4 公开入口已是纯 Java 签名，可直接满足 SVS 依赖：

| 能力 | 入口 |
|---|---|
| 设备信息与算法能力位 | `org.liuzx.jce.provider.util.DeviceInfoUtil.getDeviceInfo()` |
| 会话池容量/占用/签出超时 | `SDFSessionManager.getPoolSize()/getAvailableSessionCount()/getBorrowTimeoutMillis()` |
| 独占会话签出 | `SDFSessionManager.borrowSession()` |
| 按需私钥访问权 | `SDFSessionManager.getPrivateKeyAccessRight(session, keyIndex, char[])` |
| 厂商错误码 | `SDFException.getErrorCode()/getFunctionName()/getErrorDescription(int)` |
| Profile / 库路径 / RSA 布局 / 平台 | `org.liuzx.jce.provider.SDFConfig` |

Provider 侧**不需要**重构这些内部实现，只需在新的稳定公开包中暴露一个窄 façade。

## 3. 新增公开包

```text
org.liuzx.jce.api          ← 新增，稳定公开包
```

硬性约束：

- 只使用 JDK 类型；**不得**出现 `org.liuzx.jce.jna..`、`com.sun.jna..`、`java.nio.file.Path`、`java.io.File`
- 不依赖 Spring、Jackson 或任何框架
- 所有类型不可变；集合返回不可变视图
- 语义化版本：兼容新增走次版本，破坏性变更走主版本

## 4. 公开类型

### 4.1 `SdfErrorCategory`（枚举）

与 SVS 的稳定分类一一对应，SVS 直接 1:1 映射、不做二次解释：

```java
public enum SdfErrorCategory {
    DEVICE_UNAVAILABLE,
    DEVICE_BUSY,
    KEY_NOT_FOUND,
    KEY_USAGE_MISMATCH,
    ALGORITHM_UNSUPPORTED,
    AUTHORIZATION_FAILED,
    OPERATION_FAILED,
    INPUT_TOO_LARGE,
    NATIVE_DEPENDENCY_UNAVAILABLE
}
```

### 4.2 `SdfException`（公开异常）

```java
public class SdfException extends RuntimeException {
    public SdfErrorCategory category();
    public String operation();        // 仅操作名，例如 "signSm2"
    public String internalDetail();   // 仅操作名与十六进制厂商码，禁止路径/PIN/KeyId/索引
    public boolean isRetryable();     // 仅 DEVICE_UNAVAILABLE 与 DEVICE_BUSY 为 true
}
```

### 4.3 `SdfDeviceInfo`（脱敏设备信息）

```java
public record SdfDeviceInfo(
        String issuerName,
        String deviceName,
        String deviceModelClass,   // 型号分类；严禁序列号
        int deviceVersion,
        int standardVersion,
        int symAlgAbility,
        int hashAlgAbility,
        int bufferSize,
        String libraryDigestPrefix) {  // 已加载库摘要前缀，严禁路径或文件名
    public String toSafeString();      // 不含序列号、路径、库文件名
}
```

要求：**不得**提供序列号访问器，也**不得**让 `toString()` 输出序列号。

### 4.4 `SdfCapabilities`（能力指纹）

```java
public record SdfCapabilities(
        Set<AlgorithmFamily> families,        // SM2, SM3, RSA（复用现有枚举或在本包重新声明）
        boolean sm2DigestSigningSupported,
        String sm2DefaultUserId,              // 现在硬编码在 SM2SignatureSpi 的私有常量，需公开
        int sessionPoolSize,
        int sessionPoolAvailable,
        long borrowTimeoutMillis) {
}
```

`sm2DefaultUserId` 必须来自实际生效值，**不得**让消费者自行猜测或硬编码兜底。

### 4.5 `SdfDevice`（门面）

```java
public interface SdfDevice extends AutoCloseable {
    SdfDeviceInfo deviceInfo();
    SdfCapabilities capabilities();

    // 返回 X.509 SubjectPublicKeyInfo
    byte[] exportSignPublicKey(int keyIndex);

    // SM2 原文签名：设备内部计算 Z 与 e
    byte[] signSm2(int keyIndex, byte[] message, char[] pinOrNull);

    // SM2 摘要签名：直接对调用方给出的 e 签名，禁止再次哈希
    byte[] signSm2Digest(int keyIndex, byte[] digest, char[] pinOrNull);

    // RSA 原文签名：EMSA-PKCS1 v1.5 + SHA-256，输出模长字节
    byte[] signRsa(int keyIndex, byte[] message, char[] pinOrNull);

    @Override void close();
}
```

语义要求：

- `signSm2`：设备端计算 `e = SM3(Z ‖ M)`；SM2 签名结果固定为 `r[32] ‖ s[32]`
- `signSm2Digest`：**直接**把 `digest` 作为 `e` 交给 `SDF_InternalSign_ECC`，不得再次哈希；`digest` 长度必须为 32，否则抛 `OPERATION_FAILED`
- `signRsa`：输出长度等于模长字节数，保留前导零
- 私钥访问权按需申请、`finally` 中释放；**不得**按会话或按索引长期缓存 PIN
- 每次调用只需一个 `char[]` 参数，用后由调用方清零；门面不得把 PIN 存入任何字段或缓存
- `pinOrNull` 为 `null` 或空表示该密钥无需口令
- 所有失败抛出本包的 `SdfException`，携带 `SdfErrorCategory`
- `close()` 幂等；关闭后再次调用任何方法抛 `IllegalStateException`

### 4.6 入口工厂

```java
public final class SdfDevices {
    public static SdfDevice open();                    // 使用已配置的 Profile / 系统属性
    public static SdfDevice open(Properties overrides); // 白名单属性覆盖，不得含凭据
}
```

要求：入口内部完成设备打开与会话预热；**不得**要求调用方提供 `SDFLibrary`、`Pointer` 或会话句柄。

## 5. 明确不暴露

- `org.liuzx.jce.jna.SDFLibrary`
- `SDFSessionManager.getSdfLibrary()`
- 任何 JNA 结构类型
- 绝对路径、库文件名、`svrconfig.ini` 内容
- 私钥字节、原生句柄、密钥枚举、密钥导入/删除/生成/备份
- `SDF_GetSecretKeyInMemory`、`SDF_ImportKey`、`SDF_DestroyKey`、`SDF_GenerateKeyPair_*`

## 6. 验收标准

Provider 发布 1.1.5 前必须满足：

1. 上述 façade 全部存在于 `org.liuzx.jce.api`
2. 反射审计通过：`org.liuzx.jce.api` 下任何公开方法签名中不出现 JNA、`Path`、`File`、`Pointer` 或 `PrivateKey`
3. `SdfDeviceInfo` 无序列号访问器，`toSafeString()` 不含序列号
4. `SdfException` 的九类分类可被真实设备错误触发（至少覆盖 `KEY_NOT_FOUND`、`AUTHORIZATION_FAILED`、`DEVICE_UNAVAILABLE`、`ALGORITHM_UNSUPPORTED`）
5. `signSm2Digest` 与 `signRsa` 的真机输出可被独立软件验签器用导出的公钥验证通过
6. `exportSignPublicKey` 的输出可被标准 X.509 解析器解析
7. `mvn -q verify` 在 Provider 仓库通过

SVS 侧的对应门禁是 `DeviceDependencyContractTest`：它在 Provider 缺失时报告 `BLOCKED on liuzx-sdf-jce 1.1.5`，在 Provider 就绪后要求上述 façade 全部可解析。

## 7. 影响面

- 新增一个包与 6 个类型；不修改现有内部实现
- `SM2SignatureSpi.DEFAULT_USER_ID` 需要提取为可读取的常量或配置值
- `DeviceInfoUtil.DeviceInfo` 需要新增脱敏投影（或由 façade 包装）
- 不改动现有 JCE 注册、会话管理、厂商 Profile 逻辑
