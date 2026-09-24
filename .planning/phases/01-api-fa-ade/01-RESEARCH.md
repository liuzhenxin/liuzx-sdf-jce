# Phase 1: 消费方 API Façade — Research

**Researched:** 2026-09-23
**Domain:** 在既有 JCE Provider 之上暴露稳定的、不泄漏 JNA 类型的消费方门面
**Spec source:** `doc/SVS-FACADE-1.1.5-CHECKLIST.md`（`liuzx-svs` 需求副本）
**Confidence:** HIGH（需求规格明确，代码库映射已完成）

---

## 1. 要解决的问题

`liuzx-svs` Phase 2 的适配层通过 `ProviderCryptoBridge` 接缝调用本 Provider，并**禁止**触碰：

- `SDFSessionManager.getInstance().getSdfLibrary()`
- `org.liuzx.jce.jna..` 下任何类型

但 1.1.4 导出内部密钥公钥的唯一路径是 JNA：

```text
SDFLibrary: SDF_ExportSignPublicKey_ECC(Pointer, int, ECCrefPublicKey$ByReference)
SDFLibrary: SDF_ExportSignPublicKey_RSA(Pointer, int, RSArefPublicKey$ByReference)
```

而内部密钥签名对象必须先持有公钥：

```java
public SM2PrivateKey(int, char[], ECCrefPublicKey)   // 必须 JNA 结构
public SDFRSAPrivateKey(int, char[], RSAPublicKey)   // 标准类型，但仍须先导出公钥
```

因此需要一个**窄门面**：消费方只传 `int keyIndex` 与 `char[] pin`，门面内部完成 JNA 操作，对外只返回 JDK 类型。

## 2. 可复用的既有能力（已勘察，无需重构）

| 能力 | 现有入口 |
|---|---|
| 设备信息与算法能力位 | `org.liuzx.jce.provider.util.DeviceInfoUtil.getDeviceInfo()` → `DeviceInfoUtil.DeviceInfo` |
| 会话池容量/占用/超时 | `SDFSessionManager.getPoolSize()` / `getAvailableSessionCount()` / `getBorrowTimeoutMillis()` |
| 独占会话签出 | `SDFSessionManager.borrowSession()` |
| 按需私钥访问权 | `SDFSessionManager.getPrivateKeyAccessRight(session, keyIndex, char[])` |
| 厂商错误码 | `SDFException.getErrorCode()` / `getFunctionName()` / `getErrorDescription(int)` |
| Profile / 库路径 / RSA 布局 / 平台 | `org.liuzx.jce.provider.SDFConfig` |
| SM2 公钥 X.509 编码 | `SM2PublicKey.getEncoded()`（返回 SubjectPublicKeyInfo） |
| RSA 公钥编码 | `RSAKeyConverter` + 标准 `RSAPublicKey` |
| 内部公钥导出 | `SDFLibrary.SDF_ExportSignPublicKey_ECC` / `..._RSA` |
| 内部签名 | `SDFLibrary.SDF_InternalSign_ECC` / `SDF_InternalSign_RSA` |
| SM2 默认 UserID | `SM2SignatureSpi.DEFAULT_USER_ID`（`private static final byte[]`，值 `"1234567812345678"`，需公开） |
| 设备信息中的序列号 | `DeviceInfoUtil.DeviceInfo.getDeviceSerial()`（**门面必须隐藏**） |

## 3. 设计约束（来自规格 §3、§5）

- `org.liuzx.jce.api` 只允许 JDK 类型，不得出现 `org.liuzx.jce.jna..`、`com.sun.jna..`、`java.nio.file.Path`、`java.io.File`
- 不依赖 Spring / Jackson / 任何框架
- 所有类型不可变；集合返回不可变视图
- 不得暴露：路径、库文件名、INI 内容、私钥字节、原生句柄、密钥枚举/导入/删除/生成/备份
- 语义化版本：兼容新增走次版本

## 4. 语义陷阱（必须在计划中显式处理）

1. **`signSm2Digest` 不得再次哈希**：入参 `digest` 直接作为 `e` 传给 `SDF_InternalSign_ECC`；长度必须为 32，否则抛 `OPERATION_FAILED`。若误用 SM3 再哈希，签名结果无法被标准验签器验证，且是静默错误。
2. **`signSm2` 由设备计算 Z 与 e**：设备端计算 `e = SM3(Z ‖ M)`，输出固定 `r[32] ‖ s[32]`。
3. **`signRsa` 输出保留前导零**：输出长度必须等于模长字节数（2048→256，4096→512）。
4. **PIN 生命周期**：按需申请、`finally` 释放；不得按会话或索引缓存；不得存入任何字段；调用方负责清零。
5. **脱敏**：`SdfDeviceInfo` 不得有序列号访问器，`toSafeString()` 与 `toString()` 都不得输出序列号/路径/库文件名。
6. **`close()` 幂等**：关闭后调用任何方法抛 `IllegalStateException`。
7. **错误分类映射**：需把 `SDFErrorConstants` 的原始码映射到九类 `SdfErrorCategory`；`internalDetail` 只允许操作名 + 十六进制码。

## 5. 错误分类映射建议（研究结论）

| 原始 SDF 码 | `SdfErrorCategory` | `isRetryable` |
|---|---|---|
| `SDR_COMMFAIL` (0x01000003) | `DEVICE_UNAVAILABLE` | true |
| `SDR_HSM_NOT_READY` (0x01000403) | `DEVICE_BUSY` | true |
| `SDR_KEYNOTEXIST` (0x01000008) / `SDR_KEYERR` (0x01000015) | `KEY_NOT_FOUND` | false |
| `SDR_KEYTYPEERR` (0x01000014) | `KEY_USAGE_MISMATCH` | false |
| `SDR_ALGNOTSUPPORT` / `SDR_ALGMODNOTSUPPORT` | `ALGORITHM_UNSUPPORTED` | false |
| `SDR_PARDENY` / `SDR_PRKRERR` | `AUTHORIZATION_FAILED` | false |
| `SDR_INARGERR` / `SDR_OUTARGERR` | `INPUT_TOO_LARGE` | false |
| 库加载失败（`RuntimeException` from `SDFLibraryLoader`） | `NATIVE_DEPENDENCY_UNAVAILABLE` | false |
| 其余 | `OPERATION_FAILED` | false |

> 该映射是研究建议，最终以实现与真机验证为准（验收标准只要求至少覆盖 4 类）。
>
> **真机修正（2026-09-24，数盾 211.88.20.91）**：数盾对“范围内不存在的索引”返回
> `0x01000015`（`SDR_KEYERR`，“密钥获取异常”）而非 `SDR_KEYNOTEXIST`，因此
> `SDR_KEYERR` 改映射为 `KEY_NOT_FOUND`；越界索引返回 `0x0100001D`（`SDR_INARGERR`）→
> `INPUT_TOO_LARGE`；密钥类型不匹配返回 `0x01000014`（`SDR_KEYTYPEERR`）→
> `KEY_USAGE_MISMATCH`。

## 6. 验证架构

- **单元/反射测试（无硬件）**：反射审计 `org.liuzx.jce.api` 公开签名；`toSafeString()` 脱敏断言；`close()` 幂等与关闭后 `IllegalStateException`；错误码→分类映射表测试。
- **契约测试（需 Provider 就绪）**：`liuzx-svs` 的 `DeviceDependencyContractTest`，当前报 `BLOCKED on liuzx-sdf-jce 1.1.5`。
- **真机验证（需数盾/DYSX 设备）**：`exportSignPublicKey` 经标准 X.509 解析器；`signSm2` / `signSm2Digest` / `signRsa` 经独立软件验签器；四类错误码可被触发。
- **构建门禁**：`mvn -q verify`。

## 7. 风险

| 风险 | 说明 | 缓解 |
|---|---|---|
| 反射审计漏检 | 只扫描直接签名会漏掉泛型/数组嵌套 | 扫描所有公开方法与构造器的参数/返回类型，递归解析数组与泛型 |
| 设备公钥导出依赖密钥索引有效 | 真机测试需要已知的内部密钥索引 | 复用 `SMOKE_SM2_SIGN_INDEX` / `SMOKE_RSA_SIGN_INDEX` 环境约定 |
| `signSm2` 的 UserID 与既有 SPI 不一致 | 若门面硬编码 UserID 会与 `SM2SignatureSpi` 漂移 | 从 `SM2SignatureSpi.DEFAULT_USER_ID` 提取单一来源并进入 `SdfCapabilities` |
| RSA packed 布局 | 数盾使用变长布局 | 复用 `RSAKeyConverter`，不新写转换 |

---

*Research complete. Ready for planning.*
