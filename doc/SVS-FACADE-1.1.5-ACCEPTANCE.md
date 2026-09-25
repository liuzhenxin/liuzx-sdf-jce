# SVS Façade 1.1.5 真机验收记录

- 日期：2026-09-24
- 被测版本：`liuzx-sdf-jce-1.1.5-SNAPSHOT`
- 执行环境：macOS x86_64 + OrbStack Docker，容器 `eclipse-temurin:25-jre-jammy`
- 覆盖设备：
  - 数盾综合密码机 `211.88.20.91:1815`（serial `****0001`）
  - DYSX 密码机 `10.10.10.61:8001`（`AnyHSM-CS-G`，serial `****7890`）
- 独立验签器：OpenSSL 3.5.7（`alpine/openssl`）与自研 raw-EC SM2 验签器（无 Provider / 无 BouncyCastle）
- 实际设备打开函数：两者均为标准 `SDF_OpenDevice`

## 一、结果汇总

**API-06 … API-12 全部达标。**

| 需求 | 状态 | 证据 |
|---|---|---|
| API-06 门面接口 | ✅ | `SdfDevice` 七个方法齐备 |
| API-07 入口工厂 | ✅ | 两台设备上 `SdfDevices.open()` 均不接触 JNA 类型 |
| API-08 公钥导出 | ✅ | DER `0x30…`；OpenSSL 解析为 256-bit EC 公钥 |
| API-09 SM2 签名 | ✅ | DYSX：`signSm2` / `signSm2Digest` 均 64B；独立验签通过 |
| API-10 RSA 签名 | ✅ | 数盾：`signRsa(11)` → 256B；OpenSSL `Verified OK` |
| API-11 PIN 生命周期 | ✅ | 缺口令被拒、无 `char[]` 字段、每索引仅按需申请 |
| API-12 错误分类 | ✅ | 四类均被真机错误触发（见 §3） |
| API-13 发布 | ✅ | `1.1.5` 已发布到 Maven Central（deployment `f3f7714d-3fd8-4ab6-87c1-6b5e8636b68d`，`autoPublish`）；tag `v1.1.5`；SVS 契约测试对正式 `1.1.5` 7/7 通过 |

### 冒烟结果

| 设备 | 结果 | 说明 |
|---|---|---|
| 数盾 211.88.20.91 | **17 PASS / 0 FAIL** | 内部 RSA 索引 11 通过；内部 SM2 索引 1–10 口令未获通过（见 §4） |
| DYSX 10.10.10.61 | **17 PASS / 0 FAIL** | 内部 SM2 索引 1 通过；该机无内部 RSA 密钥 |

关键门面条目（两台设备均包含）：`api-facade-open`、`api-export-public`、`api-sign-*`、`api-error-key-not-found`。

## 二、独立软件验签

| 产物 | 验签方式 | 结果 |
|---|---|---|
| 数盾 `signRsa(11)` | `openssl dgst -sha256 -verify` | **Verified OK** |
| DYSX `signSm2(1, M)` | `openssl dgst -sm3 -sigopt distid:1234567812345678 -verify` | **Verified OK** |
| DYSX `signSm2(1, M)` | 自研 raw-EC 验签（独立计算 `e = SM3(Z‖M)`） | **VALID** |
| DYSX `signSm2Digest(1, e)` | 自研 raw-EC 验签（`e` 由 OpenSSL SM3 独立产生） | **VALID** |
| DYSX `exportSignPublicKey(1)` | `openssl pkey -pubin -inform DER` | 解析为 256-bit EC 公钥 |

说明：OpenSSL 3.5 的 SM2 验签需显式 `-sigopt distid:1234567812345678`（不指定则其默认区分标识为空，会验签失败）；这同时验证了本库 `SM2SignatureSpi.DEFAULT_USER_ID_STRING` 与标准默认 ID 一致。

## 三、真机错误码映射

| 场景 | 设备 | 返回码 | 分类 |
|---|---|---|---|
| 范围内不存在的索引 | 数盾 | `0x01000015` | `KEY_NOT_FOUND` |
| 越界索引 | 数盾 | `0x0100001D` | `INPUT_TOO_LARGE` |
| ECC 导出遇到 RSA 密钥 | 数盾 | `0x01000014` | `KEY_USAGE_MISMATCH` |
| 错误/缺失私钥口令 | 数盾 | `0x01000018` | `AUTHORIZATION_FAILED` |
| 设备不可达（`127.0.0.1:1`） | 数盾 | `0x01000003` | `DEVICE_UNAVAILABLE` |
| 不支持的算法标识 | 数盾 | `0x01000009` | `ALGORITHM_UNSUPPORTED` |
| 无口令访问受保护密钥 | DYSX | `0x03000002` / `0x03000001` 场景 | `AUTHORIZATION_FAILED` |

四类必需分类（`KEY_NOT_FOUND`、`AUTHORIZATION_FAILED`、`DEVICE_UNAVAILABLE`、`ALGORITHM_UNSUPPORTED`）**均已被真机错误触发**。

## 四、内部密钥分布

| 设备 | 索引 | 类型 | 签名口令 |
|---|---|---|---|
| 数盾 211.88.20.91 | 1–10 | SM2 | 所提供的口令均被拒（`0x18`），用途待确认 |
| 数盾 211.88.20.91 | 11–12 | RSA-2048 | 已确认可用，`signRsa` 通过 |
| 数盾 211.88.20.91 | 13–64 | 空 | — |
| DYSX 10.10.10.61 | 1–2 | SM2 | 已确认可用（`signSm2` 通过） |
| DYSX 10.10.10.61 | 3+ | 空（`0x03000002`） | — |

数盾 SM2 密钥未参与验收；SM2 路径改由 DYSX 设备完成，结论等价。

## 五、SVS 消费方契约

在 `liuzx-svs` 仓将 `liuzx-sdf-jce` 暴露到测试类路径后：

```
Tests run: 7, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

对 `1.1.5-SNAPSHOT` 与**正式 `1.1.5`** 各跑一次，均 7/7 通过。`BLOCKED on liuzx-sdf-jce 1.1.5` 已解除；`org.liuzx.jce.api` 的 6 个公开类型与 7 个门面方法、反射审计、无序列号访问器均通过。SVS 仓未做任何源码改动。

## 六、发布记录（1.1.5）

- 命令：`./release.sh --version 1.1.5`
- 结果：`mvn clean deploy -Prelease,gpg-signing` `BUILD SUCCESS`
- Central 部署：`f3f7714d-3fd8-4ab6-87c1-6b5e8636b68d`，已 `validated`，`autoPublish=true`
- Git：发布提交 `55a5cbc` + tag `v1.1.5`；随后回到 `1.1.6-SNAPSHOT`（提交 `039b1b8`）
- 产物：主 jar、`-sources.jar`、`-javadoc.jar` 及各自 `.asc`
- 首次尝试因 TSA `http://timestamp.sectigo.com` 瞬时不可达而失败；重试成功
- 说明：本机 Maven 使用 Aliyun 镜像，对 `org.liuzx` 同步滞后，无法从本机独立验证 `repo1` 传播；以发布插件的 `validated` 与 `autoPublish` 为准

## 七、待办

1. **发布 1.1.5 到 Maven Central** — ✅ 已完成（见 §六）。
2. 数盾 SM2 内部密钥口令/用途确认（不影响本次结论，SM2 已由 DYSX 验证）。

## 八、安全说明

- 本文不记录任何 PIN 明文；测试口令经 `-D` 传入。
- 执行日志中出现的设备地址与序列号仅用于测试环境。
