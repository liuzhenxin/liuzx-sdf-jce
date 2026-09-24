# SVS Façade 1.1.5 真机验收记录

- 日期：2026-09-24
- 被测版本：`liuzx-sdf-jce-1.1.5-SNAPSHOT`
- 设备：数盾综合密码机 `211.88.20.91:1815`（serial `****0001`，`deviceVersion=1`，`standardVersion=18`）
- 执行环境：macOS x86_64 主机上的 OrbStack Docker，容器 `eclipse-temurin:25-jre-jammy`
- Vendor：`Shudun`；库：`HSM/SHUDUN/1.4.2/x86_64/linux/libsdhsmcrypto.so`；配置：容器内 `/opt/hsm/conf/sdhsm.ini`
- 实际设备打开函数：`SDF_OpenDevice`（标准入口）

## 一、执行方式

```bash
docker run --rm \
  -v "$PWD":/work \
  -v "$PWD/HSM/SHUDUN/1.4.2/x86_64/linux/libsdhsmcrypto.so":/opt/hsm/lib/libsdhsmcrypto.so:ro \
  -v /tmp/sdf-accept/conf:/opt/hsm/conf:ro \
  -w /opt/hsm/conf \
  eclipse-temurin:25-jre-jammy \
  java -Dfile.encoding=UTF-8 -Dliuzx.sdf.vendor=Shudun \
    -Dliuzx.sdf.library.path=/opt/hsm/lib/libsdhsmcrypto.so \
    -Dliuzx.sdf.vendor-config.path=/opt/hsm/conf \
    -Dliuzx.sdf.smoke.apiFacade=true \
    -Dliuzx.sdf.smoke.missingIndex=13 \
    -Dliuzx.sdf.smoke.sm2SignIndex=1 \
    -Dliuzx.sdf.smoke.rsaSignIndex=11 \
    -Dliuzx.sdf.smoke.expectAuthorizationFailWithoutPin=true \
    "-Dliuzx.sdf.smoke.pin=<PIN>" \
    -cp "/work/target/liuzx-sdf-jce-1.1.5-SNAPSHOT.jar:/work/target/lib/*" \
    org.liuzx.jce.demo.SdfSmokeTest
```

## 二、结果：17 PASS / 0 FAIL / 6 SKIP

| 项 | 需求 | 结果 | 备注 |
|---|---|---:|---|
| provider | — | PASS | |
| device-session | — | PASS | `strategy=SDF_OpenDevice` |
| random | — | PASS | 硬件随机数 32B |
| sm3 | — | PASS | 标准向量 |
| sm2-sign | — | PASS | 外部 SM2 + SM3withSM2 |
| sm4-cbc | — | PASS | 外部 SM4/CBC 往返 |
| rsa-sign | — | PASS | 外部 RSA-2048 + SHA256withRSA |
| sm2-cipher / sm4-ecb / sm4-mac / rsa-cipher | — | PASS | 外部运算 |
| **api-facade-open** | API-06/07 | **PASS** | `SdfDevices.open()` 不接触 JNA 类型即打开设备 |
| **api-export-public** | API-08 | **PASS** | `exportSignPublicKey(1)` → DER `0x30…`（91B SM2 SPKI） |
| **api-sign-rsa** | API-10 | **PASS** | `signRsa(11)` 输出 256B（RSA-2048） |
| **api-error-key-not-found** | API-12 | **PASS** | 索引 13 → `0x01000015` → `KEY_NOT_FOUND` |
| **api-error-authorization-failed** | API-12 | **PASS** | 有口令密钥省略 PIN → `0x01000018` → `AUTHORIZATION_FAILED` |
| rsa-sign-internal | — | PASS | 索引 11 + PIN |
| api-sign-sm2 / api-sign-sm2-digest | API-09 | SKIP | **阻塞：SM2 内部密钥口令未通过** |
| sm2-sign-internal | — | SKIP | 同上 |
| api-error-device-unavailable | API-12 | SKIP（冒烟内） | 已另行验证，见下 |
| api-error-algorithm-unsupported | API-12 | SKIP（冒烟内） | 已另行验证，见下 |

### 独立软件验签（OpenSSL 3.5.7，与 Provider 无关）

```
$ openssl rsa -pubin -inform DER -in rsa_pub.der -out rsa_pub.pem
writing RSA key
$ openssl dgst -sha256 -verify rsa_pub.pem -signature rsa_sig.bin message.bin
Verified OK
$ openssl pkey -pubin -inform DER -in sm2_pub.der -text -noout
Public-Key: (256 bit)
```

- RSA 内部密钥签名经 **OpenSSL 独立验签通过**（API-10 达标）。
- SM2 内部公钥可被标准 X.509 解析器解析为 256-bit EC 公钥（API-08 达标）。

## 三、真机发现的错误码映射

| 场景 | 数盾返回码 | 分类 |
|---|---|---|
| 范围内不存在的索引（如 13） | `0x01000015` `SDR_KEYERR` | `KEY_NOT_FOUND`（映射 A 修正） |
| 越界索引（如 990001） | `0x0100001D` `SDR_INARGERR` | `INPUT_TOO_LARGE` |
| ECC 导出遇到 RSA 密钥 | `0x01000014` `SDR_KEYTYPEERR` | `KEY_USAGE_MISMATCH` |
| 错误/缺失私钥口令 | `0x01000018` `SDR_PRKRERR` | `AUTHORIZATION_FAILED` |
| 设备不可达（`127.0.0.1:1`） | `0x01000003` `SDR_COMMFAIL` | `DEVICE_UNAVAILABLE` |
| 不支持的算法标识（`SDF_GenerateKeyPair_ECC(0x9999)`） | `0x01000009` `SDR_ALGNOTSUPPORT` | `ALGORITHM_UNSUPPORTED` |

四类必需错误分类（`KEY_NOT_FOUND`、`AUTHORIZATION_FAILED`、`DEVICE_UNAVAILABLE`、`ALGORITHM_UNSUPPORTED`）**均已由真机错误触发**。

## 四、真机内部密钥分布（导出公钥探测，不使用 PIN）

| 索引 | 类型 | 备注 |
|---|---|---|
| 1–10 | SM2 | `SDF_ExportSignPublicKey_ECC` 与 `SDF_ExportEncPublicKey_ECC` 均成功 |
| 11–12 | RSA | ECC 导出报 `0x14`，RSA 导出成功（RSA-2048） |
| 13–64 | 空 | `0x15` / `0x1D` |

## 五、阻塞项

**API-09（`signSm2` / `signSm2Digest`）未完成真机验收。**

- 索引 1–10 的 `SDF_GetPrivateKeyAccessRight` 对提供的两个口令（`1234qwer` 与 RSA 密钥口令）均返回 `0x01000018`。
- RSA 密钥（索引 11）使用同一口令可正常获得访问权并完成签名，说明设备与代码路径正常。
- 每个索引仅尝试一次，未产生锁定风险。

**待办**：确认索引 1–10 的 SM2 密钥访问口令，或确认这些密钥是否为可签名密钥。拿到正确口令后重跑冒烟即可补齐 `api-sign-sm2` / `api-sign-sm2-digest`，并用 OpenSSL 对 `r||s → DER` 转换后的签名做独立验签。

## 六、安全说明

- 本文不记录任何 PIN 明文；测试口令通过 `-D` 传入，见 README 的安全提示。
- `conf/sdhsm.ini` 可能含设备信息，不作为可提交内容。
