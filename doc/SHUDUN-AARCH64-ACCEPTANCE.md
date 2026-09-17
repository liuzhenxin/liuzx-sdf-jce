# 数盾密码机 aarch64 冒烟验收记录

- 日期：2026-09-17
- 主机：`ccsec-ca-km-prd-05`（Linux aarch64）
- JDK：OpenJDK `11.0.25`（2024-10-15）
- 设备：综合密码机，串口 `****2003`，`deviceVersion=1`，`standardVersion=18`
- 被测 Provider：`liuzx-sdf-jce-1.1.4-SNAPSHOT`
- 测试包：`liuzx-sdf-jce-smoke-shudun-aarch64.tar.gz`
- Vendor：`Shudun`；库：`lib/libsdhsmcrypto.so`（`rsaKeyLayout=packed`）；配置：`conf/sdhsm.ini`

## 一、执行方式

```bash
cd liuzx-sdf-jce-smoke-shudun-aarch64
SMOKE_PIN=<PIN> SMOKE_SM2_SIGN_INDEX=1 SMOKE_RSA_SIGN_INDEX=11 \
SMOKE_SM4_KEY_INDEX=5 ./run-smoke.sh
```

冒烟程序为 `org.liuzx.jce.demo.SdfSmokeTest`，逐项输出 `[PASS]/[FAIL]/[SKIP]`，退出码 `0` 表示全部必需项通过。

## 二、结果：14/14 PASS

| 分类 | 检查项 | 结果 | 备注 |
|---|---|---:|---|
| 必需 | provider | PASS | 注册 `LiuZX` Provider |
| 必需 | device-session | PASS | `strategy=SDF_OpenDevice`（标准入口） |
| 必需 | random | PASS | 硬件随机数 32 字节 |
| 必需 | sm3 | PASS | SM3("abc") 标准向量 |
| 必需 | sm2-sign | PASS | 外部 SM2 密钥对 + SM3withSM2 签名/验签 |
| 必需 | sm4-cbc | PASS | 外部 SM4/CBC/PKCS5Padding 往返 |
| 必需 | rsa-sign | PASS | 外部 RSA-2048 + SHA256withRSA 签名/验签 |
| 可选 | sm2-cipher | PASS | 外部 SM2 加解密往返 |
| 可选 | sm4-ecb | PASS | 外部 SM4/ECB/PKCS5Padding 往返 |
| 可选 | sm4-mac | PASS | SM4MAC（16 字节块对齐输入） |
| 可选 | rsa-cipher | PASS | 外部 RSA/ECB/PKCS1Padding 往返 |
| 内部 | sm2-sign-internal | PASS | 内部 SM2 签名索引 1 + PIN |
| 内部 | rsa-sign-internal | PASS | 内部 RSA 签名索引 11 + PIN |
| 内部 | sm4-cbc-internal | PASS | 内部 SM4 密钥索引 5 |

汇总：`passed=14`、`failed=0`、`skipped=0`、`overall=PASS`。

## 三、本版本验证到的关键行为

1. **标准优先设备打开**：实际生效函数为 `SDF_OpenDevice`。数盾 aarch64 库导出标准
   `SDF_OpenDevice` 与可选 `SDF_OpenDeviceWithPath`，未导出 `SDF_OpenDeviceEx`，标准调用成功，
   不再出现 `Error looking up function 'SDF_OpenDeviceEx'`。
2. **全局单一设备句柄**：`SDFSessionManager` 只 `SDF_OpenDevice` 一次并在会话间复用，日志中
   `应用应仅打开一次设备句柄并全局使用` 的多开告警已消失。
3. **内部对称密钥句柄能力探测**：数盾未导出 `SDF_GetSymmKeyHandle`，自动回退
   `SDF_ImportKEK`，内部 SM4（索引 5）加解密往返成功。
4. **SM4-MAC 块对齐**：数盾要求 `SDF_CalculateMAC` 输入为 16 字节整数倍（非对齐返回
   `0x0100001D`），调用方需自行填充；冒烟已使用块对齐输入并通过。
5. **退出前关闭设备**：冒烟在 `System.exit` 前显式调用 `SDFSessionManager.shutdown()`，
   关闭失败时会打印 `SDF_CloseDevice failed`；本次无该日志。

## 四、已知提示（非缺陷）

进程退出时可能出现：

```
[FORCE] 应用应在退出前或不再使用时关闭设备
```

经反汇编确认，该字符串（`libsdhsmcrypto.so` VA `0x340958`，60 字节）唯一引用于
`SDF_OpenDeviceWithIp`，是厂商库在**打开设备流程**中用 `fwrite` 写入的**一次性合规提示**，
因 C 层 stdout 缓冲在进程退出时才 flush，故显示在最后。它**不代表设备未关闭**；同一函数中的
“应用应仅打开一次设备句柄并全局使用”才是多开告警，当前已消失。该提示可忽略。

## 五、范围与限制

- 本文覆盖 **单机 JCE + 设备** 冒烟；`liuzx-sdf-jce` 字节码为 Java 8，JDK 11 可直接运行。
- **KMC / CA 集成不在本次范围**：二者的产物为 Java 25 字节码（KMC 镜像
  `eclipse-temurin:25-jre-jammy`，CA 镜像 `ghcr.io/graalvm/jdk-community:25.0.1`），需在
  JDK 25 环境或其容器内验证。KMC 侧关注 `/api/actuator/health/readiness` 的 `hsm=UP`、
  无 `SDF device probe failed` / `key protection is not ready`；CA 侧关注 `signerType=sdf`
  的签发/CRL。
