# 领域栈密码机材料

CA、KMC、Crypto 共用本目录。Compose overlay 仍在各服务目录。现场 `.env` 仍在
`pki-ca/.env` / `pki-kmc/.env`。现场数盾也可用宿主机 `/opt/shudun/` 覆盖路径。
`*.so` 和现场 `conf/*.ini` 不入库；可提交 `sdf-profile.json`、`conf/*.ini.example`、
数盾 `tls/.gitkeep`。

CA 的 JVM 用 `-Dliuzx.sdf.profile.path` 读 `sdf-profile.json`；KMC 当前仍用
`KMC_SDF_LIBRARY_PATH`。不要设 `-Dliuzx.sdf.library.path`（CA）。

```text
pki-domain-stack/HSM/
  sdf-profile.json
  DYSX/2.0/
    conf/cacipher.ini[.example]
    x86_64/linux/libsdf.so
  SanSec/1.3.87/
    conf/swsds.ini[.example]
    x86_64/linux/libswsds.so
  SHUDUN/1.4.2/
    conf/sdhsm.ini[.example]
    x86_64/linux/libsdhsmcrypto.so
    tls/
```

容器内库路径与 profile 中 `path` 一致：

| 厂商 | 容器内库 |
|---|---|
| DYSX | `/opt/hsm/lib/libsdf.so` |
| SanSec | `/opt/hsm/lib/libswsds.so` |
| 数盾 | `/opt/hsm/lib/libsdhsmcrypto.so` |
