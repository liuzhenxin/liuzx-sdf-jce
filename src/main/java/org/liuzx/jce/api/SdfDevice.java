package org.liuzx.jce.api;

/**
 * 消费方门面：在不接触任何 JNA 类型的前提下操作真实密码设备上的内部密钥。
 *
 * <p>门面只允许使用 JDK 类型；调用方不会看到 {@code SDFLibrary}、{@code Pointer} 或会话句柄。
 * 私钥始终驻留硬件，门面只通过密钥索引引用它们。</p>
 *
 * <h2>PIN 语义</h2>
 * <p>所有签名方法的 {@code pinOrNull} 参数：{@code null} 或空数组表示该密钥无需口令。
 * 门面按需申请私钥访问权并在 {@code finally} 中释放，门面不缓存 PIN，
 * 也不会把它存入任何字段。调用方在方法返回后应自行清零传入的 {@code char[]}。</p>
 *
 * <h2>生命周期</h2>
 * <p>{@link #close()} 幂等；关闭后再调用任何方法抛 {@link IllegalStateException}。</p>
 */
public interface SdfDevice extends AutoCloseable {

    /**
     * @return 脱敏后的设备信息（不含序列号、路径或库文件名）。
     * @throws SdfException 设备不可用或读取失败。
     */
    SdfDeviceInfo deviceInfo();

    /**
     * @return 设备与门面的能力指纹，含实际生效的 {@code sm2DefaultUserId}。
     */
    SdfCapabilities capabilities();

    /**
     * 导出索引对应的内部签名公钥。
     *
     * <p>实现会先按 SM2 签名密钥尝试，失败后再按 RSA 签名密钥尝试；返回第一个成功的
     * X.509 SubjectPublicKeyInfo 字节。因为 SDF 的 ECC 与 RSA 导出是不同函数，而方法
     * 只接收索引，故采用探测策略。</p>
     *
     * @param keyIndex 设备内部密钥索引
     * @return X.509 SubjectPublicKeyInfo 编码
     * @throws SdfException 索引不存在、算法不支持或设备不可用。
     */
    byte[] exportSignPublicKey(int keyIndex);

    /**
     * SM2 原文签名：由设备计算 {@code Z} 与 {@code e = SM3(Z ‖ message)}。
     *
     * @param keyIndex    设备内部 SM2 签名密钥索引
     * @param message     待签名原文
     * @param pinOrNull   私钥口令，可为 {@code null}
     * @return 固定 64 字节的 {@code r[32] ‖ s[32]}
     * @throws SdfException 设备、密钥或授权失败。
     */
    byte[] signSm2(int keyIndex, byte[] message, char[] pinOrNull);

    /**
     * SM2 摘要签名：直接把 {@code digest} 作为 {@code e} 交给设备，<b>不会</b>再次哈希。
     *
     * @param keyIndex    设备内部 SM2 签名密钥索引
     * @param digest      预计算摘要，长度必须为 32
     * @param pinOrNull   私钥口令，可为 {@code null}
     * @return 固定 64 字节的 {@code r[32] ‖ s[32]}
     * @throws SdfException {@code digest} 长度非 32 时为 {@code OPERATION_FAILED}；其余同 {@link #signSm2}
     */
    byte[] signSm2Digest(int keyIndex, byte[] digest, char[] pinOrNull);

    /**
     * RSA 原文签名：EMSA-PKCS1 v1.5 + SHA-256，输出长度等于模长字节数并保留前导零。
     *
     * @param keyIndex    设备内部 RSA 签名密钥索引
     * @param message     待签名原文
     * @param pinOrNull   私钥口令，可为 {@code null}
     * @return 模长字节数的 RSA 签名
     * @throws SdfException 设备、密钥或授权失败。
     */
    byte[] signRsa(int keyIndex, byte[] message, char[] pinOrNull);

    /**
     * 关闭门面。幂等；关闭后调用任何方法抛 {@link IllegalStateException}。
     */
    @Override
    void close();
}
