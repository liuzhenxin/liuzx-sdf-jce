package org.liuzx.jce.api;

/**
 * 门面暴露的算法族。
 *
 * <p>这是 {@link SdfCapabilities#families()} 的元素类型，仅代表设备/门面支持的能力集合，
 * 不携带任何密钥信息。</p>
 */
public enum AlgorithmFamily {

    /** 国产椭圆曲线公钥算法。 */
    SM2,

    /** 国产密码杂凑算法。 */
    SM3,

    /** RSA 公钥算法。 */
    RSA
}
