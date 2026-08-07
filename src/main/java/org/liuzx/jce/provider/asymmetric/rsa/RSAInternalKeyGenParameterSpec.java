package org.liuzx.jce.provider.asymmetric.rsa;

import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;

/**
 * 用于指定SDF设备内部RSA密钥索引的参数规范。
 * 当使用KeyPairGenerator "生成" 一个内部密钥对的引用时，将使用此规范。
 *
 * 支持外部注入公钥（RSAPublicKey）：注入后加载内部密钥引用时会跳过
 * SDF_ExportSignPublicKey_RSA / SDF_ExportEncPublicKey_RSA。数盾 SDK 的
 * 导出函数按 Lite 结构（m[256]/e[256]）仅支持到 2048 位，4096 位密钥导出
 * 会越界崩溃，因此需要调用方持有该索引对应的公钥（如导入时的密钥材料/证书）。
 */
public class RSAInternalKeyGenParameterSpec implements AlgorithmParameterSpec {
    private final int keyIndex;
    private final RSAPublicKey publicKey;

    /**
     * 构造一个内部密钥生成参数。
     * @param keyIndex 密钥在设备中的索引。
     */
    public RSAInternalKeyGenParameterSpec(int keyIndex) {
        this(keyIndex, null);
    }

    /**
     * 构造一个内部密钥生成参数，并注入该索引对应的公钥。
     * @param keyIndex  密钥在设备中的索引。
     * @param publicKey 该内部密钥的公钥；非 null 时加载将跳过 SDF 导出。
     */
    public RSAInternalKeyGenParameterSpec(int keyIndex, RSAPublicKey publicKey) {
        this.keyIndex = keyIndex;
        this.publicKey = publicKey;
    }

    public int getKeyIndex() {
        return keyIndex;
    }

    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * 是否外部注入了公钥（非 null）。是则加载时跳过 SDF 导出。
     */
    public boolean hasExternalPublicKey() {
        return publicKey != null;
    }
}
