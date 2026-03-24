package org.liuzx.jce.provider.asymmetric.rsa;

import java.security.spec.AlgorithmParameterSpec;

/**
 * 用于指定SDF设备内部RSA密钥索引的参数规范。
 * 当使用KeyPairGenerator "生成" 一个内部密钥对的引用时，将使用此规范。
 */
public class RSAInternalKeyGenParameterSpec implements AlgorithmParameterSpec {
    private final int keyIndex;

    /**
     * 构造一个内部密钥生成参数。
     * @param keyIndex 密钥在设备中的索引。
     */
    public RSAInternalKeyGenParameterSpec(int keyIndex) {
        this.keyIndex = keyIndex;
    }

    public int getKeyIndex() {
        return keyIndex;
    }
}
