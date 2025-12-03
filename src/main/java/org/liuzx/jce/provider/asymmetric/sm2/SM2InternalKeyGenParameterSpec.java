package org.liuzx.jce.provider.asymmetric.sm2;

import java.security.spec.AlgorithmParameterSpec;

public class SM2InternalKeyGenParameterSpec implements AlgorithmParameterSpec {

    public enum KeyType {
        SIGN,
        ENCRYPT
    }

    private final int keyIndex;
    private final KeyType keyType;
    // Removed password field

    /**
     * @param keyIndex The index where the key pair should be stored.
     * @param keyType  The intended usage of the key pair (SIGN or ENCRYPT).
     */
    public SM2InternalKeyGenParameterSpec(int keyIndex, KeyType keyType) {
        if (keyIndex <= 0) {
            throw new IllegalArgumentException("Key index must be a positive integer.");
        }
        if (keyType == null) {
            throw new IllegalArgumentException("Key type cannot be null.");
        }
        this.keyIndex = keyIndex;
        this.keyType = keyType;
    }

    public int getKeyIndex() {
        return keyIndex;
    }

    public KeyType getKeyType() {
        return keyType;
    }
}
