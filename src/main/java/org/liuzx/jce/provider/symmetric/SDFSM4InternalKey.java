package org.liuzx.jce.provider.symmetric;

import javax.crypto.SecretKey;
import java.util.Arrays;

/**
 * Reference to an SM4 key protected by an internal SDF KEK index.
 */
public class SDFSM4InternalKey implements SecretKey {

    private static final int DEFAULT_KEY_LENGTH_BYTES = 16;

    private final int keyIndex;
    private final int keyLengthBytes;
    private final byte[] encryptedKey;

    public SDFSM4InternalKey(int keyIndex) {
        this(keyIndex, DEFAULT_KEY_LENGTH_BYTES, new byte[DEFAULT_KEY_LENGTH_BYTES]);
    }

    public SDFSM4InternalKey(int keyIndex, byte[] encryptedKey) {
        this(keyIndex, encryptedKey == null ? DEFAULT_KEY_LENGTH_BYTES : encryptedKey.length, encryptedKey);
    }

    public SDFSM4InternalKey(int keyIndex, int keyLengthBytes, byte[] encryptedKey) {
        if (keyIndex <= 0) {
            throw new IllegalArgumentException("SM4 internal key index must be positive");
        }
        if (keyLengthBytes <= 0) {
            throw new IllegalArgumentException("SM4 key length must be positive");
        }
        this.keyIndex = keyIndex;
        this.keyLengthBytes = keyLengthBytes;
        this.encryptedKey = encryptedKey == null ? new byte[keyLengthBytes] : Arrays.copyOf(encryptedKey,
                Math.max(keyLengthBytes, encryptedKey.length));
    }

    public int getKeyIndex() {
        return keyIndex;
    }

    public int getKeyLengthBytes() {
        return keyLengthBytes;
    }

    byte[] getEncryptedKey() {
        return Arrays.copyOf(encryptedKey, encryptedKey.length);
    }

    @Override
    public String getAlgorithm() {
        return "SM4";
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return null;
    }
}
