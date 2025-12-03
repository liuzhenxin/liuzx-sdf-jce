package org.liuzx.jce.provider.symmetric;

import javax.crypto.SecretKey;
import java.util.Arrays;

public class SM4SecretKey implements SecretKey {

    private final byte[] key;

    public SM4SecretKey(byte[] key) {
        this.key = Arrays.copyOf(key, key.length);
    }

    @Override
    public String getAlgorithm() {
        return "SM4";
    }

    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public byte[] getEncoded() {
        return Arrays.copyOf(key, key.length);
    }
}
