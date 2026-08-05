package org.liuzx.jce.jna.structure;

import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

/**
 * DSA public key structure. Supports up to 3072-bit keys.
 */
@Structure.FieldOrder({"bits", "y", "p", "q", "g"})
public class DSArefPublicKey extends Structure {

    private static final int DSAref_MAX_LEN = 384; // (3072 + 7) / 8

    public int bits;
    public byte[] y = new byte[DSAref_MAX_LEN];
    public byte[] p = new byte[DSAref_MAX_LEN];
    public byte[] q = new byte[DSAref_MAX_LEN];
    public byte[] g = new byte[DSAref_MAX_LEN];

    public DSArefPublicKey() {
        super();
    }

    public static class ByReference extends DSArefPublicKey implements Structure.ByReference {
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("bits", "y", "p", "q", "g");
    }
}
