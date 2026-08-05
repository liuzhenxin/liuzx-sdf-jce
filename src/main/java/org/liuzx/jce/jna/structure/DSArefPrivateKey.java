package org.liuzx.jce.jna.structure;

import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

/**
 * DSA private key structure.
 */
@Structure.FieldOrder({"bits", "x", "p", "q", "g"})
public class DSArefPrivateKey extends Structure {

    private static final int DSAref_MAX_LEN = 384;

    public int bits;
    public byte[] x = new byte[DSAref_MAX_LEN];
    public byte[] p = new byte[DSAref_MAX_LEN];
    public byte[] q = new byte[DSAref_MAX_LEN];
    public byte[] g = new byte[DSAref_MAX_LEN];

    public DSArefPrivateKey() {
        super();
    }

    public static class ByReference extends DSArefPrivateKey implements Structure.ByReference {
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("bits", "x", "p", "q", "g");
    }
}
