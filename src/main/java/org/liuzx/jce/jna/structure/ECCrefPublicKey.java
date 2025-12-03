package org.liuzx.jce.jna.structure;

import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

@Structure.FieldOrder({"bits", "x", "y"})
public class ECCrefPublicKey extends Structure {
    // According to libsdf.h: ECCref_MAX_LEN is ((512 + 7) / 8) = 64
    private static final int ECCref_MAX_LEN = 64;

    public int bits;
    public byte[] x = new byte[ECCref_MAX_LEN]; // Ensure this is 64
    public byte[] y = new byte[ECCref_MAX_LEN]; // Ensure this is 64

    public ECCrefPublicKey() {
        super();
    }

    public static class ByReference extends ECCrefPublicKey implements Structure.ByReference {
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("bits", "x", "y");
    }
}
