package org.liuzx.jce.jna.structure;

import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

@Structure.FieldOrder({"bits", "K"})
public class ECCrefPrivateKey extends Structure {
    // According to libsdf.h: ECCref_MAX_LEN is ((512 + 7) / 8) = 64
    private static final int ECCref_MAX_LEN = 64;

    public int bits;
    public byte[] K = new byte[ECCref_MAX_LEN]; // Corrected from 32 to 64

    public ECCrefPrivateKey() {
        super();
    }

    public static class ByReference extends ECCrefPrivateKey implements Structure.ByReference {
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("bits", "K");
    }
}
