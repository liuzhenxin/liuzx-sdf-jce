package org.liuzx.jce.jna.structure;

import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

@Structure.FieldOrder({"r", "s"})
public class ECCSignature extends Structure {
    // According to libsdf.h: ECCref_MAX_LEN is ((512 + 7) / 8) = 64
    private static final int ECCref_MAX_LEN = 64;

    public byte[] r = new byte[ECCref_MAX_LEN]; // Ensure this is 64
    public byte[] s = new byte[ECCref_MAX_LEN]; // Ensure this is 64

    public ECCSignature() {
        super();
    }

    public static class ByReference extends ECCSignature implements Structure.ByReference {
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("r", "s");
    }
}
