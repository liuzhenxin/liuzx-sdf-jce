package org.liuzx.jce.jna.structure;

import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

/**
 * DSA signature structure.
 */
@Structure.FieldOrder({"r", "s"})
public class DSASignature extends Structure {

    private static final int DSAref_MAX_LEN = 384;

    public byte[] r = new byte[DSAref_MAX_LEN];
    public byte[] s = new byte[DSAref_MAX_LEN];

    public DSASignature() {
        super();
    }

    public static class ByReference extends DSASignature implements Structure.ByReference {
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("r", "s");
    }
}
