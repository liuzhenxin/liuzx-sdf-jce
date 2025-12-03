package org.liuzx.jce.jna.structure;

import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

@Structure.FieldOrder({"x", "y", "M", "L", "C"})
public class ECCCipher extends Structure {
    // ECC公钥x坐标，大端存储
    public byte[] x = new byte[64];
    // ECC公钥y坐标，大端存储
    public byte[] y = new byte[64];
    // HASH值，大端存储
    public byte[] M = new byte[32];
    // 密文数据长度
    public int L;
    // 密文数据
    public byte[] C = new byte[1024]; // 假设最大密文长度为1024

    public ECCCipher() {
        super();
    }

    public static class ByReference extends ECCCipher implements Structure.ByReference {
    }

    @Override
    protected List<String> getFieldOrder() {
        // 顺序必须与SDF库定义的一致
        return Arrays.asList("x", "y", "M", "L", "C");
    }
}
