package org.liuzx.jce.jna.structure;

import com.sun.jna.Structure;
import java.util.Arrays;
import java.util.List;

/**
 * SDF定义的RSA公钥结构。
 * 用于通过JNA与硬件加密设备进行交互。
 *
 * 注意：实测数盾(Shudun) SDF 库使用的是 Lite 布局（RSArefPublicKeyLite，
 * 字段按 2048 位上限 = 256 字节），与 GM/T 0018 标准的 m[512]/e[512] 不同。
 * 设备返回的模数/指数为右对齐大端。已按 Lite 布局声明。
 */
@Structure.FieldOrder({"bits", "m", "e"})
public class RSArefPublicKey extends Structure {
    /**
     * 密钥模长，以位为单位。
     */
    public int bits;

    /**
     * RSA公钥的模数（n）。
     * 缓冲区大小256字节（LiteRSAref_MAX_LEN，支持最大2048位密钥）。
     * 数据为大端格式，右对齐填充。
     */
    public byte[] m = new byte[256];

    /**
     * RSA公钥的指数（e）。
     * 缓冲区大小256字节。数据为大端格式，右对齐填充。
     */
    public byte[] e = new byte[256];

    public RSArefPublicKey() {
        super();
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("bits", "m", "e");
    }

    /**
     * 用于作为函数参数的引用类型。
     */
    public static class ByReference extends RSArefPublicKey implements Structure.ByReference {}
}
