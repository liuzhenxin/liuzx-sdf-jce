package org.liuzx.jce.jna.structure;

import com.sun.jna.Structure;
import java.util.Arrays;
import java.util.List;

/**
 * SDF定义的RSA公钥结构。
 * 用于通过JNA与硬件加密设备进行交互。
 */
@Structure.FieldOrder({"bits", "m", "e"})
public class RSArefPublicKey extends Structure {
    /**
     * 密钥模长，以位为单位。
     */
    public int bits;

    /**
     * RSA公钥的模数（n）。
     * 缓冲区大小设置为512字节，以支持最大4096位的密钥。
     * 数据为大端格式。
     */
    public byte[] m = new byte[512];

    /**
     * RSA公钥的指数（e）。
     * 缓冲区大小设置为512字节，以支持较大的公钥指数。
     * 数据为大端格式。
     */
    public byte[] e = new byte[512];

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
