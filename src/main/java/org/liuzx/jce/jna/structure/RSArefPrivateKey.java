package org.liuzx.jce.jna.structure;

import com.sun.jna.Structure;
import java.util.Arrays;
import java.util.List;

/**
 * SDF定义的RSA私钥结构。
 * 用于通过JNA从硬件加密设备接收导出的私钥。
 * 注意：这是一个包含敏感信息的结构体，应谨慎处理。
 */
@Structure.FieldOrder({"bits", "m", "e", "d", "p", "q", "dp", "dq", "qinv"})
public class RSArefPrivateKey extends Structure {
    /**
     * 密钥模长，以位为单位。
     */
    public int bits;

    /**
     * RSA公钥的模数 (n)。
     * 缓冲区大小512字节，支持最大4096位密钥。
     */
    public byte[] m = new byte[512];

    /**
     * RSA公钥的指数 (e)。
     * 缓冲区大小512字节。
     */
    public byte[] e = new byte[512];

    /**
     * RSA私钥的指数 (d)。
     * 缓冲区大小512字节。
     */
    public byte[] d = new byte[512];

    /**
     * CRT参数：素数p。
     * 缓冲区大小256字节，支持最大2048位密钥的因子。
     */
    public byte[] p = new byte[256];

    /**
     * CRT参数：素数q。
     * 缓冲区大小256字节。
     */
    public byte[] q = new byte[256];

    /**
     * CRT参数：dP = d mod (p-1)。
     * 缓冲区大小256字节。
     */
    public byte[] dp = new byte[256];

    /**
     * CRT参数：dQ = d mod (q-1)。
     * 缓冲区大小256字节。
     */
    public byte[] dq = new byte[256];

    /**
     * CRT参数：qInv = q^(-1) mod p。
     * 缓冲区大小256字节。
     */
    public byte[] qinv = new byte[256];

    public RSArefPrivateKey() {
        super();
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("bits", "m", "e", "d", "p", "q", "dp", "dq", "qinv");
    }

    /**
     * 用于作为函数参数的引用类型。
     */
    public static class ByReference extends RSArefPrivateKey implements Structure.ByReference {}
}
