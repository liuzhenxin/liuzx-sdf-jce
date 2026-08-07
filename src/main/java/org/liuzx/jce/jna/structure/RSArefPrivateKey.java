package org.liuzx.jce.jna.structure;

import com.sun.jna.Structure;
import java.util.Arrays;
import java.util.List;

/**
 * SDF 定义的 RSA 私钥结构（数盾 libsdf.h 的 RSArefPrivateKey）。
 * 字段：bits + m[512] + e[512] + d[512] + prime[2][256] + pexp[2][256] + coef[256]
 * （RSAref_MAX_LEN = 512，RSAref_MAX_PLEN = 256），支持最大 4096 位密钥。
 *
 * 与公钥结构一样，数盾将其视为变长结构 bits + m[keyBytes] + e[keyBytes] +
 * d[keyBytes] + prime[2][primeBytes] + pexp[2][primeBytes] + coef[primeBytes]，
 * 其中 primeBytes = (keyBytes+1)/2。对 ≤2048 位密钥实际只读写前
 * 4 + 3*keyBytes + 5*primeBytes 字节（等效 RSArefPrivateKeyLite），4096 位才占满。
 * 各数值域均在各自 keyBytes/primeBytes 子区间内右对齐。
 *
 * 注意：这是一个包含敏感信息的结构体，应谨慎处理。
 */
@Structure.FieldOrder({"bits", "m", "e", "d", "p", "q", "dp", "dq", "qinv"})
public class RSArefPrivateKey extends Structure {
    /**
     * 密钥模长，以位为单位。
     */
    public int bits;

    /**
     * RSA 公钥的模数 (n)。缓冲区 512 字节。
     */
    public byte[] m = new byte[512];

    /**
     * RSA 公钥的指数 (e)。缓冲区 512 字节。
     */
    public byte[] e = new byte[512];

    /**
     * RSA 私钥的指数 (d)。缓冲区 512 字节。
     */
    public byte[] d = new byte[512];

    /**
     * CRT 参数：素数 p。缓冲区 256 字节（RSAref_MAX_PLEN）。
     */
    public byte[] p = new byte[256];

    /**
     * CRT 参数：素数 q。缓冲区 256 字节。
     */
    public byte[] q = new byte[256];

    /**
     * CRT 参数：dP = d mod (p-1)。缓冲区 256 字节。
     */
    public byte[] dp = new byte[256];

    /**
     * CRT 参数：dQ = d mod (q-1)。缓冲区 256 字节。
     */
    public byte[] dq = new byte[256];

    /**
     * CRT 参数：qInv = q^(-1) mod p。缓冲区 256 字节。
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
