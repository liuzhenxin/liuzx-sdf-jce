package org.liuzx.jce.jna.structure;

import com.sun.jna.Structure;
import java.util.Arrays;
import java.util.List;

/**
 * SDF 定义的 RSA 公钥结构（数盾 libsdf.h 的 RSArefPublicKey）。
 * 字段：bits + m[512] + e[512]（RSAref_MAX_BITS = 4096，RSAref_MAX_LEN = 512），
 * 支持最大 4096 位密钥。
 *
 * 注意：数盾 SDF 库将本结构视为"变长"结构 bits + m[keyBytes] + e[keyBytes]：
 * 对 ≤2048 位密钥实际只读写前 4 + 2*keyBytes 字节（等效 RSArefPublicKeyLite），
 * 4096 位密钥才占满整个 1028 字节。因此：
 *   - 模数 n 始终位于 m[0..keyBytes-1]（左对齐/恰好填满）；
 *   - 指数 e 右对齐位于紧随其后的 keyBytes 字节区间末尾
 *     （≤2048 位：落在 m[keyBytes..2*keyBytes] 尾部，即 m[508..511]；
 *      4096 位：落在 e[512] 尾部，即 e[508..511]）。
 * 读取与构造时必须按 bits 位长感知，参见 RSAKeyPairGeneratorSpi.buildRSAPublicKey
 * 与 RSACipherSpi 的转换助手。
 */
@Structure.FieldOrder({"bits", "m", "e"})
public class RSArefPublicKey extends Structure {
    /**
     * 密钥模长，以位为单位。
     */
    public int bits;

    /**
     * RSA 公钥的模数 (n)。缓冲区 512 字节，支持最大 4096 位密钥。
     */
    public byte[] m = new byte[512];

    /**
     * RSA 公钥的指数 (e)。缓冲区 512 字节。
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
