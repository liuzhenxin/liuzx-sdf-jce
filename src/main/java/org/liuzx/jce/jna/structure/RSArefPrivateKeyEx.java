package org.liuzx.jce.jna.structure;

import com.sun.jna.Structure;
import java.util.Arrays;
import java.util.List;

/**
 * SDF RSA 私钥扩展结构（支持 4096 位）。
 * 与数盾 libsdf.h 的 RSArefPrivateKeyEx 逐字段对应：
 * bits + m[512] + e[512] + d[512] + prime[2][256] + pexp[2][256] + coef[256]
 * （RSAref_MAX_LEN_EX = 512，RSAref_MAX_PLEN_EX = 256）。
 *
 * JNA 不支持 byte[][] 结构字段，故 prime/pexp 按连续 512 字节扁平声明：
 * prime[0..255]=p（素数1），prime[256..511]=q（素数2）；
 * pexp[0..255]=dP，pexp[256..511]=dQ。与头文件内存布局完全一致。
 *
 * 注意：当前打包的数盾 SDF 库（BuildID 4809acbc）未导出使用该结构的函数；
 * 新版 SDK（BuildID 056c66d1）仅导出 Ex 导入函数（SDF_ImportKeyPair_RSA_Ex）。
 * 本结构用于 Ex API 接入时作为参数，与标准 RSArefPrivateKey（m[256]）互不影响。
 */
@Structure.FieldOrder({"bits", "m", "e", "d", "prime", "pexp", "coef"})
public class RSArefPrivateKeyEx extends Structure {

    /**
     * 密钥模长，以位为单位。
     */
    public int bits;

    /**
     * RSA 公钥的模数（n）。缓冲区 512 字节。
     */
    public byte[] m = new byte[512];

    /**
     * RSA 公钥的指数（e）。缓冲区 512 字节。
     */
    public byte[] e = new byte[512];

    /**
     * RSA 私钥的指数（d）。缓冲区 512 字节。
     */
    public byte[] d = new byte[512];

    /**
     * CRT 参数：两个素数，各 256 字节（对应头文件 prime[2][256]）。
     * prime[0..255] = p，prime[256..511] = q。
     */
    public byte[] prime = new byte[512];

    /**
     * CRT 参数：dP、dQ，各 256 字节（对应头文件 pexp[2][256]）。
     * pexp[0..255] = dP = d mod (p-1)，pexp[256..511] = dQ = d mod (q-1)。
     */
    public byte[] pexp = new byte[512];

    /**
     * CRT 参数：qInv = q^(-1) mod p。256 字节（对应头文件 coef[256]）。
     */
    public byte[] coef = new byte[256];

    public RSArefPrivateKeyEx() {
        super();
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("bits", "m", "e", "d", "prime", "pexp", "coef");
    }

    /**
     * 用于作为函数参数的引用类型。
     */
    public static class ByReference extends RSArefPrivateKeyEx implements Structure.ByReference {}
}
