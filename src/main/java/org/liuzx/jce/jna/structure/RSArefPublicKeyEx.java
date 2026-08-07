package org.liuzx.jce.jna.structure;

import com.sun.jna.Structure;
import java.util.Arrays;
import java.util.List;

/**
 * SDF RSA 公钥扩展结构（支持 4096 位）。
 * 对应数盾 libsdf.h 的 RSArefPublicKeyEx：bits + m[512] + e[512]
 * （RSAref_MAX_LEN_EX = 512），数据为大端右对齐。
 *
 * 注意：当前打包的数盾 SDF 库（BuildID 4809acbc）未导出使用该结构的
 * 导出函数（如 SDF_ExportSignPublicKey_RSA_Ex 不存在）；新版 SDK
 * （BuildID 056c66d1）也仅导出 Ex 导入函数（SDF_ImportKeyPair_RSA_Ex）。
 * 本结构用于 Ex API 接入时作为参数，与标准 RSArefPublicKey（m[256]）互不影响。
 */
@Structure.FieldOrder({"bits", "m", "e"})
public class RSArefPublicKeyEx extends Structure {

    /**
     * 密钥模长，以位为单位。
     */
    public int bits;

    /**
     * RSA 公钥的模数（n）。缓冲区 512 字节，支持最大 4096 位密钥。
     */
    public byte[] m = new byte[512];

    /**
     * RSA 公钥的指数（e）。缓冲区 512 字节。
     */
    public byte[] e = new byte[512];

    public RSArefPublicKeyEx() {
        super();
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("bits", "m", "e");
    }

    /**
     * 用于作为函数参数的引用类型。
     */
    public static class ByReference extends RSArefPublicKeyEx implements Structure.ByReference {}
}
