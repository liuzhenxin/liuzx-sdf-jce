package org.liuzx.jce.provider.asymmetric.rsa;

import org.liuzx.jce.jna.structure.RSArefPrivateKey;
import org.liuzx.jce.jna.structure.RSArefPublicKey;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

/**
 * RSA 密钥 ↔ SDF 结构体的转换工具（外部密钥加解密与签名共用，保持变长布局逻辑单点）。
 *
 * <p>数盾库把 RSA 公钥/私钥当作变长结构读写：
 * <pre>
 *   公钥: bits + m[keyBytes] + e[keyBytes]                 (keyBytes = (bits+7)/8)
 *   私钥: bits + m[keyBytes] + e[keyBytes] + d[keyBytes]
 *           + p[primeBytes] + q[primeBytes] + dp[primeBytes]
 *           + dq[primeBytes] + qinv[primeBytes]            (primeBytes = (keyBytes+1)/2)
 * </pre>
 * 子区间随 keyBytes 平移：对 ≤2048 位密钥，e/d/CRT 各子区间整体落在 JNA 固定字段
 * （m[512]/e[512]/d[512]/p[256]/q[256]/dp[256]/dq[256]/qinv[256]）的前部
 * （等效 Lite 前缀）；4096 位才与 JNA 字段一一对齐。故定位字段必须按结构体相对偏移，
 * 而非按字段名直写。
 *
 * <p>公钥布局（实测 dump 原始缓冲区确认）：
 *   ≤2048 位：模数左对齐于 m[0..keyBytes)，指数右对齐于 m[keyBytes..2*keyBytes)；
 *   4096 位：模数填满 m[0..512)，指数右对齐于 e 末尾。私钥各数值在各自
 *   keyBytes/primeBytes 子区间内右对齐。
 */
final class RSAKeyConverter {

    private RSAKeyConverter() {
    }

    static RSArefPublicKey.ByReference toSdfPublicKey(RSAPublicKey key) {
        RSArefPublicKey.ByReference ref = new RSArefPublicKey.ByReference();
        int bits = key.getModulus().bitLength();
        int keyBytes = (bits + 7) / 8;
        ref.bits = bits;
        // 数盾把公钥当变长结构 bits + m[keyBytes] + e[keyBytes] 读（≤2048 位为 Lite 前缀，
        // 4096 位才占满整个 1028 字节）：模数位于 m 区开头，指数右对齐在紧随其后的
        // keyBytes 字节区间末尾。
        copyToSdfBuffer(key.getModulus(), ref.m, 0, keyBytes);
        if (keyBytes <= 256) {
            // ≤2048 位：指数区间 = m[keyBytes..2*keyBytes]（即字节偏移 4+keyBytes..4+2*keyBytes）
            copyToSdfBuffer(key.getPublicExponent(), ref.m, keyBytes, keyBytes);
        } else {
            // 4096 位：指数区间 = e[0..keyBytes]
            copyToSdfBuffer(key.getPublicExponent(), ref.e, 0, keyBytes);
        }
        return ref;
    }

    static RSArefPrivateKey.ByReference toSdfPrivateKey(SDFRSAPrivateKey key) {
        RSArefPrivateKey.ByReference ref = new RSArefPrivateKey.ByReference();
        int bits = key.getModulus().bitLength();
        int keyBytes = (bits + 7) / 8;
        int primeBytes = (((bits + 1) / 2) + 7) / 8;
        ref.bits = bits;
        // 数盾把 RSA 私钥当作变长结构 bits + m[keyBytes] + e[keyBytes] + d[keyBytes] +
        // p[primeBytes] + q[primeBytes] + dp[primeBytes] + dq[primeBytes] +
        // qinv[primeBytes] 读取，各数值在各自 keyBytes/primeBytes 子区间内右对齐。
        // 子区间随 keyBytes 平移：对 ≤2048 位密钥整体落在 JNA 结构前部（等效 Lite
        // 前缀，e 在 m 字段尾部、d 在 e 字段前段…），4096 位才与字段一一对齐。
        // 故用结构体相对偏移定位目标字段，而非按字段名直写。
        copyToSdfPrivateRegion(key.getModulus(), ref, 0, keyBytes);
        copyToSdfPrivateRegion(key.getPublicExponent(), ref, keyBytes, keyBytes);
        copyToSdfPrivateRegion(key.getPrivateExponent(), ref, 2 * keyBytes, keyBytes);
        copyToSdfPrivateRegion(key.getPrimeP(), ref, 3 * keyBytes, primeBytes);
        copyToSdfPrivateRegion(key.getPrimeQ(), ref, 3 * keyBytes + primeBytes, primeBytes);
        copyToSdfPrivateRegion(key.getPrimeExponentP(), ref, 3 * keyBytes + 2 * primeBytes, primeBytes);
        copyToSdfPrivateRegion(key.getPrimeExponentQ(), ref, 3 * keyBytes + 3 * primeBytes, primeBytes);
        copyToSdfPrivateRegion(key.getCrtCoefficient(), ref, 3 * keyBytes + 4 * primeBytes, primeBytes);
        return ref;
    }

    /**
     * 将 value 右对齐写入 JNA 私钥结构体的一个数值子区间。
     *
     * <p>JNA 结构体字段的字节区间（相对 m 字段起点，即 bits 之后的偏移）固定为：
     * m=[0,512) e=[512,1024) d=[1024,1536) p=[1536,1792) q=[1792,2048)
     * dp=[2048,2304) dq=[2304,2560) qinv=[2560,2816)。数盾库按变长布局读取，各子区间
     * 随 keyBytes 平移，故按 relOffset 定位到对应字段再写入。
     */
    private static void copyToSdfPrivateRegion(BigInteger value, RSArefPrivateKey.ByReference ref,
            int relOffset, int fieldLen) {
        byte[] target;
        int base;
        if (relOffset < 512) {
            target = ref.m;
            base = relOffset;
        } else if (relOffset < 1024) {
            target = ref.e;
            base = relOffset - 512;
        } else if (relOffset < 1536) {
            target = ref.d;
            base = relOffset - 1024;
        } else if (relOffset < 1792) {
            target = ref.p;
            base = relOffset - 1536;
        } else if (relOffset < 2048) {
            target = ref.q;
            base = relOffset - 1792;
        } else if (relOffset < 2304) {
            target = ref.dp;
            base = relOffset - 2048;
        } else if (relOffset < 2560) {
            target = ref.dq;
            base = relOffset - 2304;
        } else {
            target = ref.qinv;
            base = relOffset - 2560;
        }
        if (base < 0 || base + fieldLen > target.length) {
            throw new IllegalArgumentException(
                    "RSA private key region out of JNA buffer: bits=" + ref.bits
                            + " relOffset=" + relOffset + " fieldLen=" + fieldLen);
        }
        copyToSdfBuffer(value, target, base, fieldLen);
    }

    private static void copyToSdfBuffer(BigInteger value, byte[] buffer, int startOffset, int fieldLen) {
        byte[] bytes = value.toByteArray();
        int srcOffset = (bytes[0] == 0 && bytes.length > 1) ? 1 : 0;
        int length = bytes.length - srcOffset;
        int destOffset = startOffset + fieldLen - length;
        System.arraycopy(bytes, srcOffset, buffer, destOffset, length);
    }
}
