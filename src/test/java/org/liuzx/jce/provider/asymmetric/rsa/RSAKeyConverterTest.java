package org.liuzx.jce.provider.asymmetric.rsa;

import org.junit.jupiter.api.Test;
import org.liuzx.jce.jna.structure.RSArefPrivateKey;
import org.liuzx.jce.jna.structure.RSArefPublicKey;
import org.liuzx.jce.provider.SDFConfig;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RSAKeyConverterTest {

    @Test
    void standardLayoutUsesFixedRightAlignedFields() {
        TestKeyMaterial key = keyMaterial(2048);

        RSArefPublicKey publicRef = RSAKeyConverter.toSdfPublicKey(
                key.publicKey, SDFConfig.RsaKeyLayout.STANDARD);
        RSArefPrivateKey privateRef = RSAKeyConverter.toSdfPrivateKey(
                key.privateKey, SDFConfig.RsaKeyLayout.STANDARD);

        assertEquals(key.modulus, RSAKeyConverter.readRightAligned(publicRef.m, 256));
        assertEquals(key.publicExponent, RSAKeyConverter.readRightAligned(publicRef.e, publicRef.e.length));
        assertEquals(key.privateExponent, RSAKeyConverter.readRightAligned(privateRef.d, 256));
        assertEquals(key.primeP, RSAKeyConverter.readRightAligned(privateRef.p, 128));
        assertEquals(key.crtCoefficient, RSAKeyConverter.readRightAligned(privateRef.qinv, 128));
    }

    @Test
    void packedLayoutSupportsRegionsCrossingJnaFields() {
        TestKeyMaterial key = keyMaterial(3072);
        int keyBytes = 384;
        int primeBytes = 192;

        RSArefPublicKey publicRef = RSAKeyConverter.toSdfPublicKey(
                key.publicKey, SDFConfig.RsaKeyLayout.PACKED);
        byte[] packedPublic = RSAKeyConverter.combine(publicRef.m, publicRef.e);
        assertEquals(key.modulus, RSAKeyConverter.readPacked(packedPublic, 0, keyBytes));
        assertEquals(key.publicExponent, RSAKeyConverter.readPacked(packedPublic, keyBytes, keyBytes));

        RSArefPrivateKey privateRef = RSAKeyConverter.toSdfPrivateKey(
                key.privateKey, SDFConfig.RsaKeyLayout.PACKED);
        byte[] packedPrivate = RSAKeyConverter.combine(privateRef.m, privateRef.e, privateRef.d,
                privateRef.p, privateRef.q, privateRef.dp, privateRef.dq, privateRef.qinv);
        assertEquals(key.privateExponent,
                RSAKeyConverter.readPacked(packedPrivate, 2 * keyBytes, keyBytes));
        assertEquals(key.primeP,
                RSAKeyConverter.readPacked(packedPrivate, 3 * keyBytes, primeBytes));
        assertEquals(key.crtCoefficient,
                RSAKeyConverter.readPacked(packedPrivate, 3 * keyBytes + 4 * primeBytes, primeBytes));
    }

    private TestKeyMaterial keyMaterial(int bits) {
        int keyBytes = bits / 8;
        int primeBytes = keyBytes / 2;
        BigInteger modulus = value(keyBytes, 0x11);
        BigInteger publicExponent = BigInteger.valueOf(65537);
        BigInteger privateExponent = value(keyBytes, 0x22);
        BigInteger primeP = value(primeBytes, 0x33);
        BigInteger primeQ = value(primeBytes, 0x44);
        BigInteger exponentP = value(primeBytes, 0x55);
        BigInteger exponentQ = value(primeBytes, 0x66);
        BigInteger coefficient = value(primeBytes, 0x77);
        RSAPublicKey publicKey = new SimplePublicKey(modulus, publicExponent);
        SDFRSAPrivateKey privateKey = new SDFRSAPrivateKey(publicKey, privateExponent,
                primeP, primeQ, exponentP, exponentQ, coefficient);
        return new TestKeyMaterial(publicKey, privateKey, modulus, publicExponent,
                privateExponent, primeP, coefficient);
    }

    private BigInteger value(int bytes, int fill) {
        byte[] value = new byte[bytes];
        java.util.Arrays.fill(value, (byte) fill);
        value[0] = (byte) 0x80;
        return new BigInteger(1, value);
    }

    private static class TestKeyMaterial {
        private final RSAPublicKey publicKey;
        private final SDFRSAPrivateKey privateKey;
        private final BigInteger modulus;
        private final BigInteger publicExponent;
        private final BigInteger privateExponent;
        private final BigInteger primeP;
        private final BigInteger crtCoefficient;

        private TestKeyMaterial(RSAPublicKey publicKey, SDFRSAPrivateKey privateKey,
                BigInteger modulus, BigInteger publicExponent, BigInteger privateExponent,
                BigInteger primeP, BigInteger crtCoefficient) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
            this.modulus = modulus;
            this.publicExponent = publicExponent;
            this.privateExponent = privateExponent;
            this.primeP = primeP;
            this.crtCoefficient = crtCoefficient;
        }
    }

    private static class SimplePublicKey implements RSAPublicKey {
        private static final long serialVersionUID = 1L;
        private final BigInteger modulus;
        private final BigInteger publicExponent;

        private SimplePublicKey(BigInteger modulus, BigInteger publicExponent) {
            this.modulus = modulus;
            this.publicExponent = publicExponent;
        }

        @Override public BigInteger getModulus() { return modulus; }
        @Override public BigInteger getPublicExponent() { return publicExponent; }
        @Override public String getAlgorithm() { return "RSA"; }
        @Override public String getFormat() { return null; }
        @Override public byte[] getEncoded() { return null; }
    }
}
