package org.liuzx.jce.provider.asymmetric.rsa;

import org.liuzx.jce.jna.structure.RSArefPrivateKey;
import org.liuzx.jce.jna.structure.RSArefPublicKey;
import org.liuzx.jce.provider.SDFConfig;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

/** Converts Java RSA keys to the fixed or vendor-packed SDF ABI. */
final class RSAKeyConverter {

    private static final int PUBLIC_FIELD_BYTES = 512;
    private static final int PRIME_FIELD_BYTES = 256;

    private RSAKeyConverter() {
    }

    static RSArefPublicKey.ByReference toSdfPublicKey(RSAPublicKey key) {
        return toSdfPublicKey(key, SDFConfig.getInstance().getRsaKeyLayout());
    }

    static RSArefPublicKey.ByReference toSdfPublicKey(
            RSAPublicKey key, SDFConfig.RsaKeyLayout layout) {
        RSArefPublicKey.ByReference ref = new RSArefPublicKey.ByReference();
        int bits = key.getModulus().bitLength();
        int keyBytes = keyBytes(bits);
        ref.bits = bits;

        if (layout == SDFConfig.RsaKeyLayout.STANDARD) {
            copyRightAligned(key.getModulus(), ref.m, 0, ref.m.length);
            copyRightAligned(key.getPublicExponent(), ref.e, 0, ref.e.length);
        } else {
            byte[] packed = new byte[PUBLIC_FIELD_BYTES * 2];
            copyRightAligned(key.getModulus(), packed, 0, keyBytes);
            copyRightAligned(key.getPublicExponent(), packed, keyBytes, keyBytes);
            copyFromCombined(packed, ref.m, ref.e);
        }
        return ref;
    }

    static RSArefPrivateKey.ByReference toSdfPrivateKey(SDFRSAPrivateKey key) {
        return toSdfPrivateKey(key, SDFConfig.getInstance().getRsaKeyLayout());
    }

    static RSArefPrivateKey.ByReference toSdfPrivateKey(
            SDFRSAPrivateKey key, SDFConfig.RsaKeyLayout layout) {
        RSArefPrivateKey.ByReference ref = new RSArefPrivateKey.ByReference();
        int bits = key.getModulus().bitLength();
        int keyBytes = keyBytes(bits);
        int primeBytes = primeBytes(keyBytes);
        ref.bits = bits;

        if (layout == SDFConfig.RsaKeyLayout.STANDARD) {
            copyRightAligned(key.getModulus(), ref.m, 0, ref.m.length);
            copyRightAligned(key.getPublicExponent(), ref.e, 0, ref.e.length);
            copyRightAligned(key.getPrivateExponent(), ref.d, 0, ref.d.length);
            copyRightAligned(key.getPrimeP(), ref.p, 0, ref.p.length);
            copyRightAligned(key.getPrimeQ(), ref.q, 0, ref.q.length);
            copyRightAligned(key.getPrimeExponentP(), ref.dp, 0, ref.dp.length);
            copyRightAligned(key.getPrimeExponentQ(), ref.dq, 0, ref.dq.length);
            copyRightAligned(key.getCrtCoefficient(), ref.qinv, 0, ref.qinv.length);
        } else {
            byte[] packed = new byte[3 * PUBLIC_FIELD_BYTES + 5 * PRIME_FIELD_BYTES];
            copyRightAligned(key.getModulus(), packed, 0, keyBytes);
            copyRightAligned(key.getPublicExponent(), packed, keyBytes, keyBytes);
            copyRightAligned(key.getPrivateExponent(), packed, 2 * keyBytes, keyBytes);
            copyRightAligned(key.getPrimeP(), packed, 3 * keyBytes, primeBytes);
            copyRightAligned(key.getPrimeQ(), packed, 3 * keyBytes + primeBytes, primeBytes);
            copyRightAligned(key.getPrimeExponentP(), packed, 3 * keyBytes + 2 * primeBytes, primeBytes);
            copyRightAligned(key.getPrimeExponentQ(), packed, 3 * keyBytes + 3 * primeBytes, primeBytes);
            copyRightAligned(key.getCrtCoefficient(), packed, 3 * keyBytes + 4 * primeBytes, primeBytes);
            copyFromCombined(packed, ref.m, ref.e, ref.d, ref.p, ref.q, ref.dp, ref.dq, ref.qinv);
        }
        return ref;
    }

    static int keyBytes(int bits) {
        int bytes = (bits + 7) / 8;
        if (bytes <= 0 || bytes > PUBLIC_FIELD_BYTES) {
            throw new IllegalArgumentException("Unsupported RSA key size: " + bits + " bits");
        }
        return bytes;
    }

    static int primeBytes(int keyBytes) {
        return (keyBytes + 1) / 2;
    }

    static BigInteger readRightAligned(byte[] field, int valueBytes) {
        if (valueBytes <= 0 || valueBytes > field.length) {
            throw new IllegalArgumentException("Invalid RSA value length: " + valueBytes);
        }
        byte[] value = new byte[valueBytes];
        System.arraycopy(field, field.length - valueBytes, value, 0, valueBytes);
        return new BigInteger(1, value);
    }

    static BigInteger readPacked(byte[] packed, int offset, int valueBytes) {
        if (offset < 0 || valueBytes <= 0 || offset + valueBytes > packed.length) {
            throw new IllegalArgumentException("RSA packed region is out of bounds: offset="
                    + offset + " length=" + valueBytes + " capacity=" + packed.length);
        }
        byte[] value = new byte[valueBytes];
        System.arraycopy(packed, offset, value, 0, valueBytes);
        return new BigInteger(1, value);
    }

    static byte[] combine(byte[]... fields) {
        int length = 0;
        for (byte[] field : fields) {
            length += field.length;
        }
        byte[] combined = new byte[length];
        int offset = 0;
        for (byte[] field : fields) {
            System.arraycopy(field, 0, combined, offset, field.length);
            offset += field.length;
        }
        return combined;
    }

    private static void copyFromCombined(byte[] combined, byte[]... fields) {
        int offset = 0;
        for (byte[] field : fields) {
            System.arraycopy(combined, offset, field, 0, field.length);
            offset += field.length;
        }
    }

    private static void copyRightAligned(BigInteger value, byte[] buffer, int startOffset, int fieldLength) {
        if (value == null || value.signum() < 0) {
            throw new IllegalArgumentException("RSA value must be a non-negative integer");
        }
        if (startOffset < 0 || fieldLength <= 0 || startOffset + fieldLength > buffer.length) {
            throw new IllegalArgumentException("RSA target region is out of bounds");
        }
        byte[] bytes = value.toByteArray();
        int sourceOffset = bytes.length > 1 && bytes[0] == 0 ? 1 : 0;
        int length = bytes.length - sourceOffset;
        if (length > fieldLength) {
            throw new IllegalArgumentException("RSA value needs " + length
                    + " bytes but field has only " + fieldLength);
        }
        int destinationOffset = startOffset + fieldLength - length;
        System.arraycopy(bytes, sourceOffset, buffer, destinationOffset, length);
    }
}
