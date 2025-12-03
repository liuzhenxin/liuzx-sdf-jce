package org.liuzx.jce.provider.util;

import org.liuzx.jce.jna.structure.ECCCipher;
import org.liuzx.jce.jna.structure.ECCrefPrivateKey;
import org.liuzx.jce.jna.structure.ECCrefPublicKey;
import org.liuzx.jce.jna.structure.ECCSignature;

import javax.crypto.BadPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SignatureException;
import java.util.Arrays;

public final class ASN1Util {

    private static final int ASN1_SEQUENCE = 0x30;
    private static final int ASN1_INTEGER = 0x02;
    private static final int ASN1_OCTET_STRING = 0x04;
    private static final int ASN1_OBJECT_IDENTIFIER = 0x06;
    private static final int ASN1_BIT_STRING = 0x03;
    private static final int ASN1_CONTEXT_SPECIFIC_0 = 0xA0;
    private static final int ASN1_CONTEXT_SPECIFIC_1 = 0xA1;

    // ... (existing signature, ciphertext, and X.509 methods)

    public static byte[] toPKCS8PrivateKey(ECCrefPrivateKey privateKey, ECCrefPublicKey publicKey) throws IOException {
        // --- Inner ECPrivateKey structure ---
        ByteArrayOutputStream ecPrivateKeyStream = new ByteArrayOutputStream();
        
        // 1. version (INTEGER, 1)
        writeTLV(ecPrivateKeyStream, ASN1_INTEGER, new byte[]{0x01}, false);

        // 2. privateKey (OCTET STRING)
        byte[] d = trimLeadingZeros(privateKey.K);
        writeTLV(ecPrivateKeyStream, ASN1_OCTET_STRING, d, false);

        // 3. parameters [0] (OBJECT IDENTIFIER)
        ByteArrayOutputStream paramsStream = new ByteArrayOutputStream();
        writeTLV(paramsStream, ASN1_OBJECT_IDENTIFIER, GMObjectIdentifiers.OID_SM2_P256V1, false);
        writeTLV(ecPrivateKeyStream, ASN1_CONTEXT_SPECIFIC_0, paramsStream.toByteArray(), false);

        // 4. publicKey [1] (BIT STRING)
        ByteArrayOutputStream pubKeyBitStringStream = new ByteArrayOutputStream();
        pubKeyBitStringStream.write(0x00); // Unused bits
        pubKeyBitStringStream.write(0x04); // Uncompressed point indicator
        pubKeyBitStringStream.write(publicKey.x);
        pubKeyBitStringStream.write(publicKey.y);
        writeTLV(ecPrivateKeyStream, ASN1_CONTEXT_SPECIFIC_1, pubKeyBitStringStream.toByteArray(), false);

        byte[] ecPrivateKeyBytes = ecPrivateKeyStream.toByteArray();

        // --- Outer PrivateKeyInfo structure ---
        ByteArrayOutputStream privateKeyInfoStream = new ByteArrayOutputStream();

        // 1. version (INTEGER, 0)
        writeTLV(privateKeyInfoStream, ASN1_INTEGER, new byte[]{0x00}, false);

        // 2. privateKeyAlgorithm (AlgorithmIdentifier)
        ByteArrayOutputStream algIdStream = new ByteArrayOutputStream();
        writeTLV(algIdStream, ASN1_OBJECT_IDENTIFIER, GMObjectIdentifiers.OID_SM2_PUBLIC_KEY_ENCRYPTION, false);
        writeTLV(algIdStream, ASN1_OBJECT_IDENTIFIER, GMObjectIdentifiers.OID_SM2_P256V1, false);
        writeTLV(privateKeyInfoStream, ASN1_SEQUENCE, algIdStream.toByteArray(), false);

        // 3. privateKey (OCTET STRING containing the ECPrivateKey structure)
        writeTLV(privateKeyInfoStream, ASN1_OCTET_STRING, ecPrivateKeyBytes, false);

        // Wrap everything in a final SEQUENCE
        ByteArrayOutputStream finalStream = new ByteArrayOutputStream();
        writeTLV(finalStream, ASN1_SEQUENCE, privateKeyInfoStream.toByteArray(), false);

        return finalStream.toByteArray();
    }
    
    // --- Existing Methods Below ---
    public static byte[] toX509PublicKey(ECCrefPublicKey sm2PublicKey) throws IOException {
        ByteArrayOutputStream spStream = new ByteArrayOutputStream();
        spStream.write(0x00);
        spStream.write(0x04);
        spStream.write(sm2PublicKey.x);
        spStream.write(sm2PublicKey.y);
        byte[] subjectPublicKeyBytes = spStream.toByteArray();
        
        ByteArrayOutputStream algIdStream = new ByteArrayOutputStream();
        writeTLV(algIdStream, ASN1_OBJECT_IDENTIFIER, GMObjectIdentifiers.OID_SM2_PUBLIC_KEY_ENCRYPTION, false);
        writeTLV(algIdStream, ASN1_OBJECT_IDENTIFIER, GMObjectIdentifiers.OID_SM2_P256V1, false);
        byte[] algIdBytes = algIdStream.toByteArray();

        ByteArrayOutputStream resultStream = new ByteArrayOutputStream();
        writeTLV(resultStream, ASN1_SEQUENCE, algIdBytes, false);
        writeTLV(resultStream, ASN1_BIT_STRING, subjectPublicKeyBytes, false);

        ByteArrayOutputStream finalStream = new ByteArrayOutputStream();
        writeTLV(finalStream, ASN1_SEQUENCE, resultStream.toByteArray(), false);
        return finalStream.toByteArray();
    }
    
    public static byte[] toASN1Signature(ECCSignature eccSignature) throws IOException {
        byte[] r = trimLeadingZeros(eccSignature.r);
        byte[] s = trimLeadingZeros(eccSignature.s);
        int rLen = calculateTLVLength(r, true);
        int sLen = calculateTLVLength(s, true);
        int seqLen = rLen + sLen;
        ByteArrayOutputStream der = new ByteArrayOutputStream();
        writeTL(der, ASN1_SEQUENCE, seqLen);
        writeTLV(der, ASN1_INTEGER, r, true);
        writeTLV(der, ASN1_INTEGER, s, true);
        return der.toByteArray();
    }

    public static ECCSignature fromASN1Signature(byte[] asn1Signature) throws SignatureException {
        try {
            int offset = 0;
            if (asn1Signature[offset++] != ASN1_SEQUENCE) throw new SignatureException("Not a valid ASN.1 SEQUENCE");
            int seqLength = readLength(asn1Signature, offset);
            offset += calculateLengthBytes(seqLength);
            byte[] r = readTLV(asn1Signature, offset, ASN1_INTEGER);
            offset += calculateTLVLength(r, true);
            byte[] s = readTLV(asn1Signature, offset, ASN1_INTEGER);
            ECCSignature eccSignature = new ECCSignature();
            System.arraycopy(r, 0, eccSignature.r, eccSignature.r.length - r.length, r.length);
            System.arraycopy(s, 0, eccSignature.s, eccSignature.s.length - s.length, s.length);
            return eccSignature;
        } catch (Exception e) {
            throw new SignatureException("Failed to decode ASN.1 signature", e);
        }
    }

    public static byte[] toASN1Ciphertext(ECCCipher eccCipher) throws IOException {
        byte[] x = trimLeadingZeros(eccCipher.x);
        byte[] y = trimLeadingZeros(eccCipher.y);
        byte[] c3 = Arrays.copyOfRange(eccCipher.M, 0, 32);
        byte[] c2 = Arrays.copyOfRange(eccCipher.C, 0, eccCipher.L);
        int xLen = calculateTLVLength(x, true);
        int yLen = calculateTLVLength(y, true);
        int c3Len = calculateTLVLength(c3, false);
        int c2Len = calculateTLVLength(c2, false);
        int seqLen = xLen + yLen + c3Len + c2Len;
        ByteArrayOutputStream der = new ByteArrayOutputStream();
        writeTL(der, ASN1_SEQUENCE, seqLen);
        writeTLV(der, ASN1_INTEGER, x, true);
        writeTLV(der, ASN1_INTEGER, y, true);
        writeTLV(der, ASN1_OCTET_STRING, c3, false);
        writeTLV(der, ASN1_OCTET_STRING, c2, false);
        return der.toByteArray();
    }

    public static ECCCipher fromASN1Ciphertext(byte[] asn1Ciphertext) throws BadPaddingException {
        try {
            int offset = 0;
            if (asn1Ciphertext[offset++] != ASN1_SEQUENCE) throw new BadPaddingException("Not a valid ASN.1 SEQUENCE");
            int seqLength = readLength(asn1Ciphertext, offset);
            offset += calculateLengthBytes(seqLength);
            byte[] x = readTLV(asn1Ciphertext, offset, ASN1_INTEGER);
            offset += calculateTLVLength(x, true);
            byte[] y = readTLV(asn1Ciphertext, offset, ASN1_INTEGER);
            offset += calculateTLVLength(y, true);
            byte[] c3 = readTLV(asn1Ciphertext, offset, ASN1_OCTET_STRING);
            offset += calculateTLVLength(c3, false);
            byte[] c2 = readTLV(asn1Ciphertext, offset, ASN1_OCTET_STRING);
            ECCCipher eccCipher = new ECCCipher();
            System.arraycopy(x, 0, eccCipher.x, eccCipher.x.length - x.length, x.length);
            System.arraycopy(y, 0, eccCipher.y, eccCipher.y.length - y.length, y.length);
            System.arraycopy(c3, 0, eccCipher.M, 0, c3.length);
            eccCipher.L = c2.length;
            System.arraycopy(c2, 0, eccCipher.C, 0, c2.length);
            return eccCipher;
        } catch (Exception e) {
            throw new BadPaddingException("Failed to decode ASN.1 ciphertext: " + e.getMessage());
        }
    }

    private static byte[] trimLeadingZeros(byte[] data) {
        int firstNonZero = 0;
        while (firstNonZero < data.length - 1 && data[firstNonZero] == 0) firstNonZero++;
        if (firstNonZero == 0) return data;
        byte[] trimmed = new byte[data.length - firstNonZero];
        System.arraycopy(data, firstNonZero, trimmed, 0, trimmed.length);
        return trimmed;
    }

    private static int calculateTLVLength(byte[] value, boolean isInteger) {
        int valueLen = value.length;
        if (isInteger && value.length > 0 && value[0] < 0) valueLen++;
        return 1 + calculateLengthBytes(valueLen) + valueLen;
    }

    private static int calculateLengthBytes(int length) {
        if (length < 128) return 1;
        if (length < 0x100) return 2;
        if (length < 0x10000) return 3;
        if (length < 0x1000000) return 4;
        return 5;
    }

    private static void writeTL(ByteArrayOutputStream out, int tag, int length) throws IOException {
        out.write(tag);
        if (length < 128) {
            out.write(length);
        } else {
            byte[] lenBytes = toBytes(length);
            out.write(0x80 | lenBytes.length);
            out.write(lenBytes);
        }
    }

    private static void writeTLV(ByteArrayOutputStream out, int tag, byte[] value, boolean isInteger) throws IOException {
        boolean prependZero = isInteger && value.length > 0 && value[0] < 0;
        int length = prependZero ? value.length + 1 : value.length;
        writeTL(out, tag, length);
        if (prependZero) out.write(0x00);
        out.write(value);
    }

    private static byte[] readTLV(byte[] data, int offset, int expectedTag) throws IOException {
        if (offset >= data.length || data[offset] != expectedTag) throw new IOException("Invalid ASN.1 tag. Expected " + expectedTag);
        offset++;
        int length = readLength(data, offset);
        offset += calculateLengthBytes(length);
        byte[] value = new byte[length];
        System.arraycopy(data, offset, value, 0, length);
        return value;
    }

    private static int readLength(byte[] data, int offset) {
        int length = data[offset] & 0xFF;
        if ((length & 0x80) == 0) return length;
        int numOctets = length & 0x7F;
        if (numOctets == 0 || numOctets > 4 || offset + numOctets >= data.length) throw new IllegalArgumentException("Invalid length field");
        length = 0;
        for (int i = 0; i < numOctets; i++) {
            length = (length << 8) | (data[offset + 1 + i] & 0xFF);
        }
        return length;
    }

    private static byte[] toBytes(int value) {
        if (value < 0x100) return new byte[]{(byte) value};
        if (value < 0x10000) return new byte[]{(byte) (value >> 8), (byte) value};
        if (value < 0x1000000) return new byte[]{(byte) (value >> 16), (byte) (value >> 8), (byte) value};
        return new byte[]{(byte) (value >> 24), (byte) (value >> 16), (byte) (value >> 8), (byte) value};
    }
}
