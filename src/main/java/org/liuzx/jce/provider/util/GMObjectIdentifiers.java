package org.liuzx.jce.provider.util;

/**
 * Object Identifiers for Chinese Government Cryptography standards.
 */
public interface GMObjectIdentifiers {
    // Algorithm OIDs
    byte[] OID_SM2_PUBLIC_KEY_ENCRYPTION = new byte[]{0x2A, (byte)0x86, 0x48, (byte)0xCE, 0x3D, 0x02, 0x01}; // 1.2.840.10045.2.1
    byte[] OID_SM2_P256V1 = new byte[]{0x2A, (byte)0x81, 0x1C, (byte)0xCF, 0x55, 0x01, (byte)0x82, 0x2D}; // 1.2.156.10197.1.301
}
