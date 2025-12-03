package org.liuzx.jce.provider.test;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.liuzx.jce.jna.structure.ECCrefPublicKey;
import org.liuzx.jce.provider.LiuZXProvider;
import org.liuzx.jce.provider.asymmetric.sm2.SM2InternalKeyGenParameterSpec;
import org.liuzx.jce.provider.asymmetric.sm2.SM2PrivateKey;
import org.liuzx.jce.provider.asymmetric.sm2.SM2PublicKey;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class SM2InternalKeyUsageTest {

    private static final char[] KEY_PASSWORD = "TestPassword123!".toCharArray();
    private static final Random random = new Random();

    @BeforeAll
    public static void setup() {
        Provider provider = Security.getProvider(LiuZXProvider.PROVIDER_NAME);
        if (provider == null) {
            Security.addProvider(new LiuZXProvider());
        }
    }

    @Test
    @Order(1)
    @DisplayName("Load and Use Internal Signing Key Pair WITH Password")
    public void testLoadAndUseInternalSignKeyPairWithPassword() throws Exception {
        int keyIndex = 1000 + random.nextInt(1000);
        System.out.println("--- Testing Internal Signing Key (WITH Password) at Index: " + keyIndex + " ---");

        KeyPair signKeyPairRef = loadInternalKeyPairRef(keyIndex, SM2InternalKeyGenParameterSpec.KeyType.SIGN);

        SM2PrivateKey privateKeyRef = (SM2PrivateKey) signKeyPairRef.getPrivate();
        assertTrue(privateKeyRef.isInternalKey());
        assertEquals(keyIndex, privateKeyRef.getKeyIndex());
        assertNull(privateKeyRef.getEncoded());
        assertNull(privateKeyRef.getPassword());
        System.out.println("Key properties verified successfully.");

        performSignVerify(signKeyPairRef.getPublic(), privateKeyRef, KEY_PASSWORD, "test data for internal signing key with password");
    }

    @Test
    @Order(2)
    @DisplayName("Load and Use Internal Signing Key Pair WITHOUT Password")
    public void testLoadAndUseInternalSignKeyPairWithoutPassword() throws Exception {
        int keyIndex = 1000 + random.nextInt(1000);
        System.out.println("\n--- Testing Internal Signing Key (WITHOUT Password) at Index: " + keyIndex + " ---");

        KeyPair signKeyPairRef = loadInternalKeyPairRef(keyIndex, SM2InternalKeyGenParameterSpec.KeyType.SIGN);

        SM2PrivateKey privateKeyRef = (SM2PrivateKey) signKeyPairRef.getPrivate();
        assertTrue(privateKeyRef.isInternalKey());
        assertEquals(keyIndex, privateKeyRef.getKeyIndex());
        assertNull(privateKeyRef.getPassword());
        System.out.println("Key properties verified successfully.");

        performSignVerify(signKeyPairRef.getPublic(), privateKeyRef, null, "test data for internal signing without password");
    }

    @Test
    @Order(3)
    @DisplayName("Load and Use Internal Encryption Key Pair WITH Password")
    public void testLoadAndUseInternalEncryptKeyPairWithPassword() throws Exception {
        int keyIndex = 1000 + random.nextInt(1000);
        System.out.println("\n--- Testing Internal Encryption Key (WITH Password) at Index: " + keyIndex + " ---");

        KeyPair encryptKeyPairRef = loadInternalKeyPairRef(keyIndex, SM2InternalKeyGenParameterSpec.KeyType.ENCRYPT);

        performEncryptDecrypt(encryptKeyPairRef.getPublic(), encryptKeyPairRef.getPrivate(), KEY_PASSWORD, "test data for internal encryption with password");
    }

    private KeyPair loadInternalKeyPairRef(int keyIndex, SM2InternalKeyGenParameterSpec.KeyType keyType) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", LiuZXProvider.PROVIDER_NAME);
        SM2InternalKeyGenParameterSpec spec = new SM2InternalKeyGenParameterSpec(keyIndex, keyType);
        kpg.initialize(spec);
        KeyPair keyPair = kpg.generateKeyPair();
        assertNotNull(keyPair);
        System.out.println("Internal " + keyType + " key pair reference loaded at index " + keyIndex);
        return keyPair;
    }

    private void performSignVerify(PublicKey publicKeyRef, PrivateKey privateKeyRef, char[] password, String testData) throws Exception {
        System.out.println("--- Performing Sign/Verify ---");
        byte[] data = testData.getBytes(StandardCharsets.UTF_8);
        System.out.println("Test Data: " + testData);

        // Correctly construct the private key for use, including the public key part
        ECCrefPublicKey eccPublicKey = ((SM2PublicKey) publicKeyRef).getEccPublicKey();
        SM2PrivateKey actualPrivateKey = new SM2PrivateKey(((SM2PrivateKey) privateKeyRef).getKeyIndex(), password, eccPublicKey);

        Signature signer = Signature.getInstance("SM3withSM2", LiuZXProvider.PROVIDER_NAME);
        signer.initSign(actualPrivateKey);
        signer.update(data);
        byte[] signature = signer.sign();
        assertNotNull(signature);
        System.out.println("Signature (Hex): " + toHexString(signature));

        Signature verifier = Signature.getInstance("SM3withSM2", LiuZXProvider.PROVIDER_NAME);
        verifier.initVerify(publicKeyRef);
        verifier.update(data);
        boolean result = verifier.verify(signature);
        
        assertTrue(result, "Signature should be valid.");
        System.out.println("SUCCESS: Signature verified successfully.");
    }

    private void performEncryptDecrypt(PublicKey publicKeyRef, PrivateKey privateKeyRef, char[] password, String testData) throws Exception {
        System.out.println("--- Performing Encrypt/Decrypt ---");
        byte[] plaintext = testData.getBytes(StandardCharsets.UTF_8);
        System.out.println("Plaintext: " + testData);

        Cipher cipher = Cipher.getInstance("SM2", LiuZXProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, publicKeyRef);
        byte[] ciphertext = cipher.doFinal(plaintext);
        assertNotNull(ciphertext);
        System.out.println("Ciphertext (Hex): " + toHexString(ciphertext));

        // Correctly construct the private key for use, including the public key part
        ECCrefPublicKey eccPublicKey = ((SM2PublicKey) publicKeyRef).getEccPublicKey();
        SM2PrivateKey actualPrivateKey = new SM2PrivateKey(((SM2PrivateKey) privateKeyRef).getKeyIndex(), password, eccPublicKey);

        cipher.init(Cipher.DECRYPT_MODE, actualPrivateKey);
        byte[] decryptedBytes = cipher.doFinal(ciphertext);
        
        assertArrayEquals(plaintext, decryptedBytes, "Decrypted text should match original plaintext.");
        System.out.println("SUCCESS: Decrypted text matches original plaintext.");
    }

    private static String toHexString(byte[] bytes) {
        if (bytes == null) return "null";
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
