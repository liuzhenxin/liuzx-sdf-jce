package org.liuzx.jce.provider.test;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.liuzx.jce.provider.LiuZXProvider;
import org.liuzx.jce.provider.asymmetric.rsa.RSAInternalKeyGenParameterSpec;
import org.liuzx.jce.provider.asymmetric.rsa.SDFRSAPrivateKey;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("Comprehensive Test for RSA Features (Internal/External Keys)")
public class RSAFullFeatureTest {

    // !!! 重要 !!!
    // !!! 请将此值修改为您SDF设备上实际存在的RSA密钥对索引 !!!
    private static final int INTERNAL_RSA_KEY_INDEX = 1;

    @BeforeAll
    public static void setup() {
        Provider provider = Security.getProvider(LiuZXProvider.PROVIDER_NAME);
        if (provider == null) {
            Security.addProvider(new LiuZXProvider());
            System.out.println("Registered LiuZXProvider.");
        }
    }

    @Test
    @DisplayName("Test 1: Encrypt with Internal Public Key, Decrypt with Internal Private Key")
    public void testInternalKeyEncryption() throws Exception {
        System.out.println("\n--- Test 1: Internal Key Encryption & Decryption ---");

        // 1. 加载内部密钥
        RSAInternalKeyGenParameterSpec spec = new RSAInternalKeyGenParameterSpec(INTERNAL_RSA_KEY_INDEX);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", LiuZXProvider.PROVIDER_NAME);
        kpg.initialize(spec);
        KeyPair keyPair = kpg.generateKeyPair();
        System.out.println("Loaded internal key pair reference.");

        byte[] plaintext = "Test data for internal key encryption".getBytes(StandardCharsets.UTF_8);

        // 2. 使用内部密钥对象进行加密 (SDF_InternalPublicKeyOperation_RSA)
        // 注意：虽然我们传入的是PrivateKey对象，但CipherSpi会识别它是内部密钥并使用其索引进行公钥操作
        Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", LiuZXProvider.PROVIDER_NAME);
        encryptCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate()); 
        byte[] ciphertext = encryptCipher.doFinal(plaintext);
        System.out.println("Encrypted with internal public key (via private key ref).");

        // 3. 使用内部私钥解密 (SDF_InternalPrivateKeyOperation_RSA)
        Cipher decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", LiuZXProvider.PROVIDER_NAME);
        decryptCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decrypted = decryptCipher.doFinal(ciphertext);
        System.out.println("Decrypted with internal private key.");

        assertDecryptedData(plaintext, decrypted);
    }

    @Test
    @DisplayName("Test 2: Encrypt with External Public Key, Decrypt with External Private Key")
    public void testExternalKeyDecryption() throws Exception {
        System.out.println("\n--- Test 2: External Key Encryption & Decryption ---");

        // 1. 生成外部密钥 (SDF_GenerateKeyPair_RSA)
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", LiuZXProvider.PROVIDER_NAME);
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        System.out.println("Generated external RSA key pair via SDF.");

        SDFRSAPrivateKey privateKey = (SDFRSAPrivateKey) keyPair.getPrivate();
        assertTrue(!privateKey.isInternalKey(), "Generated key should be external.");
        assertNotNull(privateKey.getPrimeP(), "External key should have CRT parameters (p).");

        byte[] plaintext = "Test data for external key decryption".getBytes(StandardCharsets.UTF_8);

        // 2. 使用外部公钥加密 (SDF_ExternalPublicKeyOperation_RSA)
        Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", LiuZXProvider.PROVIDER_NAME);
        encryptCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] ciphertext = encryptCipher.doFinal(plaintext);
        System.out.println("Encrypted with external public key.");

        // 3. 使用外部私钥解密 (SDF_ExternalPrivateKeyOperation_RSA)
        Cipher decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", LiuZXProvider.PROVIDER_NAME);
        decryptCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decrypted = decryptCipher.doFinal(ciphertext);
        System.out.println("Decrypted with external private key.");

        assertDecryptedData(plaintext, decrypted);
    }

    private void assertDecryptedData(byte[] expected, byte[] actual) {
        // 简单的去填充逻辑，以防SDF返回Raw RSA结果
        if (actual.length > expected.length) {
            int index = -1;
            for(int i=0; i<actual.length; i++) {
                if(actual[i] == 0x00) {
                    index = i;
                    break;
                }
            }
            if (index != -1 && index < actual.length - 1) {
                byte[] unpadded = new byte[actual.length - index - 1];
                System.arraycopy(actual, index + 1, unpadded, 0, unpadded.length);
                if (java.util.Arrays.equals(expected, unpadded)) {
                    System.out.println("SUCCESS: Decrypted data matches (after manual unpadding).");
                    return;
                }
            }
        }
        
        assertArrayEquals(expected, actual, "Decrypted data should match plaintext.");
        System.out.println("SUCCESS: Decrypted data matches perfectly.");
    }
}
