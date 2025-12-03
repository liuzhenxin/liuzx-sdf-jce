package org.liuzx.jce.provider.test;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.liuzx.jce.provider.LiuZXProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class SM4CipherTest {

    @BeforeAll
    public static void setup() {
        if (Security.getProvider(LiuZXProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new LiuZXProvider());
        }
    }

    @Test
    public void testEcbEncryptAndDecrypt() throws Exception {
        // 1. 生成SM4密钥
        KeyGenerator kg = KeyGenerator.getInstance("SM4", LiuZXProvider.PROVIDER_NAME);
        kg.init(128);
        SecretKey secretKey = kg.generateKey();

        // 2. 获取Cipher实例 (ECB模式)
        Cipher cipher = Cipher.getInstance("SM4/ECB/PKCS5Padding", LiuZXProvider.PROVIDER_NAME);

        // 3. 加密
        byte[] plaintext = "SM4 ECB test message".getBytes(StandardCharsets.UTF_8);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] ciphertext = cipher.doFinal(plaintext);

        // 4. 解密
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedText = cipher.doFinal(ciphertext);

        // 5. 验证
        assertArrayEquals(plaintext, decryptedText);
    }

    @Test
    public void testCbcEncryptAndDecrypt() throws Exception {
        // 1. 生成SM4密钥
        KeyGenerator kg = KeyGenerator.getInstance("SM4", LiuZXProvider.PROVIDER_NAME);
        kg.init(128);
        SecretKey secretKey = kg.generateKey();

        // 2. 获取Cipher实例 (CBC模式)
        Cipher cipher = Cipher.getInstance("SM4/CBC/PKCS5Padding", LiuZXProvider.PROVIDER_NAME);
        byte[] iv = new byte[16]; // IV, for testing purposes, use a fixed one
        Arrays.fill(iv, (byte) 0x01);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // 3. 加密
        byte[] plaintext = "SM4 CBC test message, slightly longer".getBytes(StandardCharsets.UTF_8);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] ciphertext = cipher.doFinal(plaintext);

        // 4. 解密
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] decryptedText = cipher.doFinal(ciphertext);

        // 5. 验证
        assertArrayEquals(plaintext, decryptedText);
    }
}
