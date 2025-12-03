package org.liuzx.jce.provider.test;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.liuzx.jce.provider.LiuZXProvider;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class SM2CipherTest {

    @BeforeAll
    public static void setup() {
        if (Security.getProvider(LiuZXProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new LiuZXProvider());
        }
    }

    @Test
    public void testEncryptAndDecrypt() throws Exception {
        // 1. 生成密钥对
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", LiuZXProvider.PROVIDER_NAME);
        KeyPair keyPair = kpg.generateKeyPair();

        // 2. 获取Cipher实例
        Cipher cipher = Cipher.getInstance("SM2", LiuZXProvider.PROVIDER_NAME);

        // 3. 初始化加密
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

        // 4. 执行加密
        byte[] plaintext = "This is a test message for SM2 encryption.".getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = cipher.doFinal(plaintext);
        System.out.println("Ciphertext (hex): " + toHexString(ciphertext));

        // 5. 初始化解密
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

        // 6. 执行解密
        byte[] decryptedText = cipher.doFinal(ciphertext);

        // 7. 验证结果
        assertArrayEquals(plaintext, decryptedText, "Decrypted text should match original plaintext");
    }

    private String toHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
