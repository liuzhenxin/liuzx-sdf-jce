package org.liuzx.jce.provider.test;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.liuzx.jce.provider.LiuZXProvider;

import java.nio.charset.StandardCharsets;
import java.security.*;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class SM2SignatureTest {

    @BeforeAll
    public static void setup() {
        if (Security.getProvider(LiuZXProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new LiuZXProvider());
        }
    }

    @Test
    public void testSignAndVerify() throws Exception {
        // 1. 生成密钥对
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", LiuZXProvider.PROVIDER_NAME);
        KeyPair keyPair = kpg.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // 2. 获取Signature实例
        Signature signature = Signature.getInstance("SM3withSM2", LiuZXProvider.PROVIDER_NAME);

        // 3. 初始化签名
        signature.initSign(privateKey);

        // 4. 更新待签名数据
        byte[] data = "Hello, SM2!".getBytes(StandardCharsets.UTF_8);
        signature.update(data);

        // 5. 执行签名
        byte[] sigBytes = signature.sign();
        System.out.println("SM2 Signature: " + toHexString(sigBytes));

        // 6. 初始化验签
        signature.initVerify(publicKey);

        // 7. 更新待验证数据
        signature.update(data);

        // 8. 执行验签
        boolean result = signature.verify(sigBytes);

        // 9. 断言结果
        assertTrue(result, "Signature verification should be successful");
    }

    private String toHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
