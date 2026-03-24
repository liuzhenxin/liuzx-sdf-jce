package org.liuzx.jce.provider.test;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.liuzx.jce.provider.LiuZXProvider;
import org.liuzx.jce.provider.asymmetric.rsa.SDFRSAPrivateKey;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

@DisplayName("Test for SDF-Generated External RSA Key Pair")
public class RSAExternalKeyGenTest {

    @BeforeAll
    public static void setup() {
        Provider provider = Security.getProvider(LiuZXProvider.PROVIDER_NAME);
        if (provider == null) {
            Security.addProvider(new LiuZXProvider());
            System.out.println("Registered LiuZXProvider.");
        }
    }

    @Test
    @DisplayName("Generate an external RSA key pair using SDF and perform sign/verify")
    public void testGenerateAndUseSDFExternalRSAKeyPair() throws Exception {
        System.out.println("--- Testing SDF-Generated External RSA Key Pair Generation ---");

        // 1. 获取我们提供者的KeyPairGenerator实例
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", LiuZXProvider.PROVIDER_NAME);
        assertNotNull(kpg, "KeyPairGenerator should not be null.");

        // 2. 初始化以生成2048位密钥
        kpg.initialize(2048);
        System.out.println("KeyPairGenerator initialized to generate a 2048-bit key via SDF.");

        // 3. 生成密钥对。这将调用SDF_GenerateKeyPair_RSA
        KeyPair keyPair = kpg.generateKeyPair();
        assertNotNull(keyPair, "Generated KeyPair should not be null.");
        System.out.println("SDF-generated external RSA key pair created successfully.");

        // 4. 验证密钥类型和属性
        assertTrue(keyPair.getPublic() instanceof RSAPublicKey, "Public key should be an RSAPublicKey.");
        assertTrue(keyPair.getPrivate() instanceof SDFRSAPrivateKey, "Private key should be an SDFRSAPrivateKey.");
        
        SDFRSAPrivateKey privateKey = (SDFRSAPrivateKey) keyPair.getPrivate();
        assertFalse(privateKey.isInternalKey(), "The generated key should be marked as external.");
        System.out.println("Key types and properties verified.");

        // 5. 验证私钥编码
        byte[] encodedPrivateKey = privateKey.getEncoded();
        assertNotNull(encodedPrivateKey, "Encoded private key should not be null.");
        assertTrue(encodedPrivateKey.length > 0, "Encoded private key should not be empty.");
        System.out.println("Private key encoded to PKCS#8 format successfully. Length: " + encodedPrivateKey.length);

        // 6. 使用默认JCE提供者执行签名和验签，以验证密钥的互操作性
        System.out.println("--- Performing Sign/Verify with the Generated Key ---");
        String algorithm = "SHA256withRSA";
        byte[] data = "This is a test for signing with an SDF-generated external RSA key.".getBytes(StandardCharsets.UTF_8);

        try {
            // 使用默认提供者来验证我们生成的密钥是否标准和可用
            Signature signer = Signature.getInstance(algorithm); 
            signer.initSign(keyPair.getPrivate());
            signer.update(data);
            byte[] signature = signer.sign();
            assertNotNull(signature, "Signature should not be null.");
            System.out.println("Data signed successfully with default provider.");

            Signature verifier = Signature.getInstance(algorithm);
            verifier.initVerify(keyPair.getPublic());
            verifier.update(data);
            boolean isVerified = verifier.verify(signature);
            
            assertTrue(isVerified, "Signature should be valid.");
            System.out.println("SUCCESS: Signature verified successfully with default provider.");

        } catch (Exception e) {
            fail("Sign/Verify operation with the SDF-generated key pair failed.", e);
        }
    }
}
