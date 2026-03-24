package org.liuzx.jce.provider.test;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.liuzx.jce.provider.LiuZXProvider;
import org.liuzx.jce.provider.asymmetric.rsa.RSAInternalKeyGenParameterSpec;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("Test for RSA Internal Key Signing and Verification")
public class RSAInternalKeyUsageTest {

    // !!! 重要 !!!
    // !!! 请将此值修改为您SDF设备上实际存在的RSA密钥对索引 !!!
    private static final int INTERNAL_RSA_KEY_INDEX = 1; 
    
    // 如果访问密钥需要密码，请在此处设置
    private static final char[] KEY_PASSWORD = null; // "123456".toCharArray();

    @BeforeAll
    public static void setup() {
        Provider provider = Security.getProvider(LiuZXProvider.PROVIDER_NAME);
        if (provider == null) {
            Security.addProvider(new LiuZXProvider());
            System.out.println("Registered LiuZXProvider.");
        }
    }

    @Test
    @DisplayName("Load internal RSA key, sign data, and verify signature")
    public void testInternalRSASignAndVerify() throws Exception {
        System.out.println("--- Testing RSA Internal Key at Index: " + INTERNAL_RSA_KEY_INDEX + " ---");

        // 1. 创建一个参数，指定要加载的内部密钥索引
        RSAInternalKeyGenParameterSpec spec = new RSAInternalKeyGenParameterSpec(INTERNAL_RSA_KEY_INDEX);

        // 2. 获取KeyPairGenerator实例，并用我们的provider
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", LiuZXProvider.PROVIDER_NAME);

        // 3. 初始化KeyPairGenerator以“加载”内部密钥
        kpg.initialize(spec);
        System.out.println("KeyPairGenerator initialized to load internal key reference.");

        // 4. "生成"密钥对引用。这会调用SDF_ExportEncPublicKey_RSA
        KeyPair keyPair = kpg.generateKeyPair();
        assertNotNull(keyPair, "KeyPair should not be null.");
        assertNotNull(keyPair.getPublic(), "Public key should not be null.");
        assertNotNull(keyPair.getPrivate(), "Private key reference should not be null.");
        System.out.println("Successfully loaded key pair reference.");
        System.out.println("Public Key Algorithm: " + keyPair.getPublic().getAlgorithm());
        System.out.println("Public Key Format: " + keyPair.getPublic().getFormat());

        // 5. 准备签名
        String algorithm = "SHA256withRSA";
        Signature signer = Signature.getInstance(algorithm, LiuZXProvider.PROVIDER_NAME);
        
        // 使用私钥引用进行初始化。注意：如果需要密码，私钥对象需要能够携带密码信息。
        // 我们当前的SDFRSAPrivateKey设计是在签名时（在SDFUtil中）传递密码。
        signer.initSign(keyPair.getPrivate());
        System.out.println("Signature instance initialized for signing with algorithm: " + algorithm);

        // 6. 更新数据并执行签名
        byte[] data = "This is the data to be signed with the internal RSA key.".getBytes(StandardCharsets.UTF_8);
        signer.update(data);
        byte[] signature = signer.sign(); // 这会调用SDF_InternalSign_RSA
        assertNotNull(signature, "Signature should not be null.");
        System.out.println("Data signed successfully. Signature length: " + signature.length);

        // 7. 准备验签
        Signature verifier = Signature.getInstance(algorithm, LiuZXProvider.PROVIDER_NAME);
        verifier.initVerify(keyPair.getPublic());
        System.out.println("Signature instance initialized for verification.");

        // 8. 更新数据并执行验签
        verifier.update(data);
        boolean isVerified = verifier.verify(signature);
        
        // 9. 断言结果
        assertTrue(isVerified, "Signature should be valid and verification should succeed.");
        System.out.println("SUCCESS: Signature verified successfully!");
    }
}
