package org.liuzx.jce.provider;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * SEC-01 静态门禁：{@code pom.xml} 不得再出现明文 JCE 签名口令，凭据必须属性化。
 *
 * <p>不依赖硬件或 settings.xml；Surefire 的工作目录为项目根，故可直接读取 {@code pom.xml}。</p>
 */
class SigningCredentialConfigTest {

    private static String pomText() throws Exception {
        Path pom = Paths.get("pom.xml");
        assertTrue(Files.isRegularFile(pom), "pom.xml not found from working dir " + Paths.get("").toAbsolutePath());
        return new String(Files.readAllBytes(pom), StandardCharsets.UTF_8);
    }

    @Test
    void pomContainsNoPlaintextSigningPasswords() throws Exception {
        String pom = pomText();
        assertFalse(pom.contains("storepass>123456<"), "pom.xml still contains a plaintext storepass");
        assertFalse(pom.contains("keypass>123456<"), "pom.xml still contains a plaintext keypass");
        assertFalse(pom.contains("storepass=\"123456\""), "pom.xml still contains a plaintext storepass attribute");
        assertFalse(pom.contains("keypass=\"123456\""), "pom.xml still contains a plaintext keypass attribute");
    }

    @Test
    void pomUsesPropertyPlaceholdersForSigningCredentials() throws Exception {
        String pom = pomText();
        assertTrue(pom.contains("${jce.storepass}"), "pom.xml must reference ${jce.storepass}");
        assertTrue(pom.contains("${jce.keypass}"), "pom.xml must reference ${jce.keypass}");
        assertTrue(pom.contains("${jce.keystore}"), "pom.xml must reference ${jce.keystore}");
    }

    @Test
    void pomNoLongerHardcodesTheLegacyAliasPassword() throws Exception {
        String pom = pomText();
        // The legacy alias name may remain as the default property value, but no password literal may.
        assertFalse(pom.contains(">123456<"), "pom.xml still contains the literal password 123456");
    }
}
