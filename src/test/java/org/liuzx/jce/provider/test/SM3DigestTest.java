package org.liuzx.jce.provider.test;

import org.junit.jupiter.api.Test;
import org.liuzx.jce.provider.LiuZXProvider;

import java.security.MessageDigest;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class SM3DigestTest {

    @Test
    public void testSM3() throws Exception {
        Security.addProvider(new LiuZXProvider());
        MessageDigest md = MessageDigest.getInstance("SM3", LiuZXProvider.PROVIDER_NAME);
        md.update("hello world".getBytes());
        byte[] digest = md.digest();
        // This is the expected SM3 hash of "hello world"
        // 用 openssl dgst -sm3 与数盾设备实测一致，修正了原有过时/错误的期望值
        String expectedHash = "44F0061E69FA6FDFC290C494654A05DC0C053DA7E5C52B84EF93A9D67D3FFF88";
        assertEquals(expectedHash, toHexString(digest));
    }

    private String toHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
