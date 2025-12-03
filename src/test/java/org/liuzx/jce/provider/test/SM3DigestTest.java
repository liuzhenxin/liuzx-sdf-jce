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
        MessageDigest md = MessageDigest.getInstance("SM3", "liuzx");
        md.update("hello world".getBytes());
        byte[] digest = md.digest();
        // This is the expected SM3 hash of "hello world"
        String expectedHash = "44F0061E5145A584342534295496044A5B55CB53383995877F54044D2B4421B2";
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
