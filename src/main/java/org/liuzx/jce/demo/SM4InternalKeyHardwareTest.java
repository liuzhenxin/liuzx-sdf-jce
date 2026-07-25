package org.liuzx.jce.demo;

import org.liuzx.jce.provider.LiuZXProvider;
import org.liuzx.jce.provider.symmetric.SDFSM4Keys;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Arrays;

/**
 * Hardware smoke test for an SM4 key stored at an internal SDF index.
 */
public final class SM4InternalKeyHardwareTest {

    private static final byte[] TEST_DATA =
            "liuzx-sdf-jce SM4 hardware round-trip".getBytes(StandardCharsets.UTF_8);
    private static final byte[] TEST_IV =
            "0123456789abcdef".getBytes(StandardCharsets.US_ASCII);

    private SM4InternalKeyHardwareTest() {
    }

    public static void main(String[] args) throws Exception {
        int keyIndex = args.length == 0 ? 1 : Integer.parseInt(args[0]);
        Security.addProvider(new LiuZXProvider());

        SecretKey key = SDFSM4Keys.internalKey(keyIndex);
        verifyRoundTrip("SM4/ECB/PKCS5Padding", key, null);
        verifyRoundTrip("SM4/CBC/PKCS5Padding", key, new IvParameterSpec(TEST_IV));

        System.out.println("SM4 hardware test passed: keyIndex=" + keyIndex
                + ", modes=ECB,CBC, plaintextLength=" + TEST_DATA.length);
    }

    private static void verifyRoundTrip(String transformation, SecretKey key, IvParameterSpec iv)
            throws Exception {
        Cipher cipher = Cipher.getInstance(transformation, LiuZXProvider.PROVIDER_NAME);
        if (iv == null) {
            cipher.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        }
        byte[] encrypted = cipher.doFinal(TEST_DATA);

        if (iv == null) {
            cipher.init(Cipher.DECRYPT_MODE, key);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
        }
        byte[] decrypted = cipher.doFinal(encrypted);

        if (!Arrays.equals(TEST_DATA, decrypted)) {
            throw new IllegalStateException(transformation + " round-trip result mismatch");
        }
        System.out.println(transformation + " passed, ciphertextLength=" + encrypted.length);
    }
}
