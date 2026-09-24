package org.liuzx.jce.demo;

import org.liuzx.jce.api.SdfDevice;
import org.liuzx.jce.api.SdfDevices;
import org.liuzx.jce.api.SdfErrorCategory;
import org.liuzx.jce.api.SdfException;
import org.liuzx.jce.provider.LiuZXProvider;
import org.liuzx.jce.provider.asymmetric.rsa.RSAInternalKeyGenParameterSpec;
import org.liuzx.jce.provider.asymmetric.rsa.SDFRSAPrivateKey;
import org.liuzx.jce.provider.asymmetric.sm2.SM2InternalKeyGenParameterSpec;
import org.liuzx.jce.provider.asymmetric.sm2.SM2PrivateKey;
import org.liuzx.jce.provider.asymmetric.sm2.SM2PublicKey;
import org.liuzx.jce.provider.session.SDFDeviceOpener;
import org.liuzx.jce.provider.session.SDFSessionManager;
import org.liuzx.jce.provider.symmetric.SDFSM4Keys;
import org.liuzx.jce.provider.util.DeviceInfoUtil;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Non-interactive SDF JCE smoke test.
 *
 * <p>Runs a fixed battery of checks against a connected SDF device and prints one
 * {@code [PASS]}/{@code [FAIL]}/{@code [SKIP]} line per check. Only external-key and
 * digest/symmetric operations are required, so it works on any vendor without knowing
 * pre-provisioned internal key indices. Internal-key checks run only when the matching
 * {@code -Dliuzx.sdf.smoke.*} property is supplied.</p>
 *
 * <p>Exit code {@code 0} means every required check passed.</p>
 *
 * <p>Supported properties:</p>
 * <ul>
 *   <li>{@code liuzx.sdf.smoke.sm2SignIndex} + {@code liuzx.sdf.smoke.pin}</li>
 *   <li>{@code liuzx.sdf.smoke.rsaSignIndex} + {@code liuzx.sdf.smoke.pin}</li>
 *   <li>{@code liuzx.sdf.smoke.sm4KeyIndex}</li>
 * </ul>
 */
public final class SdfSmokeTest {

    private static final String PROVIDER = LiuZXProvider.PROVIDER_NAME;

    private static final String[] REQUIRED = {
            "provider", "device-session", "random", "sm3", "sm2-sign", "sm4-cbc", "rsa-sign"
    };

    private static final List<String> FAILED = new ArrayList<String>();

    private static final List<String> PASSED = new ArrayList<String>();

    private static final List<String> SKIPPED = new ArrayList<String>();

    private SdfSmokeTest() {
    }

    public static void main(String[] args) {
        banner();
        Security.addProvider(new LiuZXProvider());

        check("provider", "LiuZX provider registered", () -> {
            if (Security.getProvider(PROVIDER) == null) {
                throw new IllegalStateException("provider not registered");
            }
        });

        check("device-session", "open device + session + device info", () -> {
            DeviceInfoUtil.DeviceInfo info = DeviceInfoUtil.getDeviceInfo();
            System.out.println("      strategy=" + SDFDeviceOpener.getLastSuccessfulOperation()
                    + " device=" + blankToDash(info.getDeviceName())
                    + " serial=" + maskSerial(info.getDeviceSerial())
                    + " deviceVersion=" + info.getDeviceVersion()
                    + " standardVersion=" + info.getStandardVersion());
        });

        if (FAILED.contains("device-session")) {
            System.out.println("[smoke] device/session unavailable; remaining hardware checks skipped");
            summary();
            shutdownSessionManager();
            System.exit(1);
        }

        check("random", "hardware random (32 bytes, non-zero)", () -> {
            byte[] random = new byte[32];
            SecureRandom.getInstance("SDF", PROVIDER).nextBytes(random);
            boolean allZero = true;
            for (byte b : random) {
                if (b != 0) {
                    allZero = false;
                    break;
                }
            }
            if (allZero) {
                throw new IllegalStateException("random output is all zero");
            }
        });

        check("sm3", "SM3(\"abc\") matches known vector", () -> {
            byte[] expected = hex("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
            byte[] actual = MessageDigest.getInstance("SM3", PROVIDER)
                    .digest("abc".getBytes(StandardCharsets.US_ASCII));
            if (!MessageDigest.isEqual(expected, actual)) {
                throw new IllegalStateException("unexpected SM3 digest: " + toHex(actual));
            }
        });

        check("sm2-sign", "external SM2 keypair + SM3withSM2 sign/verify", () -> {
            verifySignature("SM3withSM2", generateKeyPair("SM2", 256));
        });

        check("sm4-cbc", "external SM4/CBC/PKCS5Padding round-trip", () -> sm4RoundTrip("SM4/CBC/PKCS5Padding"));

        check("rsa-sign", "external RSA-2048 + SHA256withRSA sign/verify", () -> {
            verifySignature("SHA256withRSA", generateKeyPair("RSA", 2048));
        });

        optional("sm2-cipher", "external SM2 encrypt/decrypt round-trip", true, () -> {
            KeyPair keyPair = generateKeyPair("SM2", 256);
            byte[] message = "sdf-smoke-sm2".getBytes(StandardCharsets.UTF_8);
            Cipher cipher = Cipher.getInstance("SM2", PROVIDER);
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            byte[] encrypted = cipher.doFinal(message);
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            if (!Arrays.equals(message, cipher.doFinal(encrypted))) {
                throw new IllegalStateException("round-trip mismatch");
            }
        });

        optional("sm4-ecb", "external SM4/ECB/PKCS5Padding round-trip", true, () -> sm4RoundTrip("SM4/ECB/PKCS5Padding"));

        optional("sm4-mac", "SM4MAC over a block-aligned key", true, () -> {
            Mac mac = Mac.getInstance("SM4MAC", PROVIDER);
            mac.init(sm4Key());
            // Some devices (e.g. Shudun) require block-aligned MAC input; the caller pads.
            byte[] message = "sdf-smoke-mac-16".getBytes(StandardCharsets.UTF_8);
            byte[] tag = mac.doFinal(message);
            if (tag.length == 0) {
                throw new IllegalStateException("empty MAC");
            }
        });

        optional("rsa-cipher", "external RSA/ECB/PKCS1Padding round-trip", true, () -> {
            KeyPair keyPair = generateKeyPair("RSA", 2048);
            byte[] message = "sdf-smoke-rsa".getBytes(StandardCharsets.UTF_8);
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", PROVIDER);
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            byte[] encrypted = cipher.doFinal(message);
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            if (!Arrays.equals(message, cipher.doFinal(encrypted))) {
                throw new IllegalStateException("round-trip mismatch");
            }
        });

        runFacadeChecks();
        runInternalChecks();
        summary();
        shutdownSessionManager();
        System.exit(FAILED.isEmpty() ? 0 : 1);
    }

    /**
     * Closes the SDF device explicitly before JVM exit. Vendors such as Shudun require
     * the device to be closed by the application before it terminates, not merely from a
     * JVM shutdown hook.
     */
    private static void shutdownSessionManager() {
        try {
            SDFSessionManager.getInstance().shutdown();
        }
        catch (Throwable ignored) {
            // Best effort: the provider may never have initialised (e.g. library load failure).
        }
    }

    private static void runInternalChecks() {
        final char[] pin = System.getProperty("liuzx.sdf.smoke.pin") == null
                ? null : System.getProperty("liuzx.sdf.smoke.pin").toCharArray();

        final int sm2SignIndex = Integer.getInteger("liuzx.sdf.smoke.sm2SignIndex", -1);
        optional("sm2-sign-internal", "internal SM2 sign index " + sm2SignIndex, sm2SignIndex > 0, () -> {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("SM2", PROVIDER);
            generator.initialize(new SM2InternalKeyGenParameterSpec(sm2SignIndex,
                    SM2InternalKeyGenParameterSpec.KeyType.SIGN));
            KeyPair reference = generator.generateKeyPair();
            SM2PublicKey publicKey = (SM2PublicKey) reference.getPublic();
            PrivateKey privateKey = new SM2PrivateKey(sm2SignIndex, pin, publicKey.getEccPublicKey());
            verifySignature("SM3withSM2", publicKey, privateKey);
        });

        final int rsaSignIndex = Integer.getInteger("liuzx.sdf.smoke.rsaSignIndex", -1);
        optional("rsa-sign-internal", "internal RSA sign index " + rsaSignIndex, rsaSignIndex > 0, () -> {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", PROVIDER);
            generator.initialize(new RSAInternalKeyGenParameterSpec(rsaSignIndex));
            KeyPair reference = generator.generateKeyPair();
            RSAPublicKey publicKey = (RSAPublicKey) reference.getPublic();
            PrivateKey privateKey = new SDFRSAPrivateKey(rsaSignIndex, pin, publicKey);
            verifySignature("SHA256withRSA", publicKey, privateKey);
        });

        final int sm4KeyIndex = Integer.getInteger("liuzx.sdf.smoke.sm4KeyIndex", -1);
        optional("sm4-cbc-internal", "internal SM4 key index " + sm4KeyIndex, sm4KeyIndex > 0, () -> {
            SecretKey key = SDFSM4Keys.internalKey(sm4KeyIndex);
            cipherRoundTrip("SM4/CBC/PKCS5Padding", key);
        });
    }

    /**
     * Facade checks driven by {@code org.liuzx.jce.api}. These prove a consumer can sign
     * without touching JNA types. Enabled by default; disable with
     * {@code -Dliuzx.sdf.smoke.apiFacade=false}. PIN exposure: {@code SMOKE_BAD_PIN} is used
     * only to trigger AUTHORIZATION_FAILED and is never logged.
     */
    private static void runFacadeChecks() {
        final boolean enabled = !"false".equalsIgnoreCase(
                System.getProperty("liuzx.sdf.smoke.apiFacade", "true"));
        final int sm2SignIndex = Integer.getInteger("liuzx.sdf.smoke.sm2SignIndex", -1);
        final int rsaSignIndex = Integer.getInteger("liuzx.sdf.smoke.rsaSignIndex", -1);
        final int missingIndex = Integer.getInteger("liuzx.sdf.smoke.missingIndex", 990001);
        final String badPin = System.getProperty("liuzx.sdf.smoke.badPin");
        final char[] pin = System.getProperty("liuzx.sdf.smoke.pin") == null
                ? null : System.getProperty("liuzx.sdf.smoke.pin").toCharArray();
        final boolean expectDeviceUnavailable = Boolean.parseBoolean(
                System.getProperty("liuzx.sdf.smoke.expectDeviceUnavailable", "false"));
        final boolean expectAuthFailWithoutPin = Boolean.parseBoolean(
                System.getProperty("liuzx.sdf.smoke.expectAuthorizationFailWithoutPin", "false"));
        final int algorithmUnsupportedIndex = Integer.getInteger(
                "liuzx.sdf.smoke.algorithmUnsupportedIndex", -1);

        final SdfDevice[] device = new SdfDevice[1];
        try {
            optional("api-facade-open", "org.liuzx.jce.api facade opens device", enabled, () -> {
                device[0] = SdfDevices.open();
                if (device[0].capabilities().sm2DefaultUserId().isEmpty()) {
                    throw new IllegalStateException("empty sm2DefaultUserId");
                }
                if (device[0].deviceInfo().toSafeString().isEmpty()) {
                    throw new IllegalStateException("empty toSafeString");
                }
            });
            final boolean opened = device[0] != null;

            optional("api-export-public", "facade exportSignPublicKey returns DER",
                    enabled && opened && sm2SignIndex > 0, () -> {
                byte[] encoded = device[0].exportSignPublicKey(sm2SignIndex);
                if (encoded.length == 0 || (encoded[0] & 0xff) != 0x30) {
                    throw new IllegalStateException("not a DER SEQUENCE");
                }
            });

            optional("api-sign-sm2", "facade signSm2 returns 64 bytes",
                    enabled && opened && sm2SignIndex > 0, () -> {
                byte[] signature = device[0].signSm2(sm2SignIndex,
                        "facade".getBytes(StandardCharsets.UTF_8), pin);
                if (signature.length != 64) {
                    throw new IllegalStateException("length=" + signature.length);
                }
            });

            optional("api-sign-sm2-digest", "facade signSm2Digest returns 64 bytes without re-hash",
                    enabled && opened && sm2SignIndex > 0, () -> {
                byte[] digest = new byte[32];
                Arrays.fill(digest, (byte) 1);
                byte[] signature = device[0].signSm2Digest(sm2SignIndex, digest, pin);
                if (signature.length != 64) {
                    throw new IllegalStateException("length=" + signature.length);
                }
            });

            optional("api-sign-rsa", "facade signRsa matches modulus length",
                    enabled && opened && rsaSignIndex > 0, () -> {
                byte[] signature = device[0].signRsa(rsaSignIndex,
                        "facade".getBytes(StandardCharsets.UTF_8), pin);
                if (signature.length != 256 && signature.length != 512) {
                    throw new IllegalStateException("length=" + signature.length);
                }
            });

            optional("api-error-key-not-found", "missing index maps to KEY_NOT_FOUND", enabled && opened, () -> {
                expectCategory(() -> device[0].signSm2(missingIndex, new byte[] {1}, null),
                        SdfErrorCategory.KEY_NOT_FOUND);
            });

            optional("api-error-authorization-failed", "wrong/absent PIN maps to AUTHORIZATION_FAILED",
                    enabled && opened && ((badPin != null && sm2SignIndex > 0)
                            || (expectAuthFailWithoutPin && rsaSignIndex > 0)), () -> {
                if (badPin != null) {
                    expectCategory(() -> device[0].signSm2(sm2SignIndex, new byte[] {1}, badPin.toCharArray()),
                            SdfErrorCategory.AUTHORIZATION_FAILED);
                } else {
                    // Pin-protected key with no PIN supplied: the device rejects the operation
                    // with SDR_PRKRERR, which maps to AUTHORIZATION_FAILED. No wrong-PIN guess.
                    expectCategory(() -> device[0].signRsa(rsaSignIndex, new byte[] {1}, null),
                            SdfErrorCategory.AUTHORIZATION_FAILED);
                }
            });

            optional("api-error-device-unavailable", "DISCONNECT device then expect DEVICE_UNAVAILABLE",
                    enabled && expectDeviceUnavailable, () -> {
                throw new IllegalStateException("set liuzx.sdf.smoke.expectDeviceUnavailable with a disconnected device");
            });

            optional("api-error-algorithm-unsupported", "unsupported algorithm index maps to ALGORITHM_UNSUPPORTED",
                    enabled && opened && algorithmUnsupportedIndex > 0, () -> {
                expectCategory(() -> device[0].signSm2Digest(algorithmUnsupportedIndex, new byte[32], null),
                        SdfErrorCategory.ALGORITHM_UNSUPPORTED);
            });
        }
        finally {
            if (device[0] != null) {
                device[0].close();
            }
        }
    }

    private static void expectCategory(CheckedRunnable action, SdfErrorCategory expected) throws Exception {
        try {
            action.run();
        }
        catch (SdfException e) {
            if (e.category() != expected) {
                throw new IllegalStateException("expected " + expected + " but got " + e.category(), e);
            }
            return;
        }
        throw new IllegalStateException("expected " + expected + " but call succeeded");
    }

    private static KeyPair generateKeyPair(String algorithm, int bits) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm, PROVIDER);
        generator.initialize(bits);
        return generator.generateKeyPair();
    }

    private static SecretKey sm4Key() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("SM4", PROVIDER);
        generator.init(128);
        return generator.generateKey();
    }

    private static void sm4RoundTrip(String transformation) throws Exception {
        cipherRoundTrip(transformation, sm4Key());
    }

    private static void cipherRoundTrip(String transformation, SecretKey key) throws Exception {
        byte[] message = "sdf-smoke-symmetric".getBytes(StandardCharsets.UTF_8);
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        boolean needsIv = transformation.contains("CBC");
        Cipher cipher = Cipher.getInstance(transformation, PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, key, needsIv ? new IvParameterSpec(iv) : null);
        byte[] encrypted = cipher.doFinal(message);
        cipher.init(Cipher.DECRYPT_MODE, key, needsIv ? new IvParameterSpec(iv) : null);
        if (!Arrays.equals(message, cipher.doFinal(encrypted))) {
            throw new IllegalStateException("round-trip mismatch");
        }
    }

    private static void verifySignature(String transformation, KeyPair keyPair) throws Exception {
        verifySignature(transformation, keyPair.getPublic(), keyPair.getPrivate());
    }

    private static void verifySignature(String transformation, java.security.PublicKey publicKey,
            PrivateKey privateKey) throws Exception {
        byte[] message = "sdf-smoke-signature".getBytes(StandardCharsets.UTF_8);
        Signature signer = Signature.getInstance(transformation, PROVIDER);
        signer.initSign(privateKey);
        signer.update(message);
        byte[] signature = signer.sign();
        Signature verifier = Signature.getInstance(transformation, PROVIDER);
        verifier.initVerify(publicKey);
        verifier.update(message);
        if (!verifier.verify(signature)) {
            throw new IllegalStateException("signature verification failed");
        }
    }

    private static void check(String id, String description, CheckedRunnable body) {
        execute(id, description, true, body);
    }

    private static void optional(String id, String description, boolean enabled, CheckedRunnable body) {
        if (!enabled) {
            SKIPPED.add(id);
            System.out.println("[SKIP] " + id + " - " + description);
            return;
        }
        execute(id, description, false, body);
    }

    private static void execute(String id, String description, boolean required, CheckedRunnable body) {
        long startedAt = System.nanoTime();
        try {
            body.run();
            long millis = (System.nanoTime() - startedAt) / 1_000_000L;
            PASSED.add(id);
            System.out.println("[PASS] " + id + " (" + millis + "ms) - " + description);
        }
        catch (Throwable error) {
            String message = describe(error);
            if (required) {
                FAILED.add(id);
                System.out.println("[FAIL] " + id + " - " + description + " -> " + message);
            }
            else {
                SKIPPED.add(id);
                System.out.println("[SKIP] " + id + " - " + description + " -> " + message);
            }
        }
    }

    private static String describe(Throwable error) {
        Throwable root = error;
        for (Throwable cause = error.getCause(); cause != null && cause != root; cause = cause.getCause()) {
            root = cause;
        }
        StringBuilder message = new StringBuilder(root.getClass().getSimpleName());
        if (root.getMessage() != null) {
            message.append(": ").append(root.getMessage());
        }
        if (root != error) {
            message.append(" (root of ").append(error.getClass().getSimpleName()).append(')');
        }
        return message.toString();
    }

    private static void summary() {
        System.out.println();
        System.out.println("=== SDF smoke summary ===");
        System.out.println("required: " + Arrays.toString(REQUIRED));
        System.out.println("passed: " + PASSED.size() + " " + PASSED);
        System.out.println("failed: " + FAILED.size() + " " + FAILED);
        System.out.println("skipped/optional: " + SKIPPED.size() + " " + SKIPPED);
        System.out.println("overall: " + (FAILED.isEmpty() ? "PASS" : "FAIL"));
    }

    private static void banner() {
        System.out.println("=== SDF JCE smoke test ===");
        System.out.println("vendor=" + System.getProperty("liuzx.sdf.vendor", "<default>")
                + " library=" + System.getProperty("liuzx.sdf.library.path", "<profile/classpath>")
                + " config=" + System.getProperty("liuzx.sdf.vendor-config.path", "<none>"));
    }

    private static String maskSerial(String serial) {
        if (serial == null || serial.trim().isEmpty()) {
            return "-";
        }
        String value = serial.trim();
        return value.length() <= 4 ? "****" : "****" + value.substring(value.length() - 4);
    }

    private static String blankToDash(String value) {
        return value == null || value.trim().isEmpty() ? "-" : value;
    }

    private static byte[] hex(String value) {
        byte[] result = new byte[value.length() / 2];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        }
        return result;
    }

    private static String toHex(byte[] value) {
        StringBuilder builder = new StringBuilder(value.length * 2);
        for (byte item : value) {
            builder.append(String.format("%02x", item & 0xff));
        }
        return builder.toString();
    }

    @FunctionalInterface
    private interface CheckedRunnable {
        void run() throws Exception;
    }
}
