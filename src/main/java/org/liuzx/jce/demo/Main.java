package org.liuzx.jce.demo;

import org.liuzx.jce.jna.structure.ECCrefPublicKey;
import org.liuzx.jce.provider.LiuZXProvider;
import org.liuzx.jce.provider.asymmetric.sm2.SM2InternalKeyGenParameterSpec;
import org.liuzx.jce.provider.asymmetric.sm2.SM2PrivateKey;
import org.liuzx.jce.provider.asymmetric.sm2.SM2PublicKey;
import org.liuzx.jce.provider.log.LiuzxProviderLogger;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Locale;
import java.util.Scanner;

public class Main {

    private static final LiuzxProviderLogger logger = LiuzxProviderLogger.getLogger(Main.class);
    private static final String PROVIDER_NAME = LiuZXProvider.PROVIDER_NAME;
    private static final Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) {
        Security.addProvider(new LiuZXProvider());
        logger.info("JCE Provider '{}' registered successfully.", PROVIDER_NAME);

        selectLanguage();

        if (args.length > 0 && "stress".equalsIgnoreCase(args[0])) {
            runStressTestFromArgs(args);
            return;
        }

        while (true) {
            printMenu();
            System.out.print(I18n.get("app.choice") + ": ");
            String choice = scanner.nextLine().toLowerCase();
            System.out.println();

            try {
                switch (choice) {
                    case "1": testInternalSm2Sign(); break;
                    case "2": testInternalSm2Encrypt(); break;
                    case "3": testExternalSm2Sign(); break;
                    case "4": testExternalSm2Encrypt(); break;
                    case "5": testSm4Ecb(); break;
                    case "6": testSm4Cbc(); break;
                    case "7": testSm3(); break;
                    case "8": testInternalSm2SignStress(); break;
                    case "9": testKeyPairGenStress(); break;
                    case "0": logger.info(I18n.get("app.exiting")); return;
                    default: logger.warn(I18n.get("app.invalid_choice") + ": {}", choice); break;
                }
            } catch (Exception e) {
                logger.error(I18n.get("app.error"), e);
            }

            System.out.println("\n" + I18n.get("app.continue"));
            scanner.nextLine();
        }
    }

    private static void selectLanguage() {
        System.out.print("Select language (1: English, 2: 中文): ");
        String langChoice = scanner.nextLine();
        if ("2".equals(langChoice)) {
            I18n.setLocale(Locale.CHINESE);
        } else {
            I18n.setLocale(Locale.ENGLISH);
        }
        System.out.println();
    }

    private static void printMenu() {
        System.out.println("\n--- " + I18n.get("app.title") + " ---");
        System.out.println("1. " + I18n.get("menu.1"));
        System.out.println("2. " + I18n.get("menu.2"));
        System.out.println("3. " + I18n.get("menu.3"));
        System.out.println("4. " + I18n.get("menu.4"));
        System.out.println("5. " + I18n.get("menu.5"));
        System.out.println("6. " + I18n.get("menu.6"));
        System.out.println("7. " + I18n.get("menu.7"));
        System.out.println("8. " + I18n.get("menu.8"));
        System.out.println("9. " + I18n.get("menu.9"));
        System.out.println("---------------------------------");
        System.out.println("0. " + I18n.get("menu.0"));
    }

    private static void testInternalSm2Sign() throws Exception {
        logger.info(I18n.get("test.sm2.internal.sign.title"));
        System.out.print(I18n.get("prompt.key_index.sign") + ": ");
        int keyIndex = Integer.parseInt(scanner.nextLine());
        System.out.print(I18n.get("prompt.password") + ": ");
        char[] password = scanner.nextLine().toCharArray();
        if (password.length == 0) password = null;

        KeyPair keyPairRef = loadInternalKeyPairRef(keyIndex, SM2InternalKeyGenParameterSpec.KeyType.SIGN);
        SM2PublicKey sm2PublicKey = (SM2PublicKey) keyPairRef.getPublic();
        ECCrefPublicKey eccPublicKey = sm2PublicKey.getEccPublicKey();
        PrivateKey privateKeyForUse = new SM2PrivateKey(keyIndex, password, eccPublicKey);
        
        performSignVerify(keyPairRef.getPublic(), privateKeyForUse, "Test data for internal signing key");
    }

    private static void testInternalSm2Encrypt() throws Exception {
        logger.info(I18n.get("test.sm2.internal.encrypt.title"));
        System.out.print(I18n.get("prompt.key_index.encrypt") + ": ");
        int keyIndex = Integer.parseInt(scanner.nextLine());
        System.out.print(I18n.get("prompt.password") + ": ");
        char[] password = scanner.nextLine().toCharArray();
        if (password.length == 0) password = null;

        KeyPair keyPairRef = loadInternalKeyPairRef(keyIndex, SM2InternalKeyGenParameterSpec.KeyType.ENCRYPT);
        SM2PublicKey sm2PublicKey = (SM2PublicKey) keyPairRef.getPublic();
        ECCrefPublicKey eccPublicKey = sm2PublicKey.getEccPublicKey();
        PrivateKey privateKeyForUse = new SM2PrivateKey(keyIndex, password, eccPublicKey);
        
        performEncryptDecrypt(keyPairRef.getPublic(), privateKeyForUse, "Test data for internal encryption key");
    }

    private static void testExternalSm2Sign() throws Exception {
        logger.info(I18n.get("test.sm2.external.sign.title"));
        KeyPair keyPair = generateExternalKeyPair();
        performSignVerify(keyPair.getPublic(), keyPair.getPrivate(), "Test data for external signing key");
    }

    private static void testExternalSm2Encrypt() throws Exception {
        logger.info(I18n.get("test.sm2.external.encrypt.title"));
        KeyPair keyPair = generateExternalKeyPair();
        performEncryptDecrypt(keyPair.getPublic(), keyPair.getPrivate(), "Test data for external encryption key");
    }

    private static void testSm4Ecb() throws Exception {
        logger.info(I18n.get("test.sm4.ecb.title"));
        SecretKey secretKey = generateSm4Key();
        Cipher cipher = Cipher.getInstance("SM4/ECB/PKCS5Padding", PROVIDER_NAME);
        String plaintext = "This is a test for SM4 in ECB mode.";
        logger.info(I18n.get("msg.plaintext") + ": {}", plaintext);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        logger.info(I18n.get("msg.ciphertext.hex") + ": {}", toHexString(ciphertext));

        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(ciphertext);
        String decryptedText = new String(decryptedBytes, StandardCharsets.UTF_8);
        logger.info(I18n.get("msg.decrypted.text") + ": {}", decryptedText);

        if (plaintext.equals(decryptedText)) logger.info("{}: {}", I18n.get("msg.success"), I18n.get("msg.decrypt.match"));
        else logger.error("{}: {}", I18n.get("msg.failure"), I18n.get("msg.decrypt.mismatch"));
    }

    private static void testSm4Cbc() throws Exception {
        logger.info(I18n.get("test.sm4.cbc.title"));
        SecretKey secretKey = generateSm4Key();
        byte[] ivBytes = new byte[16];
        SecureRandom.getInstance("SDF", PROVIDER_NAME).nextBytes(ivBytes);
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        logger.info(I18n.get("msg.iv.generated") + ": {}", toHexString(ivBytes));

        Cipher cipher = Cipher.getInstance("SM4/CBC/PKCS5Padding", PROVIDER_NAME);
        String plaintext = "This is a slightly longer test for SM4 in CBC mode.";
        logger.info(I18n.get("msg.plaintext") + ": {}", plaintext);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        logger.info(I18n.get("msg.ciphertext.hex") + ": {}", toHexString(ciphertext));

        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] decryptedBytes = cipher.doFinal(ciphertext);
        String decryptedText = new String(decryptedBytes, StandardCharsets.UTF_8);
        logger.info(I18n.get("msg.decrypted.text") + ": {}", decryptedText);

        if (plaintext.equals(decryptedText)) logger.info("{}: {}", I18n.get("msg.success"), I18n.get("msg.decrypt.match"));
        else logger.error("{}: {}", I18n.get("msg.failure"), I18n.get("msg.decrypt.mismatch"));
    }

    private static void testSm3() throws Exception {
        logger.info(I18n.get("test.sm3.title"));
        System.out.print(I18n.get("prompt.hash_text") + ": ");
        String text = scanner.nextLine();

        MessageDigest md = MessageDigest.getInstance("SM3", PROVIDER_NAME);
        byte[] digest = md.digest(text.getBytes(StandardCharsets.UTF_8));

        logger.info(I18n.get("msg.input.text") + ": {}", text);
        logger.info(I18n.get("msg.hash.hex") + ": {}", toHexString(digest));
    }

    private static void testInternalSm2SignStress() throws Exception {
        logger.info(I18n.get("test.stress.sign.title"));
        System.out.print(I18n.get("prompt.threads") + ": ");
        int numThreads = Integer.parseInt(scanner.nextLine());
        System.out.print(I18n.get("prompt.duration") + ": ");
        int duration = Integer.parseInt(scanner.nextLine());
        System.out.print(I18n.get("prompt.key_index.sign") + ": ");
        int keyIndex = Integer.parseInt(scanner.nextLine());
        System.out.print(I18n.get("prompt.password") + ": ");
        char[] password = scanner.nextLine().toCharArray();
        if (password.length == 0) password = null;

        StressTester tester = new StressTester(numThreads, duration, keyIndex, password);
        tester.run();
    }

    private static void testKeyPairGenStress() throws Exception {
        logger.info(I18n.get("test.stress.kpg.title"));
        System.out.print(I18n.get("prompt.threads") + ": ");
        int numThreads = Integer.parseInt(scanner.nextLine());
        System.out.print(I18n.get("prompt.duration") + ": ");
        int duration = Integer.parseInt(scanner.nextLine());

        KeyPairGenStressTester tester = new KeyPairGenStressTester(numThreads, duration);
        tester.run();
    }

    private static void runStressTestFromArgs(String[] args) {
        try {
            int threads = Integer.parseInt(args[1]);
            int duration = Integer.parseInt(args[2]);
            int keyIndex = Integer.parseInt(args[3]);
            char[] password = (args.length > 4) ? args[4].toCharArray() : null;
            
            StressTester tester = new StressTester(threads, duration, keyIndex, password);
            tester.run();
        } catch (Exception e) {
            logger.error("Failed to run stress test from command line.", e);
            System.err.println("Usage: run.sh stress <numThreads> <durationSeconds> <keyIndex> [password]");
        }
    }

    private static KeyPair generateExternalKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", PROVIDER_NAME);
        kpg.initialize(256);
        KeyPair keyPair = kpg.generateKeyPair();
        logger.info(I18n.get("msg.kpg.external.generated"));
        logger.info("Public Key (Hex): {}", toHexString(keyPair.getPublic().getEncoded()));
        logger.info("Private Key (Hex): {}", toHexString(keyPair.getPrivate().getEncoded()));
        return keyPair;
    }

    private static SecretKey generateSm4Key() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("SM4", PROVIDER_NAME);
        kg.init(128);
        SecretKey secretKey = kg.generateKey();
        logger.info(I18n.get("msg.sm4.key.generated") + ": {}", toHexString(secretKey.getEncoded()));
        return secretKey;
    }

    private static KeyPair loadInternalKeyPairRef(int keyIndex, SM2InternalKeyGenParameterSpec.KeyType keyType) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", PROVIDER_NAME);
        kpg.initialize(new SM2InternalKeyGenParameterSpec(keyIndex, keyType));
        logger.info("Loading internal {} key pair reference from index {}", keyType, keyIndex);
        return kpg.generateKeyPair();
    }

    private static void performSignVerify(PublicKey publicKey, PrivateKey privateKey, String testData) throws Exception {
        logger.info("--- Performing Sign/Verify ---");
        byte[] data = testData.getBytes(StandardCharsets.UTF_8);
        logger.info("Test Data: {}", testData);

        Signature signer = Signature.getInstance("SM3withSM2", PROVIDER_NAME);
        signer.initSign(privateKey);
        signer.update(data);
        byte[] signature = signer.sign();
        logger.info(I18n.get("msg.signature.hex") + ": {}", toHexString(signature));

        Signature verifier = Signature.getInstance("SM3withSM2", PROVIDER_NAME);
        verifier.initVerify(publicKey);
        verifier.update(data);
        boolean result = verifier.verify(signature);
        
        if (result) logger.info("{}: {}", I18n.get("msg.success"), I18n.get("msg.sign.verified"));
        else logger.error("{}: {}", I18n.get("msg.failure"), I18n.get("msg.sign.failed"));
    }

    private static void performEncryptDecrypt(PublicKey publicKey, PrivateKey privateKey, String testData) throws Exception {
        logger.info("--- Performing Encrypt/Decrypt ---");
        byte[] plaintext = testData.getBytes(StandardCharsets.UTF_8);
        logger.info(I18n.get("msg.plaintext") + ": {}", testData);

        Cipher cipher = Cipher.getInstance("SM2", PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] ciphertext = cipher.doFinal(plaintext);
        logger.info(I18n.get("msg.ciphertext.hex") + ": {}", toHexString(ciphertext));

        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(ciphertext);
        String decryptedText = new String(decryptedBytes, StandardCharsets.UTF_8);
        logger.info(I18n.get("msg.decrypted.text") + ": {}", decryptedText);

        if (testData.equals(decryptedText)) logger.info("{}: {}", I18n.get("msg.success"), I18n.get("msg.decrypt.match"));
        else logger.error("{}: {}", I18n.get("msg.failure"), I18n.get("msg.decrypt.mismatch"));
    }

    private static String toHexString(byte[] bytes) {
        if (bytes == null) return "null";
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
