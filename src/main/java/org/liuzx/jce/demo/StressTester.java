package org.liuzx.jce.demo;

import org.liuzx.jce.provider.LiuZXProvider;
import org.liuzx.jce.provider.asymmetric.sm2.SM2InternalKeyGenParameterSpec;
import org.liuzx.jce.provider.asymmetric.sm2.SM2PrivateKey;
import org.liuzx.jce.provider.asymmetric.sm2.SM2PublicKey;
import org.liuzx.jce.provider.log.LiuzxProviderLogger;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

public class StressTester {

    private static final LiuzxProviderLogger logger = LiuzxProviderLogger.getLogger(StressTester.class);
    private static final String PROVIDER_NAME = LiuZXProvider.PROVIDER_NAME;

    private final int numThreads;
    private final int durationSeconds;
    private final int keyIndex;
    private final char[] password;

    public StressTester(int numThreads, int durationSeconds, int keyIndex, char[] password) {
        this.numThreads = numThreads;
        this.durationSeconds = durationSeconds;
        this.keyIndex = keyIndex;
        this.password = password;
    }

    public void run() throws Exception {
        logger.info("Starting SM2 Internal Signing Stress Test...");
        logger.info("Threads: {}, Duration: {} seconds, Key Index: {}", numThreads, durationSeconds, keyIndex);

        // 1. Load the key pair reference once
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", PROVIDER_NAME);
        kpg.initialize(new SM2InternalKeyGenParameterSpec(keyIndex, SM2InternalKeyGenParameterSpec.KeyType.SIGN));
        KeyPair keyPairRef = kpg.generateKeyPair();
        PublicKey publicKey = keyPairRef.getPublic();
        
        // Construct the private key for use
        PrivateKey privateKeyForUse = new SM2PrivateKey(keyIndex, password, ((SM2PublicKey)publicKey).getEccPublicKey());

        // 2. Prepare for multi-threading
        ExecutorService executor = Executors.newFixedThreadPool(numThreads);
        CountDownLatch startLatch = new CountDownLatch(1);
        AtomicBoolean stopFlag = new AtomicBoolean(false);
        AtomicLong totalSignatures = new AtomicLong(0);
        byte[] dataToSign = "stress test data".getBytes(StandardCharsets.UTF_8);

        // 3. Create and submit tasks
        for (int i = 0; i < numThreads; i++) {
            executor.submit(() -> {
                try {
                    Signature signer = Signature.getInstance("SM3withSM2", PROVIDER_NAME);
                    signer.initSign(privateKeyForUse);
                    
                    startLatch.await(); // Wait for the signal to start

                    while (!stopFlag.get()) {
                        signer.update(dataToSign);
                        signer.sign();
                        totalSignatures.incrementAndGet();
                    }
                } catch (Exception e) {
                    logger.error("Error in worker thread", e);
                }
            });
        }

        // 4. Start and run the test
        logger.info("All threads ready. Starting test in 3 seconds...");
        Thread.sleep(3000);
        long startTime = System.currentTimeMillis();
        startLatch.countDown(); // Signal all threads to start
        logger.info("Test started!");

        Thread.sleep(durationSeconds * 1000);
        stopFlag.set(true); // Signal all threads to stop

        // 5. Shutdown and calculate results
        executor.shutdown();
        executor.awaitTermination(10, TimeUnit.SECONDS);
        long endTime = System.currentTimeMillis();

        long actualDurationMillis = endTime - startTime;
        long finalCount = totalSignatures.get();
        double tps = (double) finalCount / actualDurationMillis * 1000.0;

        logger.info("--- Stress Test Results ---");
        logger.info("Total Signatures: {}", finalCount);
        logger.info("Actual Duration: {} ms", actualDurationMillis);
        logger.info("TPS (Transactions Per Second): {}", String.format("%.2f", tps));
        System.out.println("\n--- Stress Test Results ---");
        System.out.printf("Total Signatures: %d\n", finalCount);
        System.out.printf("Actual Duration: %d ms\n", actualDurationMillis);
        System.out.printf("TPS (Transactions Per Second): %.2f\n", tps);
    }
}
