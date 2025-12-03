package org.liuzx.jce.demo;

import org.liuzx.jce.provider.LiuZXProvider;
import org.liuzx.jce.provider.log.LiuzxProviderLogger;

import java.security.KeyPairGenerator;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * A stress tester specifically for generating SM2 External KeyPairs.
 */
public class KeyPairGenStressTester {

    private static final LiuzxProviderLogger logger = LiuzxProviderLogger.getLogger(KeyPairGenStressTester.class);
    private static final String PROVIDER_NAME = LiuZXProvider.PROVIDER_NAME;

    private final int numThreads;
    private final int durationSeconds;

    public KeyPairGenStressTester(int numThreads, int durationSeconds) {
        this.numThreads = numThreads;
        this.durationSeconds = durationSeconds;
    }

    public void run() throws Exception {
        logger.info("Starting SM2 External KeyPair Generation Stress Test...");
        logger.info("Threads: {}, Duration: {} seconds", numThreads, durationSeconds);

        ExecutorService executor = Executors.newFixedThreadPool(numThreads);
        CountDownLatch startLatch = new CountDownLatch(1);
        AtomicBoolean stopFlag = new AtomicBoolean(false);
        AtomicLong totalKeyPairs = new AtomicLong(0);

        for (int i = 0; i < numThreads; i++) {
            executor.submit(() -> {
                try {
                    KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", PROVIDER_NAME);
                    kpg.initialize(256); // Initialize once per thread for external keys
                    
                    startLatch.await(); // Wait for the signal to start

                    while (!stopFlag.get()) {
                        kpg.generateKeyPair();
                        totalKeyPairs.incrementAndGet();
                    }
                } catch (Exception e) {
                    logger.error("Error in worker thread", e);
                }
            });
        }

        logger.info("All threads ready. Starting test in 3 seconds...");
        Thread.sleep(3000);
        long startTime = System.currentTimeMillis();
        startLatch.countDown();
        logger.info("Test started!");

        Thread.sleep(durationSeconds * 1000);
        stopFlag.set(true);

        executor.shutdown();
        executor.awaitTermination(10, TimeUnit.SECONDS);
        long endTime = System.currentTimeMillis();

        long actualDurationMillis = endTime - startTime;
        long finalCount = totalKeyPairs.get();
        double tps = (finalCount > 0 && actualDurationMillis > 0) ? (double) finalCount / actualDurationMillis * 1000.0 : 0;

        logger.info("--- External KeyPair Generation Stress Test Results ---");
        logger.info("Total KeyPairs Generated: {}", finalCount);
        logger.info("Actual Duration: {} ms", actualDurationMillis);
        logger.info("TPS (KeyPairs Per Second): {}", String.format("%.2f", tps));
        System.out.println("\n--- External KeyPair Generation Stress Test Results ---");
        System.out.printf("Total KeyPairs Generated: %d\n", finalCount);
        System.out.printf("Actual Duration: %d ms\n", actualDurationMillis);
        System.out.printf("TPS (KeyPairs Per Second): %.2f\n", tps);
    }
}
