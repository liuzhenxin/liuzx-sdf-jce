package org.liuzx.jce.provider.session;

import com.sun.jna.Pointer;
import org.liuzx.jce.jna.SDFLibrary;
import org.liuzx.jce.provider.log.LiuzxProviderLogger; // Updated import

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

public class SDFSessionManager {

    private static final LiuzxProviderLogger logger = LiuzxProviderLogger.getLogger(SDFSessionManager.class); // Updated class
    private static final SDFSessionManager INSTANCE = new SDFSessionManager();
    private static final int POOL_SIZE = 10;
    private static final long TIMEOUT_MS = 5000;

    private final BlockingQueue<SDFSession> sessionPool;
    private final SDFLibrary sdfLibrary;

    private SDFSessionManager() {
        this.sdfLibrary = SDFLibrary.getInstance();
        this.sessionPool = new ArrayBlockingQueue<>(POOL_SIZE);
        initializePool();
        Runtime.getRuntime().addShutdownHook(new Thread(this::shutdown));
    }

    public static SDFSessionManager getInstance() {
        return INSTANCE;
    }

    private void initializePool() {
        logger.info("Initializing SDF session pool with size {}...", POOL_SIZE);
        for (int i = 0; i < POOL_SIZE; i++) {
            try {
                Pointer[] phDeviceHandle = new Pointer[1];
                int rv = sdfLibrary.SDF_OpenDevice(phDeviceHandle);
                if (rv != 0) throw new RuntimeException("SDF_OpenDevice failed: " + rv);

                Pointer[] phSessionHandle = new Pointer[1];
                rv = sdfLibrary.SDF_OpenSession(phDeviceHandle[0], phSessionHandle);
                if (rv != 0) throw new RuntimeException("SDF_OpenSession failed: " + rv);

                sessionPool.add(new SDFSession(phDeviceHandle[0], phSessionHandle[0], this));
                logger.debug("Created and added session #{} to the pool.", i + 1);
            } catch (Exception e) {
                logger.error("Failed to initialize SDF session pool", e);
                break;
            }
        }
        logger.info("SDF session pool initialized with {} sessions.", sessionPool.size());
    }

    public SDFSession borrowSession() {
        logger.debug("Attempting to borrow a session from the pool...");
        try {
            SDFSession session = sessionPool.poll(TIMEOUT_MS, TimeUnit.MILLISECONDS);
            if (session == null) {
                throw new RuntimeException("Could not get SDF session from pool within " + TIMEOUT_MS + "ms");
            }
            logger.debug("Session borrowed successfully. Pool size now: {}", sessionPool.size());
            return session;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Interrupted while waiting for SDF session", e);
        }
    }

    void returnSession(SDFSession session) {
        if (session != null) {
            sessionPool.offer(session);
            logger.debug("Session returned to the pool. Pool size now: {}", sessionPool.size());
        }
    }

    public SDFLibrary getSdfLibrary() {
        return sdfLibrary;
    }

    private void shutdown() {
        logger.info("Shutting down SDF session pool...");
        for (SDFSession session : sessionPool) {
            session.destroy();
        }
        sessionPool.clear();
        logger.info("SDF session pool shut down complete.");
    }
}
