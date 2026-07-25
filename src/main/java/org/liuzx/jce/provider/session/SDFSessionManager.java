package org.liuzx.jce.provider.session;

import com.sun.jna.Pointer;
import org.liuzx.jce.jna.SDFLibrary;
import org.liuzx.jce.provider.log.LiuzxProviderLogger; // Updated import

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

public class SDFSessionManager {

    private static final LiuzxProviderLogger logger = LiuzxProviderLogger.getLogger(SDFSessionManager.class); // Updated class
    private static final int POOL_SIZE = 10;
    private static final long TIMEOUT_MS = 5000;

    private final BlockingQueue<SDFSession> sessionPool;
    private final SDFLibrary sdfLibrary;
    private volatile boolean initialized;
    private volatile boolean initFailed;

    // Double-checked locking: SDFLibrary is loaded first, then pool is initialized.
    // This avoids the JNI_OnLoad circular callback issue during Native.load().
    private static volatile SDFSessionManager INSTANCE;

    public static SDFSessionManager getInstance() {
        if (INSTANCE == null) {
            synchronized (SDFSessionManager.class) {
                if (INSTANCE == null) {
                    // Step 1: Ensure native library is loaded (may trigger JNI callbacks)
                    SDFLibrary lib = SDFLibrary.getInstance();
                    // Step 2: Now safe to create SessionManager (JNI callbacks won't recurse)
                    INSTANCE = new SDFSessionManager(lib);
                }
            }
        }
        return INSTANCE;
    }

    private SDFSessionManager(SDFLibrary sdfLibrary) {
        this.sdfLibrary = sdfLibrary;
        this.sessionPool = new ArrayBlockingQueue<>(POOL_SIZE);
    }

    private synchronized void ensureInitialized() {
        if (initialized) return;
        try {
            initializePool();
            Runtime.getRuntime().addShutdownHook(new Thread(this::shutdown));
            initialized = true;
        } catch (Exception e) {
            logger.error("SDF session pool init failed, will retry on next request", e);
            // Don't set initFailed — allow retry on next borrowSession
        }
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
        ensureInitialized();
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
