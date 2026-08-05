package org.liuzx.jce.provider.session;

import com.sun.jna.Pointer;
import org.liuzx.jce.jna.SDFLibrary;
import org.liuzx.jce.provider.exception.SDFErrorConstants;
import org.liuzx.jce.provider.log.LiuzxProviderLogger;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

public class SDFSessionManager {

    private static final LiuzxProviderLogger logger = LiuzxProviderLogger.getLogger(SDFSessionManager.class);
    private static final int POOL_SIZE = 10;
    private static final long TIMEOUT_MS = 5000;

    private final BlockingQueue<SDFSession> sessionPool;
    private final Set<SDFSession> allSessions; // Tracks all sessions for shutdown cleanup
    private final SDFLibrary sdfLibrary;
    private volatile boolean initialized;

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
        this.allSessions = Collections.synchronizedSet(new LinkedHashSet<SDFSession>());
    }

    private synchronized void ensureInitialized() {
        if (initialized) return;
        try {
            initializePool();
            Runtime.getRuntime().addShutdownHook(new Thread(this::shutdown, "SDFSessionManager-Shutdown"));
            initialized = true;
        } catch (Exception e) {
            logger.error("SDF session pool init failed, will retry on next request", e);
        }
    }

    private void initializePool() {
        logger.info("Initializing SDF session pool with size {}...", POOL_SIZE);
        for (int i = 0; i < POOL_SIZE; i++) {
            SDFSession session = openSession();
            if (session == null) {
                logger.error("Failed to initialize SDF session pool (stopped at {} sessions).", sessionPool.size());
                break;
            }
            sessionPool.add(session);
            allSessions.add(session);
            logger.debug("Created and added session #{} to the pool.", i + 1);
        }
        logger.info("SDF session pool initialized with {} sessions.", sessionPool.size());
    }

    /**
     * 打开一个新的 SDF 设备会话（SDF_OpenDevice + SDF_OpenSession）。
     *
     * @return 新会话，失败返回 null
     */
    private SDFSession openSession() {
        try {
            Pointer[] phDeviceHandle = new Pointer[1];
            int rv = sdfLibrary.SDF_OpenDevice(phDeviceHandle);
            if (rv != 0) {
                logger.warn("SDF_OpenDevice failed: {}", rv);
                return null;
            }
            Pointer[] phSessionHandle = new Pointer[1];
            rv = sdfLibrary.SDF_OpenSession(phDeviceHandle[0], phSessionHandle);
            if (rv != 0) {
                logger.warn("SDF_OpenSession failed: {}", rv);
                return null;
            }
            return new SDFSession(phDeviceHandle[0], phSessionHandle[0], this);
        } catch (Exception e) {
            logger.error("Failed to open SDF session", e);
            return null;
        }
    }

    /**
     * 判断 SDF 返回码是否表明会话/连接已失效（需要销毁并重建会话）。
     */
    public static boolean isSessionLost(int rv) {
        return rv == SDFErrorConstants.SDR_UNKNOWERR
                || rv == SDFErrorConstants.SDR_COMMFAIL
                || rv == SDFErrorConstants.SDR_HARDFAIL
                || rv == SDFErrorConstants.SDR_OPENDEVICE
                || rv == SDFErrorConstants.SDR_OPENSESSION;
    }

    public SDFSession borrowSession() {
        ensureInitialized();
        logger.debug("Attempting to borrow a session from the pool...");
        long deadline = System.currentTimeMillis() + TIMEOUT_MS;
        while (true) {
            try {
                long remaining = deadline - System.currentTimeMillis();
                if (remaining <= 0) {
                    throw new RuntimeException("Could not get SDF session from pool within " + TIMEOUT_MS + "ms");
                }
                SDFSession session = sessionPool.poll(remaining, TimeUnit.MILLISECONDS);
                if (session == null) {
                    throw new RuntimeException("Could not get SDF session from pool within " + TIMEOUT_MS + "ms");
                }
                if (session.isDestroyed() || session.isBroken()) {
                    // 已销毁/失效的会话不能复用，销毁并补一个新会话后重试
                    logger.warn("Discarding a destroyed/broken SDF session from the pool.");
                    session.destroy();
                    replenishSession();
                    continue;
                }
                logger.debug("Session borrowed successfully. Pool size now: {}", sessionPool.size());
                return session;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException("Interrupted while waiting for SDF session", e);
            }
        }
    }

    void returnSession(SDFSession session) {
        if (session == null) {
            return;
        }
        if (session.isDestroyed() || session.isBroken()) {
            // 已销毁或 HSM 侧失效（broken）的会话不能归还回池：销毁句柄并补一个新会话（自愈）
            if (session.isBroken()) {
                logger.warn("Discarding a broken SDF session (HSM connection lost), opening a replacement.");
            }
            session.destroy();
            replenishSession();
            return;
        }
        sessionPool.offer(session);
        logger.debug("Session returned to the pool. Pool size now: {}", sessionPool.size());
    }

    /**
     * 池未满时补开一个会话，保持池容量（在失效会话被销毁后调用）。
     */
    private synchronized void replenishSession() {
        if (sessionPool.size() >= POOL_SIZE) {
            return;
        }
        SDFSession session = openSession();
        if (session != null) {
            sessionPool.offer(session);
            allSessions.add(session);
            logger.info("Replenished SDF session pool ({} / {}).", sessionPool.size(), POOL_SIZE);
        }
    }

    public SDFLibrary getSdfLibrary() {
        return sdfLibrary;
    }

    private void shutdown() {
        logger.info("Shutting down SDF session pool ({} in pool + {} checked out)...",
                sessionPool.size(), allSessions.size() - sessionPool.size());
        synchronized (allSessions) {
            for (SDFSession session : allSessions) {
                session.destroy();
            }
            allSessions.clear();
        }
        sessionPool.clear();
        logger.info("SDF session pool shut down complete.");
    }

    /**
     * Convert a password char[] to byte[] without creating an intermediate String.
     * This avoids the password being interned as a String in the JVM string pool.
     * Callers should clear the returned array after use.
     */
    public static byte[] passwordToBytes(char[] password) {
        if (password == null || password.length == 0) {
            return new byte[0];
        }
        ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(password));
        byte[] bytes = new byte[byteBuffer.remaining()];
        byteBuffer.get(bytes);
        return bytes;
    }

    /**
     * Acquire access right for an internal key index, zeroing the transient password
     * byte array in a finally block so PIN material does not linger in the heap.
     * Returns the SDF return code (0 = success).
     */
    public int getPrivateKeyAccessRight(SDFSession session, int keyIndex, char[] password) {
        if (password == null || password.length == 0) {
            return 0;
        }
        byte[] pwdBytes = passwordToBytes(password);
        try {
            return sdfLibrary.SDF_GetPrivateKeyAccessRight(session.getSessionHandle(), keyIndex, pwdBytes, pwdBytes.length);
        } finally {
            Arrays.fill(pwdBytes, (byte) 0);
        }
    }
}
