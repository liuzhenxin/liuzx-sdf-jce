package org.liuzx.jce.provider.session;

import com.sun.jna.Pointer;
import org.liuzx.jce.jna.SDFLibrary;
import org.liuzx.jce.provider.SDFConfig;
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

	public static final String POOL_SIZE_PROPERTY = "liuzx.sdf.session.pool-size";

	public static final String BORROW_TIMEOUT_PROPERTY = "liuzx.sdf.session.borrow-timeout-ms";

	private static final int DEFAULT_POOL_SIZE = 16;

	private static final long DEFAULT_TIMEOUT_MS = 5000;

	private final BlockingQueue<SDFSession> sessionPool;

	private final Set<SDFSession> allSessions; // Tracks all sessions for shutdown cleanup

	private final SDFLibrary sdfLibrary;

	private final int poolSize;

	private final long borrowTimeoutMillis;

	private volatile boolean initialized;

	private volatile boolean shutdown;

	// Double-checked locking: SDFLibrary is loaded first, then pool is initialized.
	// This avoids the JNI_OnLoad circular callback issue during Native.load().
	private static volatile SDFSessionManager INSTANCE;

	public static SDFSessionManager getInstance() {
		if (INSTANCE == null) {
			synchronized (SDFSessionManager.class) {
				if (INSTANCE == null) {
					// Step 1: Ensure native library is loaded (may trigger JNI callbacks)
					SDFLibrary lib = SDFLibrary.getInstance();
					// Step 2: Now safe to create SessionManager (JNI callbacks won't
					// recurse)
					INSTANCE = new SDFSessionManager(lib);
				}
			}
		}
		return INSTANCE;
	}

	private SDFSessionManager(SDFLibrary sdfLibrary) {
		this.sdfLibrary = sdfLibrary;
		this.poolSize = positiveIntProperty(POOL_SIZE_PROPERTY, DEFAULT_POOL_SIZE);
		this.borrowTimeoutMillis = positiveLongProperty(BORROW_TIMEOUT_PROPERTY, DEFAULT_TIMEOUT_MS);
		this.sessionPool = new ArrayBlockingQueue<>(poolSize);
		this.allSessions = Collections.synchronizedSet(new LinkedHashSet<SDFSession>());
	}

	private synchronized void ensureInitialized() {
		if (shutdown) {
			throw new IllegalStateException("SDF session manager has been shut down");
		}
		if (initialized)
			return;
		try {
			initializePool();
			if (sessionPool.isEmpty()) {
				throw new IllegalStateException("SDF session pool initialization created zero sessions");
			}
			Runtime.getRuntime().addShutdownHook(new Thread(this::shutdown, "SDFSessionManager-Shutdown"));
			initialized = true;
		}
		catch (Exception e) {
			logger.error("SDF session pool init failed, will retry on next request", e);
			throw e instanceof RuntimeException
					? (RuntimeException) e
					: new IllegalStateException("SDF session pool initialization failed", e);
		}
	}

	private void initializePool() {
		logger.info("Initializing SDF session pool with size {}...", poolSize);
		for (int i = 0; i < poolSize; i++) {
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
	 * @return 新会话，失败返回 null
	 */
	private SDFSession openSession() {
		Pointer deviceHandle = null;
		try {
			Pointer[] phDeviceHandle = new Pointer[1];
			String configPath = SDFConfig.getInstance().getConfigPath();
			int rv = configPath == null
					? sdfLibrary.SDF_OpenDevice(phDeviceHandle)
					: sdfLibrary.SDF_OpenDeviceEx(phDeviceHandle, configPath, Pointer.NULL);
			if (rv != 0) {
				logger.warn("{} failed: {}", configPath == null ? "SDF_OpenDevice" : "SDF_OpenDeviceEx", rv);
				return null;
			}
			deviceHandle = phDeviceHandle[0];
			Pointer[] phSessionHandle = new Pointer[1];
			rv = sdfLibrary.SDF_OpenSession(deviceHandle, phSessionHandle);
			if (rv != 0) {
				logger.warn("SDF_OpenSession failed: {}", rv);
				Pointer failedDeviceHandle = deviceHandle;
				deviceHandle = null;
				sdfLibrary.SDF_CloseDevice(failedDeviceHandle);
				return null;
			}
			return new SDFSession(deviceHandle, phSessionHandle[0], this);
		}
		catch (Exception e) {
			if (deviceHandle != null) {
				try {
					sdfLibrary.SDF_CloseDevice(deviceHandle);
				}
				catch (RuntimeException closeError) {
					logger.warn("Failed to close SDF device after session open failure", closeError);
				}
			}
			logger.error("Failed to open SDF session", e);
			return null;
		}
	}

	/**
	 * 判断 SDF 返回码是否表明会话/连接已失效（需要销毁并重建会话）。
	 */
	public static boolean isSessionLost(int rv) {
		return rv == SDFErrorConstants.SDR_UNKNOWERR || rv == SDFErrorConstants.SDR_COMMFAIL
				|| rv == SDFErrorConstants.SDR_HARDFAIL || rv == SDFErrorConstants.SDR_OPENDEVICE
				|| rv == SDFErrorConstants.SDR_OPENSESSION
				// HSM 未就绪（数盾 0x01000403）：会话不可用，销毁重建以在 HSM 恢复后自愈
				|| rv == SDFErrorConstants.SDR_HSM_NOT_READY;
	}

	public SDFSession borrowSession() {
		ensureInitialized();
		logger.debug("Attempting to borrow a session from the pool...");
		long deadline = System.currentTimeMillis() + borrowTimeoutMillis;
		while (true) {
			if (shutdown) {
				throw new IllegalStateException("SDF session manager has been shut down");
			}
			try {
				if (sessionPool.isEmpty()) {
					replenishSession();
				}
				long remaining = deadline - System.currentTimeMillis();
				if (remaining <= 0) {
					throw new RuntimeException(
							"Could not get SDF session from pool within " + borrowTimeoutMillis + "ms");
				}
				SDFSession session = sessionPool.poll(remaining, TimeUnit.MILLISECONDS);
				if (session == null) {
					throw new RuntimeException(
							"Could not get SDF session from pool within " + borrowTimeoutMillis + "ms");
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
			}
			catch (InterruptedException e) {
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
		if (shutdown) {
			return;
		}
		if (sessionPool.size() >= poolSize) {
			return;
		}
		SDFSession session = openSession();
		if (session != null) {
			sessionPool.offer(session);
			allSessions.add(session);
			logger.info("Replenished SDF session pool ({} / {}).", sessionPool.size(), poolSize);
		}
	}

	public int getPoolSize() {
		return poolSize;
	}

	public int getAvailableSessionCount() {
		return sessionPool.size();
	}

	public long getBorrowTimeoutMillis() {
		return borrowTimeoutMillis;
	}

	public SDFLibrary getSdfLibrary() {
		return sdfLibrary;
	}

	public synchronized void shutdown() {
		if (shutdown) {
			return;
		}
		shutdown = true;
		initialized = false;
		logger.info("Shutting down SDF session pool ({} in pool + {} checked out)...", sessionPool.size(),
				allSessions.size() - sessionPool.size());
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
	 * Convert a password char[] to byte[] without creating an intermediate String. This
	 * avoids the password being interned as a String in the JVM string pool. Callers
	 * should clear the returned array after use.
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
	 * Acquire access right for an internal key index, zeroing the transient password byte
	 * array in a finally block so PIN material does not linger in the heap. Returns the
	 * SDF return code (0 = success).
	 */
	public int getPrivateKeyAccessRight(SDFSession session, int keyIndex, char[] password) {
		if (password == null || password.length == 0) {
			return 0;
		}
		byte[] pwdBytes = passwordToBytes(password);
		try {
			return sdfLibrary.SDF_GetPrivateKeyAccessRight(session.getSessionHandle(), keyIndex, pwdBytes,
					pwdBytes.length);
		}
		finally {
			Arrays.fill(pwdBytes, (byte) 0);
		}
	}

	private static int positiveIntProperty(String name, int defaultValue) {
		String value = System.getProperty(name);
		if (value == null || value.trim().isEmpty()) {
			return defaultValue;
		}
		try {
			int parsed = Integer.parseInt(value.trim());
			if (parsed <= 0) {
				throw new IllegalArgumentException(name + " must be greater than zero");
			}
			return parsed;
		}
		catch (NumberFormatException ex) {
			throw new IllegalArgumentException(name + " must be a positive integer", ex);
		}
	}

	private static long positiveLongProperty(String name, long defaultValue) {
		String value = System.getProperty(name);
		if (value == null || value.trim().isEmpty()) {
			return defaultValue;
		}
		try {
			long parsed = Long.parseLong(value.trim());
			if (parsed <= 0) {
				throw new IllegalArgumentException(name + " must be greater than zero");
			}
			return parsed;
		}
		catch (NumberFormatException ex) {
			throw new IllegalArgumentException(name + " must be a positive integer", ex);
		}
	}

}
