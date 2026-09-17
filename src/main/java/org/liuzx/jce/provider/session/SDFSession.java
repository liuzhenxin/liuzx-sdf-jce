package org.liuzx.jce.provider.session;

import com.sun.jna.Pointer;

public class SDFSession implements AutoCloseable {

    private volatile Pointer hDeviceHandle;
    private volatile Pointer hSessionHandle;
    private final SDFSessionManager manager;
    private volatile boolean broken;

    SDFSession(Pointer hDeviceHandle, Pointer hSessionHandle, SDFSessionManager manager) {
        this.hDeviceHandle = hDeviceHandle;
        this.hSessionHandle = hSessionHandle;
        this.manager = manager;
    }

    /**
     * True once this session has been marked broken (HSM 侧会话/连接已失效)。
     * 失效会话在归还时被销毁并重建，而不是放回池中。
     */
    boolean isBroken() {
        return broken;
    }

    /**
     * 记录一次 SDF 操作结果：若错误码表明会话/连接已失效（如 SDR_COMMFAIL / SDR_HARDFAIL），
     * 标记为 broken，使会话池在归还时销毁并重建会话（自愈）。rv==0 时为无操作。
     */
    public void checkResult(int rv) {
        if (SDFSessionManager.isSessionLost(rv)) {
            this.broken = true;
        }
    }

    public Pointer getDeviceHandle() {
        return hDeviceHandle;
    }

    public Pointer getSessionHandle() {
        return hSessionHandle;
    }

    /**
     * This does not close the actual session, but returns it to the pool.
     * The returned session remains valid for reuse.
     */
    @Override
    public void close() {
        manager.returnSession(this);
    }

    /**
     * True once {@link #destroy()} has run (handles cleared).
     */
    boolean isDestroyed() {
        return hSessionHandle == null;
    }

    /**
     * Actually closes the underlying SDF session handle.
     * Idempotent: safe to call multiple times.
     * The device handle is shared between sessions and owned by the session manager,
     * so it is closed once by the manager (Shudun requires a single global device handle).
     */
    void destroy() {
        Pointer session = hSessionHandle;
        // Set the field to null first so a concurrent destroy sees it as gone.
        hSessionHandle = null;
        if (session != null) {
            manager.getSdfLibrary().SDF_CloseSession(session);
        }
    }
}
