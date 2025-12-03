package org.liuzx.jce.provider.session;

import com.sun.jna.Pointer;

public class SDFSession implements AutoCloseable {

    private final Pointer hDeviceHandle;
    private final Pointer hSessionHandle;
    private final SDFSessionManager manager;

    SDFSession(Pointer hDeviceHandle, Pointer hSessionHandle, SDFSessionManager manager) {
        this.hDeviceHandle = hDeviceHandle;
        this.hSessionHandle = hSessionHandle;
        this.manager = manager;
    }

    public Pointer getDeviceHandle() {
        return hDeviceHandle;
    }

    public Pointer getSessionHandle() {
        return hSessionHandle;
    }

    /**
     * This does not close the actual session, but returns it to the pool.
     */
    @Override
    public void close() {
        manager.returnSession(this);
    }

    /**
     * Actually closes the underlying SDF session and device handles.
     * To be called only by the manager during shutdown.
     */
    void destroy() {
        if (hSessionHandle != null) {
            manager.getSdfLibrary().SDF_CloseSession(hSessionHandle);
        }
        if (hDeviceHandle != null) {
            manager.getSdfLibrary().SDF_CloseDevice(hDeviceHandle);
        }
    }
}
