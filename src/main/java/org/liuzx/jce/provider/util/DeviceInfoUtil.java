package org.liuzx.jce.provider.util;

import org.liuzx.jce.jna.SDFLibrary;
import org.liuzx.jce.jna.structure.DEVICEINFO;
import org.liuzx.jce.provider.exception.SDFException;
import org.liuzx.jce.provider.session.SDFSession;
import org.liuzx.jce.provider.session.SDFSessionManager;

/**
 * Utility to query SDF device information.
 */
public final class DeviceInfoUtil {

    private DeviceInfoUtil() {
    }

    /**
     * Read device information from the connected SDF hardware.
     */
    public static DeviceInfo getDeviceInfo() {
        SDFSessionManager mgr = SDFSessionManager.getInstance();
        try (SDFSession session = mgr.borrowSession()) {
            DEVICEINFO.ByReference info = new DEVICEINFO.ByReference();
            int rv = SDFLibrary.getInstance().SDF_GetDeviceInfo(session.getSessionHandle(), info);
            session.checkResult(rv); if (rv != 0) throw new SDFException("SDF_GetDeviceInfo", rv);
            return new DeviceInfo(info);
        }
    }

    /**
     * Human-readable device information.
     */
    public static class DeviceInfo {
        private final String issuerName;
        private final String deviceName;
        private final String deviceSerial;
        private final int deviceVersion;
        private final int standardVersion;
        private final int symAlgAbility;
        private final int hashAlgAbility;
        private final int bufferSize;

        DeviceInfo(DEVICEINFO di) {
            this.issuerName = trimString(di.IssuerName);
            this.deviceName = trimString(di.DeviceName);
            this.deviceSerial = trimString(di.DeviceSerial);
            this.deviceVersion = di.DeviceVersion;
            this.standardVersion = di.StandardVersion;
            this.symAlgAbility = di.SymAlgAbility;
            this.hashAlgAbility = di.HashAlgAbility;
            this.bufferSize = di.BufferSize;
        }

        public String getIssuerName() { return issuerName; }
        public String getDeviceName() { return deviceName; }
        public String getDeviceSerial() { return deviceSerial; }
        public int getDeviceVersion() { return deviceVersion; }
        public int getStandardVersion() { return standardVersion; }
        public int getSymAlgAbility() { return symAlgAbility; }
        public int getHashAlgAbility() { return hashAlgAbility; }
        public int getBufferSize() { return bufferSize; }

        @Override
        public String toString() {
            return String.format("Device[issuer=%s, name=%s, serial=%s, ver=%d, std=%d, sym=0x%08X, hash=0x%08X, buf=%d]",
                    issuerName, deviceName, deviceSerial, deviceVersion, standardVersion,
                    symAlgAbility, hashAlgAbility, bufferSize);
        }

        private static String trimString(byte[] bytes) {
            int end = 0;
            while (end < bytes.length && bytes[end] != 0) end++;
            return new String(bytes, 0, end, java.nio.charset.StandardCharsets.UTF_8).trim();
        }
    }
}
