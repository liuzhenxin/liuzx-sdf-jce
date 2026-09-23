package org.liuzx.jce.api;

import java.util.Objects;

/**
 * 脱敏后的设备信息投影（不可变值对象）。
 *
 * <p>刻意不包含设备序列号：既没有序列号访问器，{@link #toSafeString()} 也不会输出序列号。
 * {@link #libraryDigestPrefix()} 只是已加载原生库的摘要前缀，不含库路径或文件名。</p>
 *
 * <p>本类型按 Java 8 兼容的不可变 final 类实现（不使用 {@code record} 关键字），
 * 但保留与 record 等价的访问器命名。</p>
 */
public final class SdfDeviceInfo {

    private final String issuerName;
    private final String deviceName;
    private final String deviceModelClass;
    private final int deviceVersion;
    private final int standardVersion;
    private final int symAlgAbility;
    private final int hashAlgAbility;
    private final int bufferSize;
    private final String libraryDigestPrefix;

    public SdfDeviceInfo(String issuerName, String deviceName, String deviceModelClass,
                         int deviceVersion, int standardVersion, int symAlgAbility,
                         int hashAlgAbility, int bufferSize, String libraryDigestPrefix) {
        this.issuerName = Objects.requireNonNull(issuerName, "issuerName");
        this.deviceName = Objects.requireNonNull(deviceName, "deviceName");
        this.deviceModelClass = Objects.requireNonNull(deviceModelClass, "deviceModelClass");
        this.deviceVersion = deviceVersion;
        this.standardVersion = standardVersion;
        this.symAlgAbility = symAlgAbility;
        this.hashAlgAbility = hashAlgAbility;
        this.bufferSize = bufferSize;
        this.libraryDigestPrefix = Objects.requireNonNull(libraryDigestPrefix, "libraryDigestPrefix");
    }

    public String issuerName() { return issuerName; }

    public String deviceName() { return deviceName; }

    public String deviceModelClass() { return deviceModelClass; }

    public int deviceVersion() { return deviceVersion; }

    public int standardVersion() { return standardVersion; }

    public int symAlgAbility() { return symAlgAbility; }

    public int hashAlgAbility() { return hashAlgAbility; }

    public int bufferSize() { return bufferSize; }

    public String libraryDigestPrefix() { return libraryDigestPrefix; }

    /**
     * @return 可安全记录/展示的字符串，不含序列号、路径或库文件名。
     */
    public String toSafeString() {
        return "SdfDeviceInfo[issuer=" + issuerName
                + ", name=" + deviceName
                + ", modelClass=" + deviceModelClass
                + ", deviceVersion=" + deviceVersion
                + ", standardVersion=" + standardVersion
                + ", symAlgAbility=0x" + String.format("%08X", symAlgAbility)
                + ", hashAlgAbility=0x" + String.format("%08X", hashAlgAbility)
                + ", bufferSize=" + bufferSize
                + ", libraryDigestPrefix=" + libraryDigestPrefix
                + "]";
    }

    @Override
    public String toString() {
        return toSafeString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof SdfDeviceInfo)) {
            return false;
        }
        SdfDeviceInfo other = (SdfDeviceInfo) o;
        return deviceVersion == other.deviceVersion
                && standardVersion == other.standardVersion
                && symAlgAbility == other.symAlgAbility
                && hashAlgAbility == other.hashAlgAbility
                && bufferSize == other.bufferSize
                && issuerName.equals(other.issuerName)
                && deviceName.equals(other.deviceName)
                && deviceModelClass.equals(other.deviceModelClass)
                && libraryDigestPrefix.equals(other.libraryDigestPrefix);
    }

    @Override
    public int hashCode() {
        return Objects.hash(issuerName, deviceName, deviceModelClass, deviceVersion,
                standardVersion, symAlgAbility, hashAlgAbility, bufferSize, libraryDigestPrefix);
    }
}
