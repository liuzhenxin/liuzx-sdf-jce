package org.liuzx.jce.api;

import org.liuzx.jce.jna.SDFLibrary;
import org.liuzx.jce.provider.asymmetric.rsa.RSAInternalKeyGenParameterSpec;
import org.liuzx.jce.provider.asymmetric.sm2.SM2InternalKeyGenParameterSpec;
import org.liuzx.jce.provider.asymmetric.sm2.SM2SignatureSpi;
import org.liuzx.jce.provider.session.SDFSession;
import org.liuzx.jce.provider.session.SDFSessionManager;
import org.liuzx.jce.provider.util.DeviceInfoUtil;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * {@link SdfDevice} 的包私有实现。
 *
 * <p>门面内部可以使用 JNA 与 Provider 内部类型；公开签名只暴露 JDK 类型。设备序列号、
 * 原生句柄与 PIN 都不会进入任何字段。</p>
 */
final class SdfDeviceImpl implements SdfDevice {

    private static final String PROVIDER_NAME = org.liuzx.jce.provider.LiuZXProvider.PROVIDER_NAME;

    private final SDFSessionManager sessionManager;
    private final AtomicBoolean closed = new AtomicBoolean(false);

    SdfDeviceImpl(SDFSessionManager sessionManager) {
        if (sessionManager == null) {
            throw new IllegalArgumentException("sessionManager must not be null");
        }
        this.sessionManager = sessionManager;
    }

    /** 供无硬件环境测试的包私有构造器，只用于验证关闭状态机。 */
    SdfDeviceImpl() {
        this.sessionManager = null;
    }

    /** 供无硬件环境测试的开/关状态探测。 */
    boolean isClosed() {
        return closed.get();
    }

    @Override
    public SdfDeviceInfo deviceInfo() {
        ensureOpen();
        try {
            DeviceInfoUtil.DeviceInfo info = DeviceInfoUtil.getDeviceInfo();
            return new SdfDeviceInfo(
                    info.getIssuerName(),
                    info.getDeviceName(),
                    modelClassOf(info.getDeviceName()),
                    info.getDeviceVersion(),
                    info.getStandardVersion(),
                    info.getSymAlgAbility(),
                    info.getHashAlgAbility(),
                    info.getBufferSize(),
                    libraryDigestPrefix());
        } catch (org.liuzx.jce.provider.exception.SDFException e) {
            throw new SdfException(SdfErrorMapper.map(e.getErrorCode()), "deviceInfo", e.getErrorCode(), e);
        } catch (SdfException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new SdfException(SdfErrorCategory.NATIVE_DEPENDENCY_UNAVAILABLE, "deviceInfo", 0, e);
        }
    }

    @Override
    public SdfCapabilities capabilities() {
        ensureOpen();
        Set<AlgorithmFamily> families = new LinkedHashSet<AlgorithmFamily>();
        families.add(AlgorithmFamily.SM2);
        families.add(AlgorithmFamily.SM3);
        families.add(AlgorithmFamily.RSA);
        SDFSessionManager manager = sessionManager != null
                ? sessionManager
                : SDFSessionManager.getInstance();
        return new SdfCapabilities(
                families,
                true,
                SM2SignatureSpi.DEFAULT_USER_ID_STRING,
                manager.getPoolSize(),
                manager.getAvailableSessionCount(),
                manager.getBorrowTimeoutMillis());
    }

    @Override
    public byte[] exportSignPublicKey(int keyIndex) {
        ensureOpen();
        Exception sm2Failure = null;
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("SM2", PROVIDER_NAME);
            generator.initialize(new SM2InternalKeyGenParameterSpec(
                    keyIndex, SM2InternalKeyGenParameterSpec.KeyType.SIGN));
            KeyPair pair = generator.generateKeyPair();
            byte[] encoded = pair.getPublic().getEncoded();
            if (encoded != null && encoded.length > 0) {
                return encoded;
            }
            sm2Failure = new IllegalStateException("SM2 public key encoding was empty");
        } catch (Exception e) {
            sm2Failure = e;
        }

        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", PROVIDER_NAME);
            generator.initialize(new RSAInternalKeyGenParameterSpec(keyIndex));
            KeyPair pair = generator.generateKeyPair();
            byte[] encoded = pair.getPublic().getEncoded();
            if (encoded != null && encoded.length > 0) {
                return encoded;
            }
            throw new SdfException(SdfErrorCategory.OPERATION_FAILED, "exportSignPublicKey", 0, sm2Failure);
        } catch (SdfException e) {
            throw e;
        } catch (Exception rsaFailure) {
            // Prefer the RSA failure classification when it carries a device error code;
            // otherwise fall back to the SM2 failure captured earlier.
            SdfException mapped = mapFailure("exportSignPublicKey", rsaFailure);
            if (mapped.category() == SdfErrorCategory.NATIVE_DEPENDENCY_UNAVAILABLE && sm2Failure != null) {
                throw mapFailure("exportSignPublicKey", sm2Failure);
            }
            throw mapped;
        }
    }

    @Override
    public byte[] signSm2(int keyIndex, byte[] message, char[] pinOrNull) {
        ensureOpen();
        throw new UnsupportedOperationException("signSm2 is implemented in plan 01-03");
    }

    @Override
    public byte[] signSm2Digest(int keyIndex, byte[] digest, char[] pinOrNull) {
        ensureOpen();
        throw new UnsupportedOperationException("signSm2Digest is implemented in plan 01-03");
    }

    @Override
    public byte[] signRsa(int keyIndex, byte[] message, char[] pinOrNull) {
        ensureOpen();
        throw new UnsupportedOperationException("signRsa is implemented in plan 01-03");
    }

    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            // The session pool is process-wide and owned by SDFSessionManager; the facade only
            // stops accepting new calls. It does not tear down the shared pool.
            onClosed();
        }
    }

    /** 关闭时的钩子，供子类/测试观察；默认无操作。 */
    void onClosed() {
        // no-op
    }

    private void ensureOpen() {
        if (closed.get()) {
            throw new IllegalStateException("SdfDevice is closed");
        }
    }

    /**
     * 私钥访问权生命周期：按需申请，{@code finally} 中释放。PIN 只作为局部变量存在，
     * 不会写入任何字段或缓存。
     */
    int withPrivateKeyAccess(SDFSession session, int keyIndex, char[] pinOrNull,
                             PrivateKeyAction action) throws Exception {
        boolean hasPin = pinOrNull != null && pinOrNull.length > 0;
        if (hasPin) {
            int accessRight = sessionManager.getPrivateKeyAccessRight(session, keyIndex, pinOrNull);
            if (accessRight != 0) {
                throw new SdfException(SdfErrorMapper.map(accessRight),
                        "SDF_GetPrivateKeyAccessRight", accessRight, null);
            }
        }
        try {
            return action.run();
        } finally {
            if (hasPin) {
                SDFLibrary library = sessionManager.getSdfLibrary();
                library.SDF_ReleasePrivateKeyAccessRight(session.getSessionHandle(), keyIndex);
            }
        }
    }

    /** 包私有动作接口，避免在公开签名中出现任何内部类型。 */
    interface PrivateKeyAction {
        int run() throws Exception;
    }

    private static SdfException mapFailure(String operation, Throwable failure) {
        Throwable current = failure;
        while (current != null) {
            if (current instanceof org.liuzx.jce.provider.exception.SDFException) {
                int code = ((org.liuzx.jce.provider.exception.SDFException) current).getErrorCode();
                return new SdfException(SdfErrorMapper.map(code), operation, code, failure);
            }
            if (current instanceof UnsatisfiedLinkError || current instanceof NoClassDefFoundError) {
                return new SdfException(SdfErrorCategory.NATIVE_DEPENDENCY_UNAVAILABLE, operation, 0, failure);
            }
            current = current.getCause();
        }
        return new SdfException(SdfErrorCategory.OPERATION_FAILED, operation, 0, failure);
    }

    private static String modelClassOf(String deviceName) {
        if (deviceName == null || deviceName.trim().isEmpty()) {
            return "unknown";
        }
        return deviceName.trim();
    }

    private static String libraryDigestPrefix() {
        // No public accessor exposes the loaded library digest yet; keep a stable placeholder
        // so the value never contains a path or file name.
        return "unknown";
    }
}
