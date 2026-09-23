package org.liuzx.jce.api;

import org.liuzx.jce.provider.LiuZXProvider;
import org.liuzx.jce.provider.session.SDFSession;
import org.liuzx.jce.provider.session.SDFSessionManager;

import java.security.Security;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

/**
 * 门面入口工厂。
 *
 * <p>调用方无需提供 {@code SDFLibrary}、{@code Pointer} 或会话句柄；工厂内部完成
 * Provider 注册、设备打开与会话预热。</p>
 *
 * <p>{@link #open(Properties)} 只接受白名单内的非凭据属性。含 {@code pin}、{@code password}
 * 或 {@code passwd} 的键会被拒绝，避免把凭据写进全局系统属性。</p>
 */
public final class SdfDevices {

    private static final Set<String> ALLOWED_OVERRIDE_KEYS = Collections.unmodifiableSet(
            new HashSet<String>(Arrays.asList(
                    "liuzx.sdf.vendor",
                    "liuzx.sdf.library.path",
                    "liuzx.sdf.profile.path",
                    "liuzx.sdf.vendor-config.path",
                    "liuzx.sdf.rsa-key-layout",
                    "liuzx.sdf.library.fallback-enabled",
                    "liuzx.sdf.session.pool-size",
                    "liuzx.sdf.session.borrow-timeout-ms")));

    private SdfDevices() {
    }

    /**
     * 使用已配置的 Profile / 系统属性打开设备。
     *
     * @return 就绪的门面
     * @throws SdfException 设备或原生库不可用。
     */
    public static SdfDevice open() {
        return open(new Properties());
    }

    /**
     * 使用白名单属性覆盖后打开设备。
     *
     * @param overrides 白名单内的 SDF 属性；不得含凭据
     * @return 就绪的门面
     * @throws IllegalArgumentException 出现未知键或疑似凭据键
     * @throws SdfException              设备或原生库不可用。
     */
    public static SdfDevice open(Properties overrides) {
        validateOverrides(overrides);
        applyOverrides(overrides);
        ensureProviderRegistered();
        try {
            SDFSessionManager sessionManager = SDFSessionManager.getInstance();
            warmUp(sessionManager);
            return new SdfDeviceImpl(sessionManager);
        } catch (SdfException e) {
            throw e;
        } catch (LinkageError e) {
            // Configuration / native-library static initialization failures surface here as
            // ExceptionInInitializerError, UnsatisfiedLinkError or NoClassDefFoundError.
            throw new SdfException(classifyOpenFailure(e), "open", 0, e);
        } catch (RuntimeException e) {
            throw new SdfException(classifyOpenFailure(e), "open", 0, e);
        }
    }

    private static void validateOverrides(Properties overrides) {
        if (overrides == null) {
            return;
        }
        for (String key : overrides.stringPropertyNames()) {
            String lower = key.toLowerCase();
            if (lower.contains("passwd") || lower.contains("password") || lower.contains("pin")) {
                throw new IllegalArgumentException(
                        "SdfDevices.open does not accept credential-bearing property: " + key);
            }
            if (!ALLOWED_OVERRIDE_KEYS.contains(key)) {
                throw new IllegalArgumentException("Unsupported SDF override property: " + key);
            }
        }
    }

    private static void applyOverrides(Properties overrides) {
        if (overrides == null) {
            return;
        }
        for (String key : overrides.stringPropertyNames()) {
            String value = overrides.getProperty(key);
            if (value == null) {
                System.clearProperty(key);
            } else {
                System.setProperty(key, value);
            }
        }
    }

    private static void ensureProviderRegistered() {
        if (Security.getProvider(LiuZXProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new LiuZXProvider());
        }
    }

    private static void warmUp(SDFSessionManager sessionManager) {
        try (SDFSession session = sessionManager.borrowSession()) {
            // Borrowing and returning a session warms the pool. The try-with-resources
            // block returns it to the pool via SDFSession.close().
            if (session == null) {
                throw new SdfException(SdfErrorCategory.DEVICE_UNAVAILABLE, "open", 0, null);
            }
        }
    }

    private static SdfErrorCategory classifyOpenFailure(Throwable failure) {
        Throwable current = failure;
        while (current != null) {
            if (current instanceof UnsatisfiedLinkError
                    || current instanceof NoClassDefFoundError
                    || current instanceof ClassNotFoundException) {
                return SdfErrorCategory.NATIVE_DEPENDENCY_UNAVAILABLE;
            }
            current = current.getCause();
        }
        return SdfErrorCategory.DEVICE_UNAVAILABLE;
    }
}
