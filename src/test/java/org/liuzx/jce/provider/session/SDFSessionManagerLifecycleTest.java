package org.liuzx.jce.provider.session;

import com.sun.jna.Pointer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.liuzx.jce.jna.SDFLibrary;
import org.liuzx.jce.provider.SDFConfig;

import java.nio.file.Files;
import java.nio.file.Path;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SDFSessionManagerLifecycleTest {

    @AfterEach
    public void clearProperties() {
        System.clearProperty(SDFSessionManager.POOL_SIZE_PROPERTY);
        System.clearProperty(SDFSessionManager.BORROW_TIMEOUT_PROPERTY);
        System.clearProperty(SDFConfig.VENDOR_CONFIG_PATH_PROPERTY);
        System.clearProperty(SDFConfig.CONFIG_PATH_PROPERTY);
    }

    @Test
    public void zeroSessionInitializationIsNotMarkedSuccessful() throws Exception {
        System.setProperty(SDFSessionManager.POOL_SIZE_PROPERTY, "1");
        SDFLibrary failingLibrary = libraryProxy(null, null, 1);
        SDFSessionManager manager = newManager(failingLibrary);

        Method ensureInitialized = SDFSessionManager.class.getDeclaredMethod("ensureInitialized");
        ensureInitialized.setAccessible(true);
        InvocationTargetException error = assertThrows(InvocationTargetException.class,
                () -> ensureInitialized.invoke(manager));

        Field initialized = SDFSessionManager.class.getDeclaredField("initialized");
        initialized.setAccessible(true);
        assertTrue(error.getCause() instanceof IllegalStateException);
        assertTrue(error.getCause().getMessage().contains("zero sessions"));
        assertFalse(initialized.getBoolean(manager));
        assertEquals(0, manager.getAvailableSessionCount());

        manager.shutdown();
    }

    @Test
    @SuppressWarnings("unchecked")
    public void shutdownIsPublicTerminalAndIdempotent() throws Exception {
        AtomicInteger closedSessions = new AtomicInteger();
        AtomicInteger closedDevices = new AtomicInteger();
        SDFLibrary library = libraryProxy(closedSessions, closedDevices, 0);
        SDFSessionManager manager = newManager(library);
        SDFSession session = new SDFSession(new Pointer(1), new Pointer(2), manager);

        Field allSessionsField = SDFSessionManager.class.getDeclaredField("allSessions");
        allSessionsField.setAccessible(true);
        ((Set<SDFSession>) allSessionsField.get(manager)).add(session);
        Field sessionPoolField = SDFSessionManager.class.getDeclaredField("sessionPool");
        sessionPoolField.setAccessible(true);
        ((BlockingQueue<SDFSession>) sessionPoolField.get(manager)).add(session);

        manager.shutdown();
        manager.shutdown();

        assertEquals(1, closedSessions.get());
        assertEquals(1, closedDevices.get());
        assertEquals(0, manager.getAvailableSessionCount());
        assertThrows(IllegalStateException.class, manager::borrowSession);
    }

    @Test
    public void configuredVendorFileUsesOpenDeviceEx() throws Exception {
        Path config = Files.createTempFile("sdf-vendor-", ".ini");
        System.setProperty(SDFConfig.VENDOR_CONFIG_PATH_PROPERTY, config.toString());
        AtomicReference<String> receivedConfigPath = new AtomicReference<String>();
        SDFLibrary library = (SDFLibrary) Proxy.newProxyInstance(
                SDFLibrary.class.getClassLoader(),
                new Class<?>[]{SDFLibrary.class},
                (proxy, method, args) -> {
                    if ("SDF_OpenDeviceEx".equals(method.getName())) {
                        ((Pointer[]) args[0])[0] = new Pointer(10);
                        receivedConfigPath.set((String) args[1]);
                        return 0;
                    }
                    if ("SDF_OpenSession".equals(method.getName())) {
                        ((Pointer[]) args[1])[0] = new Pointer(11);
                        return 0;
                    }
                    if ("SDF_OpenDevice".equals(method.getName())) {
                        throw new AssertionError("SDF_OpenDevice must not be used when a config path is set");
                    }
                    return method.getReturnType() == Integer.TYPE ? 0 : null;
                });
        SDFSessionManager manager = newManager(library);

        Method openSession = SDFSessionManager.class.getDeclaredMethod("openSession");
        openSession.setAccessible(true);
        SDFSession session = (SDFSession) openSession.invoke(manager);

        assertEquals(config.toRealPath().toString(), receivedConfigPath.get());
        session.destroy();
        manager.shutdown();
        Files.deleteIfExists(config);
    }

    private static SDFSessionManager newManager(SDFLibrary library) throws Exception {
        Constructor<SDFSessionManager> constructor =
                SDFSessionManager.class.getDeclaredConstructor(SDFLibrary.class);
        constructor.setAccessible(true);
        return constructor.newInstance(library);
    }

    private static SDFLibrary libraryProxy(AtomicInteger closedSessions, AtomicInteger closedDevices,
            int openDeviceResult) {
        return (SDFLibrary) Proxy.newProxyInstance(
                SDFLibrary.class.getClassLoader(),
                new Class<?>[]{SDFLibrary.class},
                (proxy, method, args) -> {
                    if ("SDF_OpenDevice".equals(method.getName())) {
                        return openDeviceResult;
                    }
                    if ("SDF_CloseSession".equals(method.getName()) && closedSessions != null) {
                        closedSessions.incrementAndGet();
                    }
                    if ("SDF_CloseDevice".equals(method.getName()) && closedDevices != null) {
                        closedDevices.incrementAndGet();
                    }
                    return method.getReturnType() == Integer.TYPE ? 0 : null;
                });
    }
}
