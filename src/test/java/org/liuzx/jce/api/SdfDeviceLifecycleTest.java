package org.liuzx.jce.api;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 门面生命周期状态机与工厂参数校验。无硬件时纯逻辑分支仍会执行；真实设备分支用
 * {@link Assumptions} 跳过。
 */
class SdfDeviceLifecycleTest {

    @Test
    void closeIsIdempotentAndBlocksFurtherCalls() {
        SdfDeviceImpl device = new SdfDeviceImpl();
        assertFalse(device.isClosed());

        device.close();
        device.close();

        assertTrue(device.isClosed());
        assertEquals("SdfDevice is closed",
                assertThrows(IllegalStateException.class, device::deviceInfo).getMessage());
        assertThrows(IllegalStateException.class, device::capabilities);
        assertThrows(IllegalStateException.class, () -> device.exportSignPublicKey(1));
        assertThrows(IllegalStateException.class, () -> device.signSm2(1, new byte[0], null));
        assertThrows(IllegalStateException.class, () -> device.signSm2Digest(1, new byte[32], null));
        assertThrows(IllegalStateException.class, () -> device.signRsa(1, new byte[0], null));
    }

    @Test
    void implHasNoPinField() {
        for (Field field : SdfDeviceImpl.class.getDeclaredFields()) {
            assertFalse(field.getType() == char[].class,
                    "SdfDeviceImpl must not store PIN material in a field: " + field.getName());
        }
    }

    @Test
    void factoryRejectsCredentialBearingProperties() {
        Properties withPin = new Properties();
        withPin.setProperty("liuzx.sdf.pin", "1234");
        assertThrows(IllegalArgumentException.class, () -> SdfDevices.open(withPin));

        Properties withPassword = new Properties();
        withPassword.setProperty("liuzx.sdf.password", "secret");
        assertThrows(IllegalArgumentException.class, () -> SdfDevices.open(withPassword));
    }

    @Test
    void factoryRejectsUnknownProperties() {
        Properties unknown = new Properties();
        unknown.setProperty("liuzx.sdf.unknown-key", "value");
        assertThrows(IllegalArgumentException.class, () -> SdfDevices.open(unknown));
    }

    @Test
    void opensRealDeviceWhenAvailable() {
        SdfDevice device;
        try {
            device = SdfDevices.open();
        } catch (SdfException e) {
            Assumptions.assumeTrue(false, "no SDF device available: " + e.category());
            return;
        }
        try {
            assertEquals("1234567812345678", device.capabilities().sm2DefaultUserId());
            assertTrue(device.capabilities().sessionPoolSize() > 0);
            assertTrue(device.deviceInfo().toSafeString().length() > 0);
        } finally {
            device.close();
        }
    }
}
