package org.liuzx.jce.provider.test;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.liuzx.jce.provider.LiuZXProvider;
import org.liuzx.jce.provider.util.DeviceInfoUtil;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 需要真实数盾密码机和外置原生库的验收测试。
 */
@EnabledIfSystemProperty(named = "shudun.it.enabled", matches = "true")
class ShudunIT {

	@BeforeAll
	static void registerProvider() {
		System.setProperty("liuzx.sdf.vendor", "Shudun");
		if (Security.getProvider(LiuZXProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new LiuZXProvider());
		}
	}

	@Test
	void shouldProbeDeviceAndGenerateHardwareRandom() throws Exception {
		DeviceInfoUtil.DeviceInfo info = DeviceInfoUtil.getDeviceInfo();
		assertNotNull(info.getDeviceSerial());
		byte[] random = new byte[32];
		SecureRandom.getInstance("SDF", LiuZXProvider.PROVIDER_NAME).nextBytes(random);
		assertTrue(hasNonZeroByte(random));
	}

	@Test
	void shouldGenerateSm2EncryptionKeyMaterial() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("SM2", LiuZXProvider.PROVIDER_NAME);
		generator.initialize(256);
		KeyPair pair = generator.generateKeyPair();
		assertNotNull(pair.getPublic().getEncoded());
		assertNotNull(pair.getPrivate().getEncoded());
	}

	@Test
	void shouldGenerateRsa2048And4096KeyMaterial() throws Exception {
		assertRsaSize(2048);
		assertRsaSize(4096);
	}

	private void assertRsaSize(int bits) throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", LiuZXProvider.PROVIDER_NAME);
		generator.initialize(bits);
		KeyPair pair = generator.generateKeyPair();
		assertEquals(bits, ((java.security.interfaces.RSAPublicKey) pair.getPublic()).getModulus().bitLength());
		assertNotNull(pair.getPrivate().getEncoded());
	}

	private boolean hasNonZeroByte(byte[] value) {
		for (byte item : value) {
			if (item != 0) {
				return true;
			}
		}
		return false;
	}

}
