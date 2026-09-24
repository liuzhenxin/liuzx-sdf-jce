package org.liuzx.jce.api;

import org.junit.jupiter.api.Test;
import org.liuzx.jce.provider.exception.SDFErrorConstants;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 校验厂商错误码到九类稳定分类的映射，不依赖任何硬件。
 */
class SdfErrorCategoryMappingTest {

    @Test
    void exposesExactlyNineCategories() {
        assertEquals(9, SdfErrorCategory.values().length);
    }

    @Test
    void mapsDeviceCodes() {
        assertEquals(SdfErrorCategory.DEVICE_UNAVAILABLE,
                SdfErrorMapper.map(SDFErrorConstants.SDR_COMMFAIL));
        assertEquals(SdfErrorCategory.DEVICE_BUSY,
                SdfErrorMapper.map(SDFErrorConstants.SDR_HSM_NOT_READY));
    }

    @Test
    void mapsKeyCodes() {
        assertEquals(SdfErrorCategory.KEY_NOT_FOUND,
                SdfErrorMapper.map(SDFErrorConstants.SDR_KEYNOTEXIST));
        assertEquals(SdfErrorCategory.KEY_USAGE_MISMATCH,
                SdfErrorMapper.map(SDFErrorConstants.SDR_KEYTYPEERR));
        // Shudun reports a missing key as SDR_KEYERR (0x01000015), not SDR_KEYNOTEXIST.
        assertEquals(SdfErrorCategory.KEY_NOT_FOUND,
                SdfErrorMapper.map(SDFErrorConstants.SDR_KEYERR));
    }

    @Test
    void mapsAlgorithmCodes() {
        assertEquals(SdfErrorCategory.ALGORITHM_UNSUPPORTED,
                SdfErrorMapper.map(SDFErrorConstants.SDR_ALGNOTSUPPORT));
        assertEquals(SdfErrorCategory.ALGORITHM_UNSUPPORTED,
                SdfErrorMapper.map(SDFErrorConstants.SDR_ALGMODNOTSUPPORT));
    }

    @Test
    void mapsAuthorizationCodes() {
        assertEquals(SdfErrorCategory.AUTHORIZATION_FAILED,
                SdfErrorMapper.map(SDFErrorConstants.SDR_PARDENY));
        assertEquals(SdfErrorCategory.AUTHORIZATION_FAILED,
                SdfErrorMapper.map(SDFErrorConstants.SDR_PRKRERR));
    }

    @Test
    void mapsInputCodes() {
        assertEquals(SdfErrorCategory.INPUT_TOO_LARGE,
                SdfErrorMapper.map(SDFErrorConstants.SDR_INARGERR));
        assertEquals(SdfErrorCategory.INPUT_TOO_LARGE,
                SdfErrorMapper.map(SDFErrorConstants.SDR_OUTARGERR));
    }

    @Test
    void mapsUnknownCodeToOperationFailed() {
        assertEquals(SdfErrorCategory.OPERATION_FAILED,
                SdfErrorMapper.map(SDFErrorConstants.SDR_SIGNERR));
        assertEquals(SdfErrorCategory.OPERATION_FAILED,
                SdfErrorMapper.map(0x0100FFFF));
    }

    @Test
    void rejectsSuccessCode() {
        assertThrows(IllegalArgumentException.class, () -> SdfErrorMapper.map(SDFErrorConstants.SDR_OK));
    }

    @Test
    void retryableOnlyForDeviceCategories() {
        assertTrue(SdfErrorMapper.isRetryable(SdfErrorCategory.DEVICE_UNAVAILABLE));
        assertTrue(SdfErrorMapper.isRetryable(SdfErrorCategory.DEVICE_BUSY));
        for (SdfErrorCategory category : SdfErrorCategory.values()) {
            if (category != SdfErrorCategory.DEVICE_UNAVAILABLE
                    && category != SdfErrorCategory.DEVICE_BUSY) {
                assertFalse(SdfErrorMapper.isRetryable(category), category + " must not be retryable");
            }
        }
    }
}
