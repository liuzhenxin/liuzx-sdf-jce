package org.liuzx.jce.api;

import org.liuzx.jce.provider.exception.SDFErrorConstants;

/**
 * 把 GM/T 0018-2012 的原始厂商错误码映射到 {@link SdfErrorCategory}。
 *
 * <p>包私有：这是公开门面的内部实现细节，不对外暴露。</p>
 */
final class SdfErrorMapper {

    private SdfErrorMapper() {
    }

    /**
     * @param sdfCode 厂商原始返回码（{@code 0} 表示成功，不是错误）
     * @return 稳定的错误分类，永不为 {@code null}
     * @throws IllegalArgumentException 当 {@code sdfCode} 为成功码 {@code 0} 时
     */
    static SdfErrorCategory map(int sdfCode) {
        if (sdfCode == SDFErrorConstants.SDR_OK) {
            throw new IllegalArgumentException("SDR_OK is not an error code");
        }
        switch (sdfCode) {
            case SDFErrorConstants.SDR_COMMFAIL:
                return SdfErrorCategory.DEVICE_UNAVAILABLE;
            case SDFErrorConstants.SDR_HSM_NOT_READY:
                return SdfErrorCategory.DEVICE_BUSY;
            case SDFErrorConstants.SDR_KEYNOTEXIST:
            case SDFErrorConstants.SDR_KEYERR:
                // Shudun reports a missing/retrieval-failed key as SDR_KEYERR (0x01000015),
                // not SDR_KEYNOTEXIST, so both map to KEY_NOT_FOUND.
                return SdfErrorCategory.KEY_NOT_FOUND;
            case SDFErrorConstants.SDR_KEYTYPEERR:
                return SdfErrorCategory.KEY_USAGE_MISMATCH;
            case SDFErrorConstants.SDR_ALGNOTSUPPORT:
            case SDFErrorConstants.SDR_ALGMODNOTSUPPORT:
                return SdfErrorCategory.ALGORITHM_UNSUPPORTED;
            case SDFErrorConstants.SDR_PARDENY:
            case SDFErrorConstants.SDR_PRKRERR:
                return SdfErrorCategory.AUTHORIZATION_FAILED;
            case SDFErrorConstants.SDR_INARGERR:
            case SDFErrorConstants.SDR_OUTARGERR:
                return SdfErrorCategory.INPUT_TOO_LARGE;
            default:
                return SdfErrorCategory.OPERATION_FAILED;
        }
    }

    /** 仅设备不可用与设备忙被标记为可重试。 */
    static boolean isRetryable(SdfErrorCategory category) {
        return category == SdfErrorCategory.DEVICE_UNAVAILABLE
                || category == SdfErrorCategory.DEVICE_BUSY;
    }
}
