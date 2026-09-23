package org.liuzx.jce.api;

/**
 * 公开的门面异常。
 *
 * <p>只携带稳定分类 {@link SdfErrorCategory}、操作名与脱敏后的厂商错误码，
 * 不暴露路径、PIN、密钥索引或设备序列号。原始厂商码只以十六进制形式出现在
 * {@link #internalDetail()} 中。</p>
 */
public class SdfException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final SdfErrorCategory category;
    private final String operation;
    private final int sdfCode;

    /**
     * @param category  稳定分类
     * @param operation 操作名，例如 {@code "signSm2"}
     * @param sdfCode   厂商原始错误码；没有厂商码时传 {@code 0}
     * @param cause     底层原因，可为 {@code null}
     */
    SdfException(SdfErrorCategory category, String operation, int sdfCode, Throwable cause) {
        super(operation + " failed", cause);
        this.category = category;
        this.operation = operation;
        this.sdfCode = sdfCode;
    }

    /** @return 稳定错误分类。 */
    public SdfErrorCategory category() {
        return category;
    }

    /** @return 操作名，例如 {@code "signSm2"}。 */
    public String operation() {
        return operation;
    }

    /**
     * @return 仅包含操作名与十六进制厂商码的脱敏细节，例如
     *         {@code "signSm2 (0x01000008)"}；没有厂商码时为操作名本身。
     */
    public String internalDetail() {
        if (sdfCode == 0) {
            return operation;
        }
        return String.format("%s (0x%08X)", operation, sdfCode);
    }

    /** @return 仅 {@code DEVICE_UNAVAILABLE} 与 {@code DEVICE_BUSY} 为 {@code true}。 */
    public boolean isRetryable() {
        return SdfErrorMapper.isRetryable(category);
    }
}
