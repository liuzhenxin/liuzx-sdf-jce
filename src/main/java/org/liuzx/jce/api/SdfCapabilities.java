package org.liuzx.jce.api;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

/**
 * 能力指纹：调用方在签名前可据此判断设备支持范围（不可变值对象）。
 *
 * <p>{@link #sm2DefaultUserId()} 必须来自实际生效值（{@code SM2SignatureSpi.DEFAULT_USER_ID_STRING}），
 * 不允许调用方自行猜测或硬编码兜底。</p>
 *
 * <p>本类型按 Java 8 兼容的不可变 final 类实现（不使用 {@code record} 关键字），
 * 但保留与 record 等价的访问器命名。</p>
 */
public final class SdfCapabilities {

    private final Set<AlgorithmFamily> families;
    private final boolean sm2DigestSigningSupported;
    private final String sm2DefaultUserId;
    private final int sessionPoolSize;
    private final int sessionPoolAvailable;
    private final long borrowTimeoutMillis;

    public SdfCapabilities(Set<AlgorithmFamily> families,
                           boolean sm2DigestSigningSupported,
                           String sm2DefaultUserId,
                           int sessionPoolSize,
                           int sessionPoolAvailable,
                           long borrowTimeoutMillis) {
        Objects.requireNonNull(families, "families");
        this.families = Collections.unmodifiableSet(new LinkedHashSet<AlgorithmFamily>(families));
        this.sm2DigestSigningSupported = sm2DigestSigningSupported;
        this.sm2DefaultUserId = Objects.requireNonNull(sm2DefaultUserId, "sm2DefaultUserId");
        this.sessionPoolSize = sessionPoolSize;
        this.sessionPoolAvailable = sessionPoolAvailable;
        this.borrowTimeoutMillis = borrowTimeoutMillis;
    }

    public Set<AlgorithmFamily> families() { return families; }

    public boolean sm2DigestSigningSupported() { return sm2DigestSigningSupported; }

    public String sm2DefaultUserId() { return sm2DefaultUserId; }

    public int sessionPoolSize() { return sessionPoolSize; }

    public int sessionPoolAvailable() { return sessionPoolAvailable; }

    public long borrowTimeoutMillis() { return borrowTimeoutMillis; }

    @Override
    public String toString() {
        return "SdfCapabilities[families=" + families
                + ", sm2DigestSigningSupported=" + sm2DigestSigningSupported
                + ", sm2DefaultUserId=" + sm2DefaultUserId
                + ", sessionPoolSize=" + sessionPoolSize
                + ", sessionPoolAvailable=" + sessionPoolAvailable
                + ", borrowTimeoutMillis=" + borrowTimeoutMillis
                + "]";
    }
}
