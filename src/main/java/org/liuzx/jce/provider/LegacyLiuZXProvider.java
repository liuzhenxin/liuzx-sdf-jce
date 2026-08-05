package org.liuzx.jce.provider;

/**
 * 兼容 provider：使用旧名称 {@code "liuzx"} 注册与 {@link LiuZXProvider} 完全一致的服务。
 * <p>
 * JCE 的 provider 名称查找区分大小写，升级到主名 {@code "LiuZX"} 后，
 * 既有硬编码 {@code "liuzx"} 的调用需额外注册本类才能继续工作：
 * <pre>{@code
 * Security.addProvider(new LiuZXProvider());        // 新名称 "LiuZX"
 * Security.addProvider(new LegacyLiuZXProvider());  // 兼容旧名称 "liuzx"
 * }</pre>
 */
public class LegacyLiuZXProvider extends LiuZXProvider {

    public LegacyLiuZXProvider() {
        super(LiuZXProvider.LEGACY_PROVIDER_NAME);
    }
}
