package org.liuzx.jce.api;

/**
 * 稳定公开的设备错误分类。
 *
 * <p>九个分类与消费方（liuzx-svs）的稳定分类一一对应，消费方直接做 1:1 映射，
 * 不应对分类做二次解释。分类是公开契约的一部分，新增分类属于兼容性新增。</p>
 */
public enum SdfErrorCategory {

    /** 设备不可用：连接失败或通信中断。 */
    DEVICE_UNAVAILABLE,

    /** 设备忙：设备未就绪或暂不可用，可重试。 */
    DEVICE_BUSY,

    /** 密钥不存在。 */
    KEY_NOT_FOUND,

    /** 密钥用途与请求操作不匹配。 */
    KEY_USAGE_MISMATCH,

    /** 设备不支持该算法或算法模式。 */
    ALGORITHM_UNSUPPORTED,

    /** 授权失败：私钥访问权被拒绝。 */
    AUTHORIZATION_FAILED,

    /** 其余设备运算失败。 */
    OPERATION_FAILED,

    /** 输入过大或参数超出设备能力。 */
    INPUT_TOO_LARGE,

    /** 原生依赖（厂商 SDF 动态库）不可用。 */
    NATIVE_DEPENDENCY_UNAVAILABLE
}
