package org.liuzx.jce.provider.exception;

import java.security.ProviderException;

public class SDFException extends ProviderException {

    private final int errorCode;
    private final String functionName;

    public SDFException(String functionName, int errorCode) {
        super(formatMessage(functionName, errorCode));
        this.functionName = functionName;
        this.errorCode = errorCode;
    }

    public int getErrorCode() {
        return errorCode;
    }

    public String getFunctionName() {
        return functionName;
    }

    private static String formatMessage(String functionName, int errorCode) {
        String errorDescription = getErrorDescription(errorCode);
        return String.format("%s failed. Error Code: 0x%08X (%s)", functionName, errorCode, errorDescription);
    }

    public static String getErrorDescription(int errorCode) {
        switch (errorCode) {
            case SDFErrorConstants.SDR_OK: return "成功 (Success)";
            case SDFErrorConstants.SDR_UNKNOWERR: return "未知错误 (Unknown Error)";
            case SDFErrorConstants.SDR_NOTSUPPORT: return "不支持的功能 (Not Supported)";
            case SDFErrorConstants.SDR_COMMFAIL: return "与设备通信失败 (Communication Failure)";
            case SDFErrorConstants.SDR_HARDFAIL: return "硬件故障 (Hardware Failure)";
            case SDFErrorConstants.SDR_OPENDEVICE: return "打开设备失败 (Failed to Open Device)";
            case SDFErrorConstants.SDR_OPENSESSION: return "创建会话失败 (Failed to Open Session)";
            case SDFErrorConstants.SDR_PARDENY: return "无权限执行该操作 (Permission Denied)";
            case SDFErrorConstants.SDR_KEYNOTEXIST: return "密钥不存在 (Key Not Exist)";
            case SDFErrorConstants.SDR_ALGNOTSUPPORT: return "不支持的算法 (Algorithm Not Supported)";
            case SDFErrorConstants.SDR_ALGMODNOTSUPPORT: return "不支持的算法模式 (Algorithm Mode Not Supported)";
            case SDFErrorConstants.SDR_PKOPERR: return "公钥运算失败 (Public Key Operation Error)";
            case SDFErrorConstants.SDR_SKOPERR: return "私钥运算失败 (Private Key Operation Error)";
            case SDFErrorConstants.SDR_SIGNERR: return "签名失败 (Signature Error)";
            case SDFErrorConstants.SDR_VERIFYERR: return "验签失败 (Verification Error)";
            case SDFErrorConstants.SDR_SYMOPERR: return "对称运算失败 (Symmetric Operation Error)";
            case SDFErrorConstants.SDR_STEPERR: return "多步运算步骤错误 (Step Error)";
            case SDFErrorConstants.SDR_FILESIZEERR: return "文件大小错误 (File Size Error)";
            case SDFErrorConstants.SDR_FILENOEXIST: return "文件不存在 (File Not Exist)";
            case SDFErrorConstants.SDR_FILEOFSERR: return "文件偏移错误 (File Offset Error)";
            case SDFErrorConstants.SDR_KEYTYPEERR: return "密钥类型错误 (Key Type Error)";
            case SDFErrorConstants.SDR_KEYERR: return "密钥错误 (Key Error)";
            case SDFErrorConstants.SDR_ENCDATAERR: return "加密数据错误 (Encrypted Data Error)";
            case SDFErrorConstants.SDR_RANDERR: return "随机数生成失败 (Random Generation Error)";
            case SDFErrorConstants.SDR_PRKRERR: return "私钥权限获取失败 (Private Key Access Right Error)";
            case SDFErrorConstants.SDR_MACERR: return "MAC运算失败 (MAC Operation Error)";
            case SDFErrorConstants.SDR_FILEEXISTS: return "文件已存在 (File Already Exists)";
            case SDFErrorConstants.SDR_FILEWERR: return "文件写入错误 (File Write Error)";
            case SDFErrorConstants.SDR_NOBUFFER: return "存储空间不足 (No Buffer)";
            case SDFErrorConstants.SDR_INARGERR: return "输入参数错误 (Input Argument Error)";
            case SDFErrorConstants.SDR_OUTARGERR: return "输出参数错误 (Output Argument Error)";
            default: return "未知或厂商自定义错误 (Unknown or Vendor-Specific Error)";
        }
    }
}
