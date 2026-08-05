package org.liuzx.jce.jna;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import org.liuzx.jce.jna.structure.*;
import org.liuzx.jce.provider.SDFConfig;

public interface SDFLibrary extends Library {

    static SDFLibrary getInstance() {
        return LazyHolder.INSTANCE;
    }

    class LazyHolder {
        static final SDFLibrary INSTANCE = loadLibrary();

        private static SDFLibrary loadLibrary() {
            String path = SDFConfig.getInstance().getDefaultLibraryPath();
            try {
                return Native.load(path, SDFLibrary.class);
            } catch (Throwable firstError) {
                System.err.println("[SDFLibrary] Failed to load native library with path: " + path);
                System.err.println("[SDFLibrary] Error: " + firstError);
                if (firstError.getCause() != null) {
                    System.err.println("[SDFLibrary] Caused by: " + firstError.getCause());
                }
                try {
                    System.err.println("[SDFLibrary] Trying fallback: Native.load(\"sdcrypto4j\", ...)");
                    SDFLibrary lib = Native.load("sdcrypto4j", SDFLibrary.class);
                    System.err.println("[SDFLibrary] Fallback succeeded via short name");
                    return lib;
                } catch (Throwable fallbackError) {
                    System.err.println("[SDFLibrary] Fallback also failed: " + fallbackError);
                    throw new RuntimeException(
                            "Failed to load SDF native library. Path='" + path
                                    + "', java.library.path='" + System.getProperty("java.library.path")
                                    + "', jna.library.path='" + System.getProperty("jna.library.path")
                                    + "'. First error: " + firstError
                                    + ". Fallback error: " + fallbackError,
                            firstError);
                }
            }
        }
    }

    // =========================================================================
    // Device Management
    // =========================================================================
    int SDF_OpenDevice(Pointer[] phDeviceHandle);
    int SDF_CloseDevice(Pointer hDeviceHandle);
    int SDF_OpenSession(Pointer hDeviceHandle, Pointer[] phSessionHandle);
    int SDF_CloseSession(Pointer hSessionHandle);
    int SDF_GetDeviceInfo(Pointer hSessionHandle, DEVICEINFO.ByReference pstDeviceInfo);
    int SDF_GenerateRandom(Pointer hSessionHandle, int uiLength, byte[] pucRandom);
    int SDF_GenerateRandomExt(Pointer hSessionHandle, byte[] pucRandom, int uiLength);
    int SDF_GetPrivateKeyAccessRight(Pointer hSessionHandle, int uiKeyIndex, byte[] pucPassword, int uiPwdLength);
    int SDF_ReleasePrivateKeyAccessRight(Pointer hSessionHandle, int uiKeyIndex);
    int SDF_OpenDeviceEx(Pointer[] phDeviceHandle, String iniPath, Pointer pconf);
    int SDF_Echo(Pointer hSessionHandle, byte[] inData, int inDataLen, byte[] outData, IntByReference outDataLen);

    // =========================================================================
    // Key Management — RSA
    // =========================================================================
    int SDF_ExportSignPublicKey_RSA(Pointer hSessionHandle, int uiKeyIndex, RSArefPublicKey.ByReference pucPublicKey);
    int SDF_ExportEncPublicKey_RSA(Pointer hSessionHandle, int uiKeyIndex, RSArefPublicKey.ByReference pucPublicKey);
    int SDF_GenerateKeyPair_RSA(Pointer hSessionHandle, int uiKeyBits, RSArefPublicKey.ByReference pucPublicKey, RSArefPrivateKey.ByReference pucPrivateKey);
    int SDF_GenerateKeyWithIPK_RSA(Pointer hSessionHandle, int uiIPKIndex, int uiKeyBits, byte[] pucKey, IntByReference puiKeyLength, Pointer[] phKeyHandle);
    int SDF_GenerateKeyWithEPK_RSA(Pointer hSessionHandle, int uiKeyBits, RSArefPublicKey.ByReference pucPublicKey, byte[] pucKey, IntByReference puiKeyLength, Pointer[] phKeyHandle);
    int SDF_ImportKeyWithISK_RSA(Pointer hSessionHandle, int uiISKIndex, byte[] pucKey, int uiKeyLength, Pointer[] phKeyHandle);

    // =========================================================================
    // Key Management — ECC
    // =========================================================================
    int SDF_ExportSignPublicKey_ECC(Pointer hSessionHandle, int uiKeyIndex, ECCrefPublicKey.ByReference pucPublicKey);
    int SDF_ExportEncPublicKey_ECC(Pointer hSessionHandle, int uiKeyIndex, ECCrefPublicKey.ByReference pucPublicKey);
    int SDF_GenerateKeyPair_ECC(Pointer hSessionHandle, int uiAlgId, int uiKeyBits, ECCrefPublicKey.ByReference pucPublicKey, ECCrefPrivateKey.ByReference pucPrivateKey);
    int SDF_GenerateKeyWithIPK_ECC(Pointer hSessionHandle, int uiIPKIndex, int uiKeyBits, ECCCipher.ByReference pucKey, Pointer[] phKeyHandle);
    int SDF_GenerateKeyWithEPK_ECC(Pointer hSessionHandle, int uiKeyBits, int uiAlgID, ECCrefPublicKey.ByReference pucPublicKey, ECCCipher.ByReference pucKey, Pointer[] phKeyHandle);
    int SDF_ImportKeyWithISK_ECC(Pointer hSessionHandle, int uiISKIndex, ECCCipher.ByReference pucKey, Pointer[] phKeyHandle);

    // =========================================================================
    // Key Management — Symmetric
    // =========================================================================
    int SDF_ImportKey(Pointer hSessionHandle, byte[] pucKey, int uiKeyLength, Pointer[] phKeyHandle);
    int SDF_ImportKEK(Pointer hSessionHandle, int uiKEKIndex, int uiKeyLength, Pointer[] phKeyHandle);
    int SDF_ImportKeyWithKEK(Pointer hSessionHandle, int uiAlgID, int uiKEKIndex, byte[] pucKey, int uiKeyLength, Pointer[] phKeyHandle);
    int SDF_GenerateKeyWithKEK(Pointer hSessionHandle, int uiKeyBits, int uiAlgID, int uiKEKIndex, byte[] pucKey, IntByReference puiKeyLength, Pointer[] phKeyHandle);
    int SDF_DestroyKey(Pointer hSessionHandle, Pointer hKeyHandle);
    int SDF_GetSymmKeyHandle(Pointer hSessionHandle, int uiKeyIndex, Pointer[] phKeyHandle);

    // =========================================================================
    // Key Management — ECC Agreement (SM2 Key Exchange)
    // =========================================================================
    int SDF_GenerateAgreementDataWithECC(Pointer hSessionHandle, int uiISKIndex, int uiKeyBits,
            byte[] pucSponsorID, int uiSponsorIDLength, ECCrefPublicKey.ByReference pucSponsorPublicKey,
            ECCrefPublicKey.ByReference pucSponsorTmpPublicKey, Pointer[] phAgreementHandle);
    int SDF_GenerateKeyWithECC(Pointer hSessionHandle, byte[] pucSponsorID, int uiSponsorIDLength,
            ECCrefPublicKey.ByReference pucResponsePublicKey, ECCrefPublicKey.ByReference pucResponseTmpPublicKey,
            Pointer hAgreementHandle, Pointer[] phKeyHandle);
    int SDF_GenerateAgreementDataAndKeyWithECC(Pointer hSessionHandle, int uiISKIndex, int uiKeyBits,
            byte[] pucSponsorID, int uiSponsorIDLength, byte[] pucResponseID, int uiResponseIDLength,
            ECCrefPublicKey.ByReference pucSponsorPublicKey, ECCrefPublicKey.ByReference pucSponsorTmpPublicKey,
            ECCrefPublicKey.ByReference pucResponsePublicKey, ECCrefPublicKey.ByReference pucResponseTmpPublicKey,
            Pointer[] phKeyHandle);

    // =========================================================================
    // Digital Envelope
    // =========================================================================
    int SDF_ExchangeDigitEnvelopeBaseOnRSA(Pointer hSessionHandle, int uiKeyIndex,
            RSArefPublicKey.ByReference pucPublicKey, byte[] pucDEInput, int uiDELength,
            byte[] pucDEOutput, IntByReference puiDELength);
    int SDF_ExchangeDigitEnvelopeBaseOnECC(Pointer hSessionHandle, int uiKeyIndex, int uiAlgID,
            ECCrefPublicKey.ByReference pucPublicKey, ECCCipher.ByReference pucEncDataIn,
            ECCCipher.ByReference pucEncDataOut);

    // =========================================================================
    // Asymmetric — ECC Operations
    // =========================================================================
    int SDF_ExternalSign_ECC(Pointer hSessionHandle, int uiAlgID, ECCrefPrivateKey pucPrivateKey,
            byte[] pucData, int uiDataLength, ECCSignature.ByReference pucSignature);
    int SDF_ExternalVerify_ECC(Pointer hSessionHandle, int uiAlgID, ECCrefPublicKey pucPublicKey,
            byte[] pucData, int uiDataLength, ECCSignature pucSignature);
    int SDF_InternalSign_ECC(Pointer hSessionHandle, int uiISKIndex, byte[] pucData, int uiDataLength,
            ECCSignature.ByReference pucSignature);
    int SDF_InternalVerify_ECC(Pointer hSessionHandle, int uiISKIndex, byte[] pucData, int uiDataLength,
            ECCSignature pucSignature);
    int SDF_ExternalEncrypt_ECC(Pointer hSessionHandle, int uiAlgID, ECCrefPublicKey pucPublicKey,
            byte[] pucData, int uiDataLength, ECCCipher.ByReference pucEncData);
    int SDF_ExternalDecrypt_ECC(Pointer hSessionHandle, int uiAlgID, ECCrefPrivateKey pucPrivateKey,
            ECCCipher pucEncData, byte[] pucData, IntByReference puiDataLength);
    int SDF_InternalEncrypt_ECC(Pointer hSessionHandle, int uiKeyIndex, int uiAlgID,
            byte[] pucData, int uiDataLength, ECCCipher.ByReference pucEncData);
    int SDF_InternalDecrypt_ECC(Pointer hSessionHandle, int uiKeyIndex, int uiAlgID,
            ECCCipher pucEncData, byte[] pucData, IntByReference puiDataLength);

    // =========================================================================
    // Asymmetric — RSA Operations
    // =========================================================================
    int SDF_InternalSign_RSA(Pointer hSessionHandle, int uiKeyIndex, byte[] pucData, int uiDataLength,
            byte[] pucSignature, IntByReference puiSignatureLength);
    int SDF_ExternalVerify_RSA(Pointer hSessionHandle, RSArefPublicKey.ByReference pucPublicKey,
            byte[] pucData, int uiDataLength, byte[] pucSignature, int uiSignatureLength);
    int SDF_ExternalPublicKeyOperation_RSA(Pointer hSessionHandle, RSArefPublicKey.ByReference pucPublicKey,
            byte[] pucDataInput, int uiInputLength, byte[] pucDataOutput, IntByReference puiOutputLength);
    int SDF_InternalPublicKeyOperation_RSA(Pointer hSessionHandle, int uiKeyIndex, byte[] pucDataInput,
            int uiInputLength, byte[] pucDataOutput, IntByReference puiOutputLength);
    int SDF_ExternalPrivateKeyOperation_RSA(Pointer hSessionHandle, RSArefPrivateKey.ByReference pucPrivateKey,
            byte[] pucDataInput, int uiInputLength, byte[] pucDataOutput, IntByReference puiOutputLength);
    int SDF_InternalPrivateKeyOperation_RSA(Pointer hSessionHandle, int uiKeyIndex, byte[] pucDataInput,
            int uiInputLength, byte[] pucDataOutput, IntByReference puiOutputLength);
    int SDF_InternalEncrypt_RSA(Pointer hSessionHandle, int uiKeyIndex, byte[] pucDataInput,
            int uiInputLength, byte[] pucDataOutput, IntByReference puiOutputLength);
    int SDF_InternalDecrypt_RSA(Pointer hSessionHandle, int uiKeyIndex, byte[] pucDataInput,
            int uiInputLength, byte[] pucDataOutput, IntByReference puiOutputLength);

    // =========================================================================
    // Asymmetric — ECDSA Operations
    // =========================================================================
    int SDF_GenerateKeyPair_ECDSA(Pointer hSessionHandle, int uiAlgID, int uiKeyBits,
            ECCrefPublicKey_ECDSA.ByReference pucPublicKey, ECCrefPrivateKey_ECDSA.ByReference pucPrivateKey);
    int SDF_ExternalSign_ECC_ECDSA(Pointer hSessionHandle, int uiAlgID,
            ECCrefPrivateKey_ECDSA.ByReference pucPrivateKey, byte[] pucData, int uiDataLength,
            ECCSignature_ECDSA.ByReference pucSignature);
    int SDF_ExternalVerify_ECC_ECDSA(Pointer hSessionHandle, int uiAlgID,
            ECCrefPublicKey_ECDSA.ByReference pucPublicKey, byte[] pucData, int uiDataLength,
            ECCSignature_ECDSA.ByReference pucSignature);
    int SDF_InternalSign_ECC_ECDSA(Pointer hSessionHandle, int uiISKIndex, int uiAlgID,
            byte[] pucData, int uiDataLength, ECCSignature_ECDSA.ByReference pucSignature);
    int SDF_InternalVerify_ECC_ECDSA(Pointer hSessionHandle, int uiISKIndex, int uiAlgID,
            byte[] pucData, int uiDataLength, ECCSignature_ECDSA.ByReference pucSignature);

    // =========================================================================
    // Asymmetric — EdDSA Operations
    // =========================================================================
    int SDF_GenerateKeyPair_EDDSA(Pointer hSessionHandle, int uiAlgID, int uiKeyBits,
            ECCrefPublicKey_EDDSA.ByReference pucPublicKey, ECCrefPrivateKey_EDDSA.ByReference pucPrivateKey);
    int SDF_ExternalSign_ECC_EDDSA(Pointer hSessionHandle, int uiAlgID,
            ECCrefPrivateKey_EDDSA.ByReference pucPrivateKey, byte[] pucData, int uiDataLength,
            ECCSignature_EDDSA.ByReference pucSignature);
    int SDF_ExternalVerify_ECC_EDDSA(Pointer hSessionHandle, int uiAlgID,
            ECCrefPublicKey_EDDSA.ByReference pucPublicKey, byte[] pucData, int uiDataLength,
            ECCSignature_EDDSA.ByReference pucSignature);
    int SDF_InternalSign_ECC_EDDSA(Pointer hSessionHandle, int uiISKIndex, int uiAlgID,
            byte[] pucData, int uiDataLength, ECCSignature_EDDSA.ByReference pucSignature);
    int SDF_InternalVerify_ECC_EDDSA(Pointer hSessionHandle, int uiISKIndex, int uiAlgID,
            byte[] pucData, int uiDataLength, ECCSignature_EDDSA.ByReference pucSignature);

    // =========================================================================
    // Asymmetric — DSA Operations
    // =========================================================================
    int SDF_GenerateKeyPair_DSA(Pointer hSessionHandle, int uiKeyBits,
            DSArefPublicKey.ByReference pucPublicKey, DSArefPrivateKey.ByReference pucPrivateKey);
    int SDF_ExternalSign_DSA(Pointer hSessionHandle, DSArefPrivateKey.ByReference pucPrivateKey,
            byte[] pucData, int uiDataLength, DSASignature.ByReference pucSignature);
    int SDF_ExternalVerify_DSA(Pointer hSessionHandle, DSArefPublicKey.ByReference pucPublicKey,
            byte[] pucDataInput, int uiInputLength, DSASignature.ByReference pucSignature);
    int SDF_InternalSign_ECC_DSA(Pointer hSessionHandle, int uiIndex, byte[] pucData, int uiDataLength,
            DSASignature.ByReference pucSignature);
    int SDF_InternalVerify_ECC_DSA(Pointer hSessionHandle, int uiIndex, byte[] pucData, int uiDataLength,
            DSASignature.ByReference pucSignature);

    // =========================================================================
    // Symmetric Operations
    // =========================================================================
    int SDF_Encrypt(Pointer hSessionHandle, Pointer hKeyHandle, int uiAlgID, byte[] pucIV,
            byte[] pucData, int uiDataLength, byte[] pucEncData, IntByReference puiEncDataLength);
    int SDF_Decrypt(Pointer hSessionHandle, Pointer hKeyHandle, int uiAlgID, byte[] pucIV,
            byte[] pucEncData, int uiEncDataLength, byte[] pucData, IntByReference puiDataLength);
    int SDF_Encrypt_Index(Pointer hSessionHandle, int uiAlgID, byte[] pucIV, int uiKeyIndex,
            byte[] pucData, int uiDataLength, byte[] pucEncData, IntByReference puiEncDataLength);
    int SDF_Decrypt_Index(Pointer hSessionHandle, int uiAlgID, byte[] pucIV, int uiKeyIndex,
            byte[] pucEncData, int uiEncDataLength, byte[] pucData, IntByReference puiDataLength);
    int SDF_InternalEncrypt(Pointer hSessionHandle, int uiAlgID, int uiKeyIndex, byte[] pucIV,
            byte[] pucData, int uiDataLength, byte[] pucEncData, IntByReference puiEncDataLength);
    int SDF_InternalDecrypt(Pointer hSessionHandle, int uiAlgID, int uiKeyIndex, byte[] pucIV,
            byte[] pucEncData, int uiEncDataLength, byte[] pucData, IntByReference puiDataLength);

    // =========================================================================
    // MAC Operations
    // =========================================================================
    int SDF_CalculateMAC(Pointer hSessionHandle, Pointer hKeyHandle, int uiAlgID, byte[] pucIV,
            byte[] pucData, int uiDataLength, byte[] pucMAC, IntByReference puiMACLength);
    int SDF_InternalMAC(Pointer hSessionHandle, int uiAlgID, int uiKeyIndex, byte[] pucIV,
            byte[] pucData, int uiDataLength, byte[] pucMAC, IntByReference puiMACLength);

    // =========================================================================
    // HMAC Operations
    // =========================================================================
    int SDF_HMAC(Pointer hSessionHandle, Pointer hKeyHandle, int uiAlgID, byte[] pucInData,
            int uiInDataLength, byte[] pucOutData, IntByReference puiOutDataLength);
    int SDF_HMACBatch(Pointer hSessionHandle, Pointer hKeyHandle, int uiAlgID, Pointer pucDataArray,
            IntByReference uiDataLengthArray, Pointer pucHmacArray, IntByReference puiHmacLenArray, int arrayCount);

    // =========================================================================
    // Hash Operations
    // =========================================================================
    int SDF_HashInit(Pointer hSessionHandle, int uiAlgID, ECCrefPublicKey pucPublicKey,
            byte[] pucID, int uiIDLength);
    int SDF_HashUpdate(Pointer hSessionHandle, byte[] pucData, int uiDataLength);
    int SDF_HashFinal(Pointer hSessionHandle, byte[] pucHash, IntByReference puiHashLength);

    // =========================================================================
    // Key Pair Management (SDFE_*)
    // =========================================================================
    int SDFE_GenerateKeyPair(Pointer hSessionHandle, int uiAlgID, int keyindex, int uiKeyBits);
    int SDFE_ImportKeyPair(Pointer hSessionHandle, int uiAlgID, int uiKeyIndex, byte[] pucPublicKey,
            int pucPublicKeyLen, byte[] pucPrivateKey, int pucPrivateKeyLen);
    int SDFE_DeleteKeyPair(Pointer hSessionHandle, int uiAlgID, int uiKeyIndex);
    int SDFE_GenerateKEK(Pointer hSessionHandle, int uiAlgID, int keyindex, int uiKeyBits);
    int SDFE_DeleteKEK(Pointer hSessionHandle, int uiAlgID, int keyindex);
    int SDFE_ImportKEK(Pointer hSessionHandle, int uiKEKIndex, byte[] pucKey, int uiKeyBits);

    // =========================================================================
    // File Operations
    // =========================================================================
    int SDF_CreateFile(Pointer hSessionHandle, byte[] pucFileName, int uiNameLen, int uiFileSize);
    int SDF_ReadFile(Pointer hSessionHandle, byte[] pucFileName, int uiNameLen, int uiOffset,
            IntByReference puiReadLength, byte[] pucBuffer);
    int SDF_WriteFile(Pointer hSessionHandle, byte[] pucFileName, int uiNameLen, int uiOffset,
            int uiWriteLength, byte[] pucBuffer);
    int SDF_DeleteFile(Pointer hSessionHandle, byte[] pucFileName, int uiNameLen);
}
