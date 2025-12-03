package org.liuzx.jce.jna;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import org.liuzx.jce.jna.structure.ECCCipher;
import org.liuzx.jce.jna.structure.ECCrefPrivateKey;
import org.liuzx.jce.jna.structure.ECCrefPublicKey;
import org.liuzx.jce.jna.structure.ECCSignature;
import org.liuzx.jce.provider.SDFConfig;

public interface SDFLibrary extends Library {

    static SDFLibrary getInstance() {
        return LazyHolder.INSTANCE;
    }

    class LazyHolder {
        static final SDFLibrary INSTANCE = Native.load(SDFConfig.getInstance().getDefaultLibraryPath(), SDFLibrary.class);
    }

    // ... (other methods)

    // --- Asymmetric ECC Operations ---
    int SDF_ExternalSign_ECC(Pointer hSessionHandle, int uiAlgID, ECCrefPrivateKey pucPrivateKey, byte[] pucData, int uiDataLength, ECCSignature.ByReference pucSignature);
    int SDF_ExternalVerify_ECC(Pointer hSessionHandle, int uiAlgID, ECCrefPublicKey pucPublicKey, byte[] pucData, int uiDataLength, ECCSignature pucSignature);
    int SDF_InternalSign_ECC(Pointer hSessionHandle, int uiISKIndex, byte[] pucData, int uiDataLength, ECCSignature.ByReference pucSignature);
    int SDF_InternalVerify_ECC(Pointer hSessionHandle, int uiISKIndex, byte[] pucData, int uiDataLength, ECCSignature pucSignature);
    
    int SDF_ExternalEncrypt_ECC(Pointer hSessionHandle, int uiAlgID, ECCrefPublicKey pucPublicKey, byte[] pucData, int uiDataLength, ECCCipher.ByReference pucEncData);
    int SDF_ExternalDecrypt_ECC(Pointer hSessionHandle, int uiAlgID, ECCrefPrivateKey pucPrivateKey, ECCCipher pucEncData, byte[] pucData, IntByReference puiDataLength);
    int SDF_InternalDecrypt_ECC(Pointer hSessionHandle, int uiKeyIndex, int uiAlgID, ECCCipher pucEncData, byte[] pucData, IntByReference puiDataLength);

    // ... (other methods)
    int SDF_HashInit(Pointer hSessionHandle, int uiAlgID, ECCrefPublicKey pucPublicKey, byte[] pucID, int uiIDLength);
    int SDF_HashUpdate(Pointer hSessionHandle, byte[] pucData, int uiDataLength);
    int SDF_HashFinal(Pointer hSessionHandle, byte[] pucHash, IntByReference puiHashLength);
    int SDF_OpenDevice(Pointer[] phDeviceHandle);
    int SDF_CloseDevice(Pointer hDeviceHandle);
    int SDF_OpenSession(Pointer hDeviceHandle, Pointer[] phSessionHandle);
    int SDF_CloseSession(Pointer hSessionHandle);
    int SDF_GetPrivateKeyAccessRight(Pointer hSessionHandle, int uiKeyIndex, byte[] pucPassword, int uiPwdLength);
    int SDF_ReleasePrivateKeyAccessRight(Pointer hSessionHandle, int uiKeyIndex);
    int SDF_ExportSignPublicKey_ECC(Pointer hSessionHandle, int uiKeyIndex, ECCrefPublicKey.ByReference pucPublicKey);
    int SDF_GenerateKeyPair_ECC(Pointer hSessionHandle, int uiAlgId, int uiKeyBits, ECCrefPublicKey.ByReference pucPublicKey, ECCrefPrivateKey.ByReference pucPrivateKey);
    int SDF_GenerateRandom(Pointer hSessionHandle, int uiLength, byte[] pucRandom);
    int SDF_ImportKey(Pointer hSessionHandle, byte[] pucKey, int uiKeyLength, Pointer[] phKeyHandle);
    int SDF_DestroyKey(Pointer hSessionHandle, Pointer hKeyHandle);
    int SDF_Encrypt(Pointer hSessionHandle, Pointer hKeyHandle, int uiAlgID, byte[] pucIV, byte[] pucData, int uiDataLength, byte[] pucEncData, IntByReference puiEncDataLength);
    int SDF_Decrypt(Pointer hSessionHandle, Pointer hKeyHandle, int uiAlgID, byte[] pucIV, byte[] pucEncData, int uiEncDataLength, byte[] pucData, IntByReference puiDataLength);
}
