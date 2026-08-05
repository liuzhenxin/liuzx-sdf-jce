package org.liuzx.jce.provider.mac;

import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import org.liuzx.jce.jna.SDFLibrary;
import org.liuzx.jce.provider.exception.SDFException;
import org.liuzx.jce.provider.session.SDFSession;
import org.liuzx.jce.provider.session.SDFSessionManager;
import org.liuzx.jce.provider.symmetric.SDFSM4InternalKey;

import javax.crypto.MacSpi;
import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

/**
 * SDF hardware-backed MAC (Message Authentication Code).
 * Supports SM4-CBC-MAC, SM1-MAC, SSF33-MAC.
 */
public class SDFMacSpi extends MacSpi {

    private static final int SGD_SMS4_MAC = 0x00000410;
    private static final int SGD_SM1_MAC  = 0x00000110;
    private static final int SGD_SSF33_MAC = 0x00000210;

    private final SDFSessionManager sessionManager;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private final int algId;
    private final int macLength;

    private byte[] keyBytes;
    private SDFSM4InternalKey internalKeyInfo;
    private byte[] iv;

    protected SDFMacSpi(int algId, int macLength) {
        this.sessionManager = SDFSessionManager.getInstance();
        this.algId = algId;
        this.macLength = macLength;
    }

    @Override
    protected int engineGetMacLength() {
        return macLength;
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params) throws InvalidKeyException,
            InvalidAlgorithmParameterException {
        buffer.reset();
        this.keyBytes = null;
        this.internalKeyInfo = null;
        this.iv = null;

        if (key instanceof SDFSM4InternalKey) {
            this.internalKeyInfo = (SDFSM4InternalKey) key;
        } else if (key instanceof SecretKey) {
            this.keyBytes = key.getEncoded();
            if (keyBytes == null || keyBytes.length == 0) {
                throw new InvalidKeyException("Key encoding is empty.");
            }
        } else {
            throw new InvalidKeyException("Key must be a SecretKey or SDFSM4InternalKey.");
        }
    }

    @Override
    protected void engineUpdate(byte input) {
        buffer.write(input);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        buffer.write(input, offset, len);
    }

    @Override
    protected byte[] engineDoFinal() {
        byte[] data = buffer.toByteArray();
        buffer.reset();
        try (SDFSession session = sessionManager.borrowSession()) {
            SDFLibrary sdf = SDFLibrary.getInstance();
            Pointer hKeyHandle = null;
            try {
                if (internalKeyInfo != null) {
                    Pointer[] ph = new Pointer[1];
                    byte[] ek = internalKeyInfo.getEncryptedKey();
                    int rv;
                    if (isEmpty(ek)) {
                        rv = sdf.SDF_ImportKEK(session.getSessionHandle(), internalKeyInfo.getKeyIndex(),
                                internalKeyInfo.getKeyLengthBytes(), ph);
                    } else {
                        rv = sdf.SDF_ImportKeyWithKEK(session.getSessionHandle(), 0x00000401,
                                internalKeyInfo.getKeyIndex(), ek, internalKeyInfo.getKeyLengthBytes(), ph);
                    }
                    if (rv != 0) throw new SDFException("ImportKey for MAC", rv);
                    hKeyHandle = ph[0];
                } else {
                    Pointer[] ph = new Pointer[1];
                    int rv = sdf.SDF_ImportKey(session.getSessionHandle(), keyBytes, keyBytes.length, ph);
                    if (rv != 0) throw new SDFException("SDF_ImportKey", rv);
                    hKeyHandle = ph[0];
                }

                byte[] mac = new byte[macLength];
                IntByReference macLen = new IntByReference(mac.length);
                int rv = sdf.SDF_CalculateMAC(session.getSessionHandle(), hKeyHandle, algId, iv, data,
                        data.length, mac, macLen);
                if (rv != 0) throw new SDFException("SDF_CalculateMAC", rv);

                byte[] result = new byte[macLen.getValue()];
                System.arraycopy(mac, 0, result, 0, result.length);
                return result;
            } finally {
                if (hKeyHandle != null) {
                    sdf.SDF_DestroyKey(session.getSessionHandle(), hKeyHandle);
                }
            }
        }
    }

    @Override
    protected void engineReset() {
        buffer.reset();
    }

    private static boolean isEmpty(byte[] arr) {
        for (byte b : arr) if (b != 0) return false;
        return true;
    }

    // --- Concrete algorithm classes ---
    public static class SM4 extends SDFMacSpi {
        public SM4() { super(SGD_SMS4_MAC, 16); }
    }
}
