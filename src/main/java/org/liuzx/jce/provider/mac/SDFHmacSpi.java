package org.liuzx.jce.provider.mac;

import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import org.liuzx.jce.jna.SDFLibrary;
import org.liuzx.jce.provider.exception.SDFException;
import org.liuzx.jce.provider.session.SDFSession;
import org.liuzx.jce.provider.session.SDFSessionManager;

import javax.crypto.MacSpi;
import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

/**
 * SDF hardware-backed HMAC using SM3, SHA-1, SHA-256.
 */
public class SDFHmacSpi extends MacSpi {

    private static final int SGD_SM3    = 0x00000001;
    private static final int SGD_SHA1   = 0x00000002;
    private static final int SGD_SHA256 = 0x00000004;
    private static final int SGD_SHA512 = 0x00000008;

    private final SDFSessionManager sessionManager;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private final int algId;
    private final int macLength;

    private byte[] keyBytes;

    protected SDFHmacSpi(int algId, int macLength) {
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
        if (!(key instanceof SecretKey)) {
            throw new InvalidKeyException("Key must be a SecretKey.");
        }
        this.keyBytes = key.getEncoded();
        if (keyBytes == null || keyBytes.length == 0) {
            throw new InvalidKeyException("Key encoding is empty.");
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
            Pointer[] phKey = new Pointer[1];
            int rv = sdf.SDF_ImportKey(session.getSessionHandle(), keyBytes, keyBytes.length, phKey);
            if (rv != 0) throw new SDFException("SDF_ImportKey", rv);
            try {
                byte[] mac = new byte[macLength];
                IntByReference macLen = new IntByReference(mac.length);
                rv = sdf.SDF_HMAC(session.getSessionHandle(), phKey[0], algId, data, data.length, mac, macLen);
                if (rv != 0) throw new SDFException("SDF_HMAC", rv);
                byte[] result = new byte[macLen.getValue()];
                System.arraycopy(mac, 0, result, 0, result.length);
                return result;
            } finally {
                sdf.SDF_DestroyKey(session.getSessionHandle(), phKey[0]);
            }
        }
    }

    @Override
    protected void engineReset() {
        buffer.reset();
    }

    public static class HmacSM3 extends SDFHmacSpi {
        public HmacSM3() { super(SGD_SM3, 32); }
    }
    public static class HmacSHA1 extends SDFHmacSpi {
        public HmacSHA1() { super(SGD_SHA1, 20); }
    }
    public static class HmacSHA256 extends SDFHmacSpi {
        public HmacSHA256() { super(SGD_SHA256, 32); }
    }
    public static class HmacSHA512 extends SDFHmacSpi {
        public HmacSHA512() { super(SGD_SHA512, 64); }
    }
}
