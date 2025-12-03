package org.liuzx.jce.provider.asymmetric.sm2;

import com.sun.jna.ptr.IntByReference;
import org.liuzx.jce.jna.SDFLibrary;
import org.liuzx.jce.jna.structure.ECCSignature;
import org.liuzx.jce.jna.structure.ECCrefPublicKey;
import org.liuzx.jce.provider.exception.SDFException;
import org.liuzx.jce.provider.session.SDFSession;
import org.liuzx.jce.provider.session.SDFSessionManager;
import org.liuzx.jce.provider.util.ASN1Util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;

public class SM2SignatureSpi extends SignatureSpi {

    private static final byte[] DEFAULT_USER_ID = "1234567812345678".getBytes(StandardCharsets.UTF_8);
    private static final int SGD_SM3 = 0x00000001;
    private static final int SGD_SM2_1 = 0x00020200; // SM2 signature algorithm ID

    private final SDFSessionManager sessionManager;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    private SM2PrivateKey sm2PrivateKey;
    private SM2PublicKey sm2PublicKey;

    public SM2SignatureSpi() {
        this.sessionManager = SDFSessionManager.getInstance();
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof SM2PublicKey)) {
            throw new InvalidKeyException("Key must be an SM2PublicKey.");
        }
        this.sm2PublicKey = (SM2PublicKey) publicKey;
        reset();
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof SM2PrivateKey)) {
            throw new InvalidKeyException("Key must be an SM2PrivateKey.");
        }
        this.sm2PrivateKey = (SM2PrivateKey) privateKey;
        reset();
    }

    @Override
    protected void engineUpdate(byte b) {
        buffer.write(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) {
        buffer.write(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (sm2PrivateKey == null) {
            throw new SignatureException("Signature not initialized for signing.");
        }
        try (SDFSession session = sessionManager.borrowSession()) {
            byte[] sm3Digest = computeSM3Digest(session, sm2PrivateKey.getEccPublicKey(), buffer.toByteArray());

            ECCSignature.ByReference eccSignature = new ECCSignature.ByReference();
            int rv;

            if (sm2PrivateKey.isInternalKey()) {
                char[] password = sm2PrivateKey.getPassword();
                if (password != null && password.length > 0) {
                    byte[] pwdBytes = new String(password).getBytes(StandardCharsets.UTF_8);
                    rv = SDFLibrary.getInstance().SDF_GetPrivateKeyAccessRight(session.getSessionHandle(), sm2PrivateKey.getKeyIndex(), pwdBytes, pwdBytes.length);
                    if (rv != 0) {
                        throw new SDFException("SDF_GetPrivateKeyAccessRight", rv);
                    }
                }
                try {
                    rv = SDFLibrary.getInstance().SDF_InternalSign_ECC(session.getSessionHandle(), sm2PrivateKey.getKeyIndex(), sm3Digest, sm3Digest.length, eccSignature);
                    if (rv != 0) {
                        throw new SDFException("SDF_InternalSign_ECC", rv);
                    }
                } finally {
                    if (password != null && password.length > 0) {
                        SDFLibrary.getInstance().SDF_ReleasePrivateKeyAccessRight(session.getSessionHandle(), sm2PrivateKey.getKeyIndex());
                    }
                }
            } else {
                // Corrected: Pass the SM2 signature algorithm ID
                rv = SDFLibrary.getInstance().SDF_ExternalSign_ECC(session.getSessionHandle(), SGD_SM2_1, sm2PrivateKey.getEccPrivateKey(), sm3Digest, sm3Digest.length, eccSignature);
                if (rv != 0) {
                    throw new SDFException("SDF_ExternalSign_ECC", rv);
                }
            }
            return ASN1Util.toASN1Signature(eccSignature);
        } catch (IOException e) {
            throw new SignatureException("ASN.1 encoding failed.", e);
        } catch (Exception e) {
            if (e instanceof SignatureException) throw (SignatureException) e;
            if (e instanceof SDFException) throw (SDFException) e;
            throw new SignatureException("Error during signing process.", e);
        } finally {
            reset();
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (sm2PublicKey == null) {
            throw new SignatureException("Signature not initialized for verification.");
        }
        try (SDFSession session = sessionManager.borrowSession()) {
            byte[] sm3Digest = computeSM3Digest(session, sm2PublicKey.getEccPublicKey(), buffer.toByteArray());
            
            ECCSignature signature = ASN1Util.fromASN1Signature(sigBytes);
            int rv;

            if (sm2PublicKey.isInternalKey()) {
                rv = SDFLibrary.getInstance().SDF_InternalVerify_ECC(session.getSessionHandle(), sm2PublicKey.getKeyIndex(), sm3Digest, sm3Digest.length, signature);
            } else {
                // Corrected: Pass the SM2 signature algorithm ID
                rv = SDFLibrary.getInstance().SDF_ExternalVerify_ECC(session.getSessionHandle(), SGD_SM2_1, sm2PublicKey.getEccPublicKey(), sm3Digest, sm3Digest.length, signature);
            }
            return rv == 0;
        } catch (Exception e) {
            if (e instanceof SDFException) {
                throw (SDFException) e;
            }
            return false;
        } finally {
            reset();
        }
    }

    private byte[] computeSM3Digest(SDFSession session, ECCrefPublicKey publicKey, byte[] message) {
        SDFLibrary sdf = SDFLibrary.getInstance();
        
        int rv = sdf.SDF_HashInit(session.getSessionHandle(), SGD_SM3, publicKey, DEFAULT_USER_ID, DEFAULT_USER_ID.length);
        if (rv != 0) {
            throw new SDFException("SDF_HashInit", rv);
        }

        rv = sdf.SDF_HashUpdate(session.getSessionHandle(), message, message.length);
        if (rv != 0) {
            throw new SDFException("SDF_HashUpdate", rv);
        }

        byte[] digest = new byte[32];
        IntByReference digestLen = new IntByReference(32);
        rv = sdf.SDF_HashFinal(session.getSessionHandle(), digest, digestLen);
        if (rv != 0) {
            throw new SDFException("SDF_HashFinal", rv);
        }
        return digest;
    }

    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new InvalidParameterException("This signature engine does not support parameters.");
    }

    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new InvalidParameterException("This signature engine does not support parameters.");
    }

    private void reset() {
        buffer.reset();
    }
}
