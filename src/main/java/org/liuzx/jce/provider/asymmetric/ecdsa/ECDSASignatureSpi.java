package org.liuzx.jce.provider.asymmetric.ecdsa;

import org.liuzx.jce.jna.SDFLibrary;
import org.liuzx.jce.jna.structure.ECCrefPrivateKey_ECDSA;
import org.liuzx.jce.jna.structure.ECCrefPublicKey_ECDSA;
import org.liuzx.jce.jna.structure.ECCSignature_ECDSA;
import org.liuzx.jce.provider.exception.SDFException;
import org.liuzx.jce.provider.log.LiuzxProviderLogger;
import org.liuzx.jce.provider.session.SDFSession;
import org.liuzx.jce.provider.session.SDFSessionManager;
import org.liuzx.jce.provider.util.ASN1Util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;

public class ECDSASignatureSpi extends SignatureSpi {

    private static final LiuzxProviderLogger logger = LiuzxProviderLogger.getLogger(ECDSASignatureSpi.class);
    private static final int SGD_ECDSA_1 = 0x00040200;
    private static final int KEY_BYTES = 66; // (521+7)/8

    private final SDFSessionManager sessionManager;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private ECDSAPrivateKey privateKey;
    private ECDSAPublicKey publicKey;

    public ECDSASignatureSpi() {
        this.sessionManager = SDFSessionManager.getInstance();
    }

    @Override protected void engineInitSign(PrivateKey pk) throws InvalidKeyException {
        if (!(pk instanceof ECDSAPrivateKey)) throw new InvalidKeyException("Requires ECDSAPrivateKey");
        this.privateKey = (ECDSAPrivateKey) pk; this.publicKey = null; buffer.reset();
    }
    @Override protected void engineInitVerify(PublicKey pk) throws InvalidKeyException {
        if (!(pk instanceof ECDSAPublicKey)) throw new InvalidKeyException("Requires ECDSAPublicKey");
        this.publicKey = (ECDSAPublicKey) pk; this.privateKey = null; buffer.reset();
    }
    @Override protected void engineUpdate(byte b) { buffer.write(b); }
    @Override protected void engineUpdate(byte[] b, int o, int l) { buffer.write(b, o, l); }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (privateKey == null) throw new SignatureException("Not initialized for signing.");
        byte[] data = buffer.toByteArray(); buffer.reset();
        try (SDFSession s = sessionManager.borrowSession()) {
            SDFLibrary sdf = SDFLibrary.getInstance();
            ECCSignature_ECDSA.ByReference sig = new ECCSignature_ECDSA.ByReference();
            int rv = sdf.SDF_ExternalSign_ECC_ECDSA(s.getSessionHandle(), SGD_ECDSA_1,
                    toByReference(privateKey.getKey()), data, data.length, sig);
            s.checkResult(rv); if (rv != 0) throw new SDFException("SDF_ExternalSign_ECC_ECDSA", rv);
            return ASN1Util.toDERSignature(sig.r, sig.s);
        } catch (IOException e) {
            throw new SignatureException("DER encoding failed", e);
        }
    }

    @Override
    protected boolean engineVerify(byte[] derSig) throws SignatureException {
        if (publicKey == null) throw new SignatureException("Not initialized for verification.");
        byte[] data = buffer.toByteArray(); buffer.reset();
        try (SDFSession s = sessionManager.borrowSession()) {
            SDFLibrary sdf = SDFLibrary.getInstance();
            byte[] raw = ASN1Util.fromDERSignature(derSig, KEY_BYTES, KEY_BYTES);
            if (raw == null) return false;
            ECCSignature_ECDSA.ByReference sig = new ECCSignature_ECDSA.ByReference();
            System.arraycopy(raw, 0, sig.r, 0, KEY_BYTES);
            System.arraycopy(raw, KEY_BYTES, sig.s, 0, KEY_BYTES);
            int rv = sdf.SDF_ExternalVerify_ECC_ECDSA(s.getSessionHandle(), SGD_ECDSA_1,
                    toByReference(publicKey.getKey()), data, data.length, sig);
            return rv == 0;
        } catch (SDFException e) {
            logger.error("SDF error during ECDSA verification", e);
            throw new SignatureException("SDF error during ECDSA verification", e);
        } catch (Exception e) {
            logger.error("Unexpected error during ECDSA verification", e);
            throw new SignatureException("Unexpected error during ECDSA verification", e);
        }
    }

    @Override protected void engineSetParameter(String p, Object v) throws InvalidParameterException {}
    @Override protected Object engineGetParameter(String p) throws InvalidParameterException { return null; }

    private static ECCrefPrivateKey_ECDSA.ByReference toByReference(ECCrefPrivateKey_ECDSA k) {
        ECCrefPrivateKey_ECDSA.ByReference ref = new ECCrefPrivateKey_ECDSA.ByReference();
        ref.bits = k.bits;
        System.arraycopy(k.K, 0, ref.K, 0, k.K.length);
        return ref;
    }

    private static ECCrefPublicKey_ECDSA.ByReference toByReference(ECCrefPublicKey_ECDSA k) {
        ECCrefPublicKey_ECDSA.ByReference ref = new ECCrefPublicKey_ECDSA.ByReference();
        ref.bits = k.bits;
        System.arraycopy(k.x, 0, ref.x, 0, k.x.length);
        System.arraycopy(k.y, 0, ref.y, 0, k.y.length);
        return ref;
    }
}
