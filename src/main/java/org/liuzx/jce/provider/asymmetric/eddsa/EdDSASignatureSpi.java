package org.liuzx.jce.provider.asymmetric.eddsa;

import org.liuzx.jce.jna.SDFLibrary;
import org.liuzx.jce.jna.structure.ECCrefPrivateKey_EDDSA;
import org.liuzx.jce.jna.structure.ECCrefPublicKey_EDDSA;
import org.liuzx.jce.jna.structure.ECCSignature_EDDSA;
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

public class EdDSASignatureSpi extends SignatureSpi {

    private static final LiuzxProviderLogger logger = LiuzxProviderLogger.getLogger(EdDSASignatureSpi.class);
    private static final int SGD_EDDSA_1 = 0x00050200;
    private static final int KEY_BYTES = 32;

    private final SDFSessionManager sessionManager = SDFSessionManager.getInstance();
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private EdDSAPrivateKey privateKey;
    private EdDSAPublicKey publicKey;

    @Override protected void engineInitSign(PrivateKey pk) throws InvalidKeyException {
        if (!(pk instanceof EdDSAPrivateKey)) throw new InvalidKeyException("Requires EdDSAPrivateKey");
        this.privateKey = (EdDSAPrivateKey) pk; this.publicKey = null; buffer.reset();
    }
    @Override protected void engineInitVerify(PublicKey pk) throws InvalidKeyException {
        if (!(pk instanceof EdDSAPublicKey)) throw new InvalidKeyException("Requires EdDSAPublicKey");
        this.publicKey = (EdDSAPublicKey) pk; this.privateKey = null; buffer.reset();
    }
    @Override protected void engineUpdate(byte b) { buffer.write(b); }
    @Override protected void engineUpdate(byte[] b, int o, int l) { buffer.write(b, o, l); }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (privateKey == null) throw new SignatureException("Not initialized for signing.");
        byte[] data = buffer.toByteArray(); buffer.reset();
        try (SDFSession s = sessionManager.borrowSession()) {
            ECCSignature_EDDSA.ByReference sig = new ECCSignature_EDDSA.ByReference();
            SDFLibrary sdf = SDFLibrary.getInstance();
            int rv = sdf.SDF_ExternalSign_ECC_EDDSA(s.getSessionHandle(), SGD_EDDSA_1,
                    toByReference(privateKey.getKey()), data, data.length, sig);
            if (rv != 0) throw new SDFException("SDF_ExternalSign_ECC_EDDSA", rv);
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
            byte[] raw = ASN1Util.fromDERSignature(derSig, KEY_BYTES, KEY_BYTES);
            if (raw == null) return false;
            ECCSignature_EDDSA.ByReference sig = new ECCSignature_EDDSA.ByReference();
            System.arraycopy(raw, 0, sig.r, 0, KEY_BYTES);
            System.arraycopy(raw, KEY_BYTES, sig.s, 0, KEY_BYTES);
            int rv = SDFLibrary.getInstance().SDF_ExternalVerify_ECC_EDDSA(s.getSessionHandle(),
                    SGD_EDDSA_1, toByReference(publicKey.getKey()), data, data.length, sig);
            return rv == 0;
        } catch (SDFException e) {
            logger.error("SDF error during EdDSA verification", e);
            throw new SignatureException("SDF error during EdDSA verification", e);
        } catch (Exception e) {
            logger.error("Unexpected error during EdDSA verification", e);
            throw new SignatureException("Unexpected error during EdDSA verification", e);
        }
    }
    @Override protected void engineSetParameter(String p, Object v) {}
    @Override protected Object engineGetParameter(String p) { return null; }

    private static ECCrefPrivateKey_EDDSA.ByReference toByReference(ECCrefPrivateKey_EDDSA k) {
        ECCrefPrivateKey_EDDSA.ByReference ref = new ECCrefPrivateKey_EDDSA.ByReference();
        ref.bits = k.bits;
        System.arraycopy(k.pri, 0, ref.pri, 0, k.pri.length);
        return ref;
    }

    private static ECCrefPublicKey_EDDSA.ByReference toByReference(ECCrefPublicKey_EDDSA k) {
        ECCrefPublicKey_EDDSA.ByReference ref = new ECCrefPublicKey_EDDSA.ByReference();
        ref.bits = k.bits;
        System.arraycopy(k.pub, 0, ref.pub, 0, k.pub.length);
        return ref;
    }
}
