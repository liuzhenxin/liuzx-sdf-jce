package org.liuzx.jce.provider.asymmetric.dsa;

import org.liuzx.jce.jna.SDFLibrary;
import org.liuzx.jce.jna.structure.DSASignature;
import org.liuzx.jce.jna.structure.DSArefPrivateKey;
import org.liuzx.jce.jna.structure.DSArefPublicKey;
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

public class DSASignatureSpi extends SignatureSpi {

    private static final LiuzxProviderLogger logger = LiuzxProviderLogger.getLogger(DSASignatureSpi.class);
    private static final int SGD_DSA_1 = 0x00060200;
    private static final int KEY_BYTES = 384; // DSAref_MAX_LEN = (3072+7)/8

    private final SDFSessionManager sessionManager = SDFSessionManager.getInstance();
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private DSAPrivateKey privateKey;
    private DSAPublicKey publicKey;

    @Override protected void engineInitSign(PrivateKey pk) throws InvalidKeyException {
        if (!(pk instanceof DSAPrivateKey)) throw new InvalidKeyException("Requires DSAPrivateKey");
        this.privateKey = (DSAPrivateKey) pk; this.publicKey = null; buffer.reset();
    }
    @Override protected void engineInitVerify(PublicKey pk) throws InvalidKeyException {
        if (!(pk instanceof DSAPublicKey)) throw new InvalidKeyException("Requires DSAPublicKey");
        this.publicKey = (DSAPublicKey) pk; this.privateKey = null; buffer.reset();
    }
    @Override protected void engineUpdate(byte b) { buffer.write(b); }
    @Override protected void engineUpdate(byte[] b, int o, int l) { buffer.write(b, o, l); }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (privateKey == null) throw new SignatureException("Not initialized for signing.");
        byte[] data = buffer.toByteArray(); buffer.reset();
        try (SDFSession s = sessionManager.borrowSession()) {
            DSASignature.ByReference sig = new DSASignature.ByReference();
            SDFLibrary sdf = SDFLibrary.getInstance();
            int rv = sdf.SDF_ExternalSign_DSA(s.getSessionHandle(), toByReference(privateKey.getKey()),
                    data, data.length, sig);
            if (rv != 0) throw new SDFException("SDF_ExternalSign_DSA", rv);
            // For DSA, q is at most 32 bytes (for 256-bit q in FIPS 186-4).
            // The SDF struct has 384-byte fields; we use only the significant portion.
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
            DSASignature.ByReference sig = new DSASignature.ByReference();
            System.arraycopy(raw, 0, sig.r, 0, KEY_BYTES);
            System.arraycopy(raw, KEY_BYTES, sig.s, 0, KEY_BYTES);
            int rv = SDFLibrary.getInstance().SDF_ExternalVerify_DSA(s.getSessionHandle(),
                    toByReference(publicKey.getKey()), data, data.length, sig);
            return rv == 0;
        } catch (SDFException e) {
            logger.error("SDF error during DSA verification", e);
            throw new SignatureException("SDF error during DSA verification", e);
        } catch (Exception e) {
            logger.error("Unexpected error during DSA verification", e);
            throw new SignatureException("Unexpected error during DSA verification", e);
        }
    }
    @Override protected void engineSetParameter(String p, Object v) {}
    @Override protected Object engineGetParameter(String p) { return null; }

    private static DSArefPrivateKey.ByReference toByReference(DSArefPrivateKey k) {
        DSArefPrivateKey.ByReference ref = new DSArefPrivateKey.ByReference();
        ref.bits = k.bits;
        System.arraycopy(k.x, 0, ref.x, 0, k.x.length);
        System.arraycopy(k.p, 0, ref.p, 0, k.p.length);
        System.arraycopy(k.q, 0, ref.q, 0, k.q.length);
        System.arraycopy(k.g, 0, ref.g, 0, k.g.length);
        return ref;
    }

    private static DSArefPublicKey.ByReference toByReference(DSArefPublicKey k) {
        DSArefPublicKey.ByReference ref = new DSArefPublicKey.ByReference();
        ref.bits = k.bits;
        System.arraycopy(k.y, 0, ref.y, 0, k.y.length);
        System.arraycopy(k.p, 0, ref.p, 0, k.p.length);
        System.arraycopy(k.q, 0, ref.q, 0, k.q.length);
        System.arraycopy(k.g, 0, ref.g, 0, k.g.length);
        return ref;
    }
}
