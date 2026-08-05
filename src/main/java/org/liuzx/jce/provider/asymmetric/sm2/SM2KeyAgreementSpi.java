package org.liuzx.jce.provider.asymmetric.sm2;

import com.sun.jna.Pointer;
import org.liuzx.jce.jna.SDFLibrary;
import org.liuzx.jce.jna.structure.ECCrefPublicKey;
import org.liuzx.jce.provider.exception.SDFException;
import org.liuzx.jce.provider.log.LiuzxProviderLogger;
import org.liuzx.jce.provider.session.SDFSession;
import org.liuzx.jce.provider.session.SDFSessionManager;

import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * SM2 Key Agreement (ECDH) per GM/T 0003.
 * <p>
 * Note: The shared secret produced by SDF hardware is a key handle, not raw bytes.
 * The key material stays inside the device and is used via SDF_Encrypt/SDF_Decrypt.
 * {@link #engineGenerateSecret()} returns a token that identifies the agreement result;
 * for raw bytes, use the SDF key handle directly with symmetric operations.
 */
public class SM2KeyAgreementSpi extends KeyAgreementSpi {

    private static final LiuzxProviderLogger logger = LiuzxProviderLogger.getLogger(SM2KeyAgreementSpi.class);
    private static final int SGD_SM2_2 = 0x00020400;
    private static final int KEY_SIZE = 16;

    private final SDFSessionManager sessionManager;

    private SM2PrivateKey sm2PrivateKey;
    private SDFSession agreementSession; // session that owns the key handle
    private Pointer hKeyHandle;          // SDF key handle from agreement

    public SM2KeyAgreementSpi() {
        this.sessionManager = SDFSessionManager.getInstance();
    }

    @Override
    protected void engineInit(Key key, SecureRandom random) throws InvalidKeyException {
        if (!(key instanceof SM2PrivateKey)) {
            throw new InvalidKeyException("Key must be an SM2PrivateKey.");
        }
        SM2PrivateKey pkey = (SM2PrivateKey) key;
        if (!pkey.isInternalKey()) {
            throw new InvalidKeyException("Only internal SM2 keys are supported for key agreement.");
        }
        destroyHandle();
        this.sm2PrivateKey = pkey;
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        engineInit(key, random);
    }

    @Override
    protected Key engineDoPhase(Key key, boolean lastPhase) throws InvalidKeyException, IllegalStateException {
        if (sm2PrivateKey == null) {
            throw new IllegalStateException("KeyAgreement not initialized.");
        }
        if (!(key instanceof SM2PublicKey)) {
            throw new InvalidKeyException("Peer key must be an SM2PublicKey.");
        }
        SM2PublicKey peerKey = (SM2PublicKey) key;

        // Destroy previous handle before creating a new one
        destroyHandle();

        SDFSession session = sessionManager.borrowSession();
        try {
            SDFLibrary sdf = SDFLibrary.getInstance();
            int keyIndex = sm2PrivateKey.getKeyIndex();
            byte[] userId = "1234567812345678".getBytes(StandardCharsets.UTF_8);

            // Copy peer public key into ByReference struct
            ECCrefPublicKey peerPub = peerKey.getEccPublicKey();
            ECCrefPublicKey.ByReference peerPubRef = new ECCrefPublicKey.ByReference();
            peerPubRef.bits = peerPub.bits;
            System.arraycopy(peerPub.x, 0, peerPubRef.x, 0, peerPub.x.length);
            System.arraycopy(peerPub.y, 0, peerPubRef.y, 0, peerPub.y.length);

            // Internal ECC agreement: compute shared key directly (single-phase ECDH)
            ECCrefPublicKey.ByReference tmpPubRef = new ECCrefPublicKey.ByReference();
            Pointer[] phKey = new Pointer[1];
            int rv = sdf.SDF_GenerateAgreementDataAndKeyWithECC(session.getSessionHandle(),
                    keyIndex, KEY_SIZE * 8, userId, userId.length, userId, userId.length,
                    null, tmpPubRef, peerPubRef, peerPubRef, phKey);
            if (rv != 0) {
                // 不要在这里归还会话 — 交给下方 catch 统一归还一次，避免双归还会话池
                throw new SDFException("SDF_GenerateAgreementDataAndKeyWithECC", rv);
            }

            // Take ownership of the session and key handle (released in destroyHandle)
            this.agreementSession = session;
            this.hKeyHandle = phKey[0];

            // Return a token — the actual key material stays in hardware
            return new SecretKeySpec(new byte[KEY_SIZE], "SM2KeyAgreement");
        } catch (Exception e) {
            session.close();
            if (e instanceof InvalidKeyException) throw (InvalidKeyException) e;
            if (e instanceof SDFException) throw (SDFException) e;
            throw new InvalidKeyException("SM2 key agreement failed: " + e.getMessage(), e);
        }
    }

    @Override
    protected byte[] engineGenerateSecret() throws IllegalStateException {
        // Hardware-bound key: raw bytes are not available.
        // The key handle (hKeyHandle) must be used directly with SDF_Encrypt/SDF_Decrypt.
        throw new IllegalStateException(
                "Shared secret is hardware-bound (key handle). Use the key handle with symmetric operations.");
    }

    @Override
    protected int engineGenerateSecret(byte[] sharedSecret, int offset)
            throws IllegalStateException, ShortBufferException {
        byte[] secret = engineGenerateSecret();
        if (sharedSecret.length - offset < secret.length) {
            throw new ShortBufferException("Buffer too short");
        }
        System.arraycopy(secret, 0, sharedSecret, offset, secret.length);
        return secret.length;
    }

    @Override
    protected SecretKey engineGenerateSecret(String algorithm) throws IllegalStateException {
        byte[] secret = engineGenerateSecret();
        return new SecretKeySpec(secret, algorithm);
    }

    /**
     * Release the SDF key handle and return the owning session to the pool.
     * Idempotent — safe to call multiple times.
     */
    private void destroyHandle() {
        if (hKeyHandle != null && agreementSession != null) {
            try {
                SDFLibrary.getInstance().SDF_DestroyKey(agreementSession.getSessionHandle(), hKeyHandle);
            } catch (Exception e) {
                logger.warn("Failed to destroy SM2 agreement key handle: {}", e.getMessage());
            }
            hKeyHandle = null;
        }
        if (agreementSession != null) {
            agreementSession.close();
            agreementSession = null;
        }
    }

    /**
     * Expose the raw SDF key handle for direct symmetric operations.
     * Caller must NOT destroy this handle — it is owned by this SPI instance.
     */
    Pointer getKeyHandle() {
        return hKeyHandle;
    }

    SDFSession getSession() {
        return agreementSession;
    }

    /**
     * Last-resort cleanup: release hardware resources if the caller forgets
     * to call {@link #engineInit(Key, SecureRandom)} or lets the instance be GC'd.
     */
    @Override
    @SuppressWarnings("deprecation")
    protected void finalize() {
        destroyHandle();
    }
}
