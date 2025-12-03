package org.liuzx.jce.provider.asymmetric.sm2;

import org.liuzx.jce.jna.SDFLibrary;
import org.liuzx.jce.jna.structure.ECCrefPrivateKey;
import org.liuzx.jce.jna.structure.ECCrefPublicKey;
import org.liuzx.jce.provider.exception.SDFException;
import org.liuzx.jce.provider.session.SDFSession;
import org.liuzx.jce.provider.session.SDFSessionManager;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class SM2KeyPairGenerator extends KeyPairGeneratorSpi {

    private static final int SGD_SM2_1 = 0x00020100;
    private static final int SM2_KEY_BITS = 256;

    private final SDFSessionManager sessionManager;
    private SM2InternalKeyGenParameterSpec internalKeySpec;

    public SM2KeyPairGenerator() {
        super();
        this.sessionManager = SDFSessionManager.getInstance();
        initialize(SM2_KEY_BITS, null);
    }

    @Override
    public void initialize(int keysize, SecureRandom random) {
        if (keysize != SM2_KEY_BITS) {
            throw new InvalidParameterException("SM2 key size must be " + SM2_KEY_BITS);
        }
        this.internalKeySpec = null;
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        if (params instanceof SM2InternalKeyGenParameterSpec) {
            this.internalKeySpec = (SM2InternalKeyGenParameterSpec) params;
        } else {
            throw new InvalidAlgorithmParameterException("Unsupported AlgorithmParameterSpec: " + params);
        }
    }

    @Override
    public KeyPair generateKeyPair() {
        if (internalKeySpec != null) {
            return loadInternalKeyPair();
        } else {
            return generateExternalKeyPair();
        }
    }

    private KeyPair generateExternalKeyPair() {
        try (SDFSession session = sessionManager.borrowSession()) {
            SDFLibrary sdf = SDFLibrary.getInstance();
            ECCrefPublicKey.ByReference pubKeyRef = new ECCrefPublicKey.ByReference();
            ECCrefPrivateKey.ByReference priKeyRef = new ECCrefPrivateKey.ByReference();
            int rv = sdf.SDF_GenerateKeyPair_ECC(session.getSessionHandle(), SGD_SM2_1, SM2_KEY_BITS, pubKeyRef, priKeyRef);
            if (rv != 0) {
                throw new SDFException("SDF_GenerateKeyPair_ECC (external)", rv);
            }
            return new KeyPair(new SM2PublicKey(pubKeyRef), new SM2PrivateKey(priKeyRef, pubKeyRef));
        }
    }

    private KeyPair loadInternalKeyPair() {
        try (SDFSession session = sessionManager.borrowSession()) {
            SDFLibrary sdf = SDFLibrary.getInstance();
            int keyIndex = internalKeySpec.getKeyIndex();
            
            ECCrefPublicKey.ByReference pubKeyRef = new ECCrefPublicKey.ByReference();
            
            String functionName = "SDF_ExportSignPublicKey_ECC";
            int rv = sdf.SDF_ExportSignPublicKey_ECC(session.getSessionHandle(), keyIndex, pubKeyRef);

            if (rv != 0) {
                throw new SDFException(functionName, rv);
            }

            PublicKey publicKey = new SM2PublicKey(keyIndex, pubKeyRef);
            PrivateKey privateKey = new SM2PrivateKey(keyIndex, pubKeyRef);
            
            return new KeyPair(publicKey, privateKey);
        }
    }
}
