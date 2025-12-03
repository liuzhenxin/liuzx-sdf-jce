package org.liuzx.jce.provider.digest;

import com.sun.jna.ptr.IntByReference;
import org.liuzx.jce.jna.SDFLibrary;
import org.liuzx.jce.jna.structure.ECCrefPublicKey;
import org.liuzx.jce.provider.exception.SDFException;
import org.liuzx.jce.provider.session.SDFSession;
import org.liuzx.jce.provider.session.SDFSessionManager;

import java.security.MessageDigestSpi;

public class SM3Digest extends MessageDigestSpi {

    private static final int SGD_SM3 = 0x00000001;
    private static final int SM3_DIGEST_LENGTH = 32;

    private final SDFSessionManager sessionManager;
    private SDFSession session;
    private boolean isHashing;

    public SM3Digest() {
        super();
        this.sessionManager = SDFSessionManager.getInstance();
        this.isHashing = false;
    }

    private void ensureSessionAndInit() {
        if (session == null) {
            session = sessionManager.borrowSession();
        }
        if (!isHashing) {
            int rv = SDFLibrary.getInstance().SDF_HashInit(session.getSessionHandle(), SGD_SM3, (ECCrefPublicKey) null, (byte[]) null, 0);
            if (rv != 0) {
                releaseSession();
                throw new SDFException("SDF_HashInit", rv);
            }
            isHashing = true;
        }
    }

    private void releaseSession() {
        if (session != null) {
            session.close();
            session = null;
        }
        isHashing = false;
    }

    @Override
    protected void engineUpdate(byte input) {
        engineUpdate(new byte[]{input}, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        ensureSessionAndInit();
        byte[] dataToUpdate = new byte[len];
        System.arraycopy(input, offset, dataToUpdate, 0, len);
        int rv = SDFLibrary.getInstance().SDF_HashUpdate(session.getSessionHandle(), dataToUpdate, len);
        if (rv != 0) {
            throw new SDFException("SDF_HashUpdate", rv);
        }
    }

    @Override
    protected byte[] engineDigest() {
        ensureSessionAndInit();
        try {
            byte[] hash = new byte[SM3_DIGEST_LENGTH];
            IntByReference hashLen = new IntByReference(SM3_DIGEST_LENGTH);
            int rv = SDFLibrary.getInstance().SDF_HashFinal(session.getSessionHandle(), hash, hashLen);
            if (rv != 0) {
                throw new SDFException("SDF_HashFinal", rv);
            }
            if (hashLen.getValue() != SM3_DIGEST_LENGTH) {
                byte[] actualHash = new byte[hashLen.getValue()];
                System.arraycopy(hash, 0, actualHash, 0, hashLen.getValue());
                return actualHash;
            }
            return hash;
        } finally {
            releaseSession();
        }
    }

    @Override
    protected void engineReset() {
        releaseSession();
    }
}
