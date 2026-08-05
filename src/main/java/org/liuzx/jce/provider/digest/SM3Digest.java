package org.liuzx.jce.provider.digest;

import com.sun.jna.ptr.IntByReference;
import org.liuzx.jce.jna.SDFLibrary;
import org.liuzx.jce.jna.structure.ECCrefPublicKey;
import org.liuzx.jce.provider.exception.SDFException;
import org.liuzx.jce.provider.session.SDFSession;
import org.liuzx.jce.provider.session.SDFSessionManager;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigestSpi;

public class SM3Digest extends MessageDigestSpi {

    private static final int SGD_SM3 = 0x00000001;
    private static final int SM3_DIGEST_LENGTH = 32;

    private final SDFSessionManager sessionManager;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    public SM3Digest() {
        this.sessionManager = SDFSessionManager.getInstance();
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
    protected byte[] engineDigest() {
        byte[] data = buffer.toByteArray();
        buffer.reset();

        try (SDFSession session = sessionManager.borrowSession()) {
            SDFLibrary sdf = SDFLibrary.getInstance();

            int rv = sdf.SDF_HashInit(session.getSessionHandle(), SGD_SM3,
                    (ECCrefPublicKey) null, (byte[]) null, 0);
            if (rv != 0) {
                throw new SDFException("SDF_HashInit", rv);
            }

            rv = sdf.SDF_HashUpdate(session.getSessionHandle(), data, data.length);
            if (rv != 0) {
                throw new SDFException("SDF_HashUpdate", rv);
            }

            byte[] hash = new byte[SM3_DIGEST_LENGTH];
            IntByReference hashLen = new IntByReference(SM3_DIGEST_LENGTH);
            rv = sdf.SDF_HashFinal(session.getSessionHandle(), hash, hashLen);
            if (rv != 0) {
                throw new SDFException("SDF_HashFinal", rv);
            }

            if (hashLen.getValue() != SM3_DIGEST_LENGTH) {
                byte[] actualHash = new byte[hashLen.getValue()];
                System.arraycopy(hash, 0, actualHash, 0, hashLen.getValue());
                return actualHash;
            }
            return hash;
        }
    }

    @Override
    protected void engineReset() {
        buffer.reset();
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        // 深拷贝：新建实例并复制缓冲区，避免与浅拷贝共享 buffer 造成状态串扰
        SM3Digest copy = new SM3Digest();
        copy.buffer.write(buffer.toByteArray(), 0, buffer.size());
        return copy;
    }
}
