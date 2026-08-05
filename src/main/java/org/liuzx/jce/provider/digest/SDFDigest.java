package org.liuzx.jce.provider.digest;

import com.sun.jna.ptr.IntByReference;
import org.liuzx.jce.jna.SDFLibrary;
import org.liuzx.jce.provider.exception.SDFException;
import org.liuzx.jce.provider.session.SDFSession;
import org.liuzx.jce.provider.session.SDFSessionManager;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigestSpi;

/**
 * SDF hardware-backed MessageDigest for SHA-1, SHA-256, SHA-384, SHA-512, and MD5.
 * Data is buffered in software; the hardware is only used in engineDigest().
 */
public abstract class SDFDigest extends MessageDigestSpi {

    private static final int SGD_SHA1   = 0x00000002;
    private static final int SGD_SHA256 = 0x00000004;
    private static final int SGD_SHA512 = 0x00000008;
    private static final int SGD_SHA384 = 0x00000040;
    private static final int SGD_SHA224 = 0x00000020;
    private static final int SGD_MD5    = 0x00000080;

    private final SDFSessionManager sessionManager;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private final int algId;
    private final int digestLength;

    protected SDFDigest(int algId, int digestLength) {
        this.sessionManager = SDFSessionManager.getInstance();
        this.algId = algId;
        this.digestLength = digestLength;
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
            int rv = sdf.SDF_HashInit(session.getSessionHandle(), algId, null, null, 0);
            session.checkResult(rv); if (rv != 0) throw new SDFException("SDF_HashInit(alg=" + Integer.toHexString(algId) + ")", rv);
            rv = sdf.SDF_HashUpdate(session.getSessionHandle(), data, data.length);
            session.checkResult(rv); if (rv != 0) throw new SDFException("SDF_HashUpdate", rv);
            byte[] hash = new byte[digestLength];
            IntByReference hashLen = new IntByReference(hash.length);
            rv = sdf.SDF_HashFinal(session.getSessionHandle(), hash, hashLen);
            session.checkResult(rv); if (rv != 0) throw new SDFException("SDF_HashFinal", rv);
            if (hashLen.getValue() != digestLength) {
                byte[] actual = new byte[hashLen.getValue()];
                System.arraycopy(hash, 0, actual, 0, hashLen.getValue());
                return actual;
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
        // 深拷贝：按运行时具体算法类重建实例并复制缓冲区（各子类无参构造已固定 algId/digestLength）
        try {
            SDFDigest copy = getClass().getDeclaredConstructor().newInstance();
            copy.buffer.write(buffer.toByteArray(), 0, buffer.size());
            return copy;
        } catch (ReflectiveOperationException e) {
            throw new CloneNotSupportedException("Cannot clone " + getClass().getName());
        }
    }

    // --- Concrete algorithm classes ---

    public static class SHA1 extends SDFDigest {
        public SHA1() { super(SGD_SHA1, 20); }
    }
    public static class SHA224 extends SDFDigest {
        public SHA224() { super(SGD_SHA224, 28); }
    }
    public static class SHA256 extends SDFDigest {
        public SHA256() { super(SGD_SHA256, 32); }
    }
    public static class SHA384 extends SDFDigest {
        public SHA384() { super(SGD_SHA384, 48); }
    }
    public static class SHA512 extends SDFDigest {
        public SHA512() { super(SGD_SHA512, 64); }
    }
    public static class MD5 extends SDFDigest {
        public MD5() { super(SGD_MD5, 16); }
    }
}
