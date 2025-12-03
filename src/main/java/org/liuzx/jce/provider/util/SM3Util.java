package org.liuzx.jce.provider.util;

/**
 * A minimal, pure software implementation of the SM3 hash algorithm.
 * This is used for pre-hashing data before signing with SM2.
 */
public final class SM3Util {

    private static final int IV[] = {0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e};
    private static final int T_J[] = {0x79cc4519, 0x7a879d8a};

    private SM3Util() {}

    public static byte[] hash(byte[] input) {
        int[] V = IV.clone();
        byte[] padded = pad(input);

        for (int i = 0; i < padded.length / 64; i++) {
            processBlock(V, padded, i * 64);
        }

        byte[] result = new byte[32];
        for (int i = 0; i < 8; i++) {
            writeInt(result, i * 4, V[i]);
        }
        return result;
    }

    private static byte[] pad(byte[] input) {
        int n = input.length;
        int k = (56 - (n + 1) % 64 + 64) % 64;
        byte[] padded = new byte[n + 1 + k + 8];
        System.arraycopy(input, 0, padded, 0, n);
        padded[n] = (byte) 0x80;
        long bitLength = (long) n * 8;
        for (int i = 0; i < 8; i++) {
            padded[padded.length - 1 - i] = (byte) (bitLength >>> (i * 8));
        }
        return padded;
    }

    private static void processBlock(int[] V, byte[] B, int offset) {
        int[] W = new int[68];
        int[] W_prime = new int[64];

        for (int i = 0; i < 16; i++) {
            W[i] = (B[offset + i * 4] & 0xFF) << 24 | (B[offset + i * 4 + 1] & 0xFF) << 16 | (B[offset + i * 4 + 2] & 0xFF) << 8 | (B[offset + i * 4 + 3] & 0xFF);
        }

        for (int j = 16; j < 68; j++) {
            W[j] = P1(W[j - 16] ^ W[j - 9] ^ Integer.rotateLeft(W[j - 3], 15)) ^ Integer.rotateLeft(W[j - 13], 7) ^ W[j - 6];
        }

        for (int j = 0; j < 64; j++) {
            W_prime[j] = W[j] ^ W[j + 4];
        }

        int A = V[0], B_ = V[1], C = V[2], D = V[3], E = V[4], F = V[5], G = V[6], H = V[7];

        for (int j = 0; j < 64; j++) {
            int SS1 = Integer.rotateLeft(Integer.rotateLeft(A, 12) + E + Integer.rotateLeft(T(j), j), 7);
            int SS2 = SS1 ^ Integer.rotateLeft(A, 12);
            int TT1 = FF(j, A, B_, C) + D + SS2 + W_prime[j];
            int TT2 = GG(j, E, F, G) + H + SS1 + W[j];
            D = C;
            C = Integer.rotateLeft(B_, 9);
            B_ = A;
            A = TT1;
            H = G;
            G = Integer.rotateLeft(F, 19);
            F = E;
            E = P0(TT2);
        }

        V[0] ^= A; V[1] ^= B_; V[2] ^= C; V[3] ^= D;
        V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
    }

    private static int T(int j) { return (j < 16) ? T_J[0] : T_J[1]; }
    private static int FF(int j, int X, int Y, int Z) { return (j < 16) ? (X ^ Y ^ Z) : ((X & Y) | (X & Z) | (Y & Z)); }
    private static int GG(int j, int X, int Y, int Z) { return (j < 16) ? (X ^ Y ^ Z) : ((X & Y) | (~X & Z)); }
    private static int P0(int X) { return X ^ Integer.rotateLeft(X, 9) ^ Integer.rotateLeft(X, 17); }
    private static int P1(int X) { return X ^ Integer.rotateLeft(X, 15) ^ Integer.rotateLeft(X, 23); }

    private static void writeInt(byte[] arr, int offset, int value) {
        arr[offset] = (byte) (value >>> 24);
        arr[offset + 1] = (byte) (value >>> 16);
        arr[offset + 2] = (byte) (value >>> 8);
        arr[offset + 3] = (byte) value;
    }
}
