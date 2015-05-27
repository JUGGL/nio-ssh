package com.zanclus.ssh.transport;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.tls.MACAlgorithm;

/**
 * Message Authentication Code ENUM type.
 *
 * @author <a href="https://github.com/InfoSec812">Deven Phillips</a>
 */
public enum HMAC {
//        keylen   digestlen              id   hash implementation
    SHA1     (20,         20,    "hmac-sha1",  SHA1Digest.class ),
    SHA1_96  (20,         12, "hmac-sha1-96",  SHA1Digest.class ),
    MD5      (16,         16,     "hmac-md5",  MD5Digest.class  ),
    MD5_96   (16,         12,  "hmac-md5-96",  MD5Digest.class  ),
    NONE     ( 0,          0,         "none",  null             );

    private final int keyLen;
    private final int digestLen;
    private final String algorithm;
    private final Class<? extends Digest> digest;

    private HMAC(int keyLen, int digestLen, String name, Class<? extends Digest> digest) {
        this.keyLen = keyLen;
        this.digestLen = digestLen;
        this.algorithm = name;
        this.digest = digest;
    }

    /**
     * HMAC key length
     *
     * @return HMAC key length
     */
    public int keyLen() {
        return keyLen;
    }

    /**
     * HMAC digest length
     *
     * @return HMAC digest length
     */
    public int digestLen() {
        return digestLen;
    }

    /**
     * HMAC algorithm name
     *
     * @return HMAC algorithm name
     */
    public String algorithm() {
        return algorithm;
    }
    
    /**
     * Get the digest implementation class
     * @return A {@link Class} which implements the {@link Digest} interface
     */
    public Class<? extends Digest> digest() {
        return digest;
    }
}