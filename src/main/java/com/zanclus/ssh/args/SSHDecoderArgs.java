package com.zanclus.ssh.args;

import com.zanclus.ssh.transport.HMAC;
import lombok.Builder;
import lombok.Data;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * A class to contain all of the appropriate arguments for an instance of {@link com.zanclus.ssh.transport.SSHFrameDecoder}
 * @author <a href="https://github.com/InfoSec812">Deven Phillips</a>
 */
@Data
@Builder
public class SSHDecoderArgs {

    private KeyParameter key;
    private HMAC algorithm;
    private BufferedBlockCipher cipher;
}