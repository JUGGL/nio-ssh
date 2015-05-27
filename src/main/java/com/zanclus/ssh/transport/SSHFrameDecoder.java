package com.zanclus.ssh.transport;

import com.zanclus.ssh.errors.PacketSizeException;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;
import java.math.BigInteger;
import java.util.List;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.macs.HMac;

/**
 * An extension to the {@link LengthFieldBasedFrameDecoder} which will decode the {@link ByteBuf}
 * into an SSH {@link Packet}
 * @author <a href="https://github.com/InfoSec812">Deven Phillips</a>
 */
public class SSHFrameDecoder extends ByteToMessageDecoder {
    
    /**
     * The length of the packet header in bytes<br/>
     * <pre><tt>
     *     uint32    packet_length      4 bytes
     *     byte      padding_length     1 byte
     * </tt></pre>
     */
    private static final int HEADER_LEN = 5;
    
    private final CipherParameters macParams;
    private final HMAC algorithm;
    private byte[] macDigest;
    
    private boolean largePacketSupport = false;
    
    public SSHFrameDecoder(HMAC algorithm, CipherParameters macParams) {
        this.algorithm = algorithm;
        this.macParams = macParams;
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) throws Exception {
        in.markReaderIndex();
        if (in.readableBytes()>HEADER_LEN) {
            byte[] header = new byte[HEADER_LEN];
            in.readBytes(header);
            int packetLen = ((0xFF & header[0]) << 24) | ((0xFF & header[1]) << 16) | ((0xFF & header[2]) << 8) | (0xFF & header[3]);
            if (largePacketSupport || packetLen<=35000) {
                int paddingLen = (int)header[4];
                int payloadLen = packetLen - paddingLen - HEADER_LEN;
                if (in.readableBytes()>=(payloadLen+paddingLen+algorithm.digestLen())) {

                    // Read the payload
                    byte[] payload = new byte[payloadLen];
                    in.readBytes(payload);

                    // Skip the random padding
                    in.skipBytes(paddingLen);

                    // Calculate the MAC for the payload read from the ByteBuf
                    HMac mac = new HMac(algorithm.digest().newInstance());
                    mac.init(macParams);
                    mac.update(payload, 0, payloadLen);
                    int macSize = mac.getMacSize();
                    byte[] computedMAC = new byte[macSize];
                    mac.doFinal(computedMAC, 0);

                    // Read MAC from ByteBuf
                    byte[] recievedMAC = new byte[algorithm.digestLen()];
                    in.readBytes(recievedMAC);

                    // Compare calculcated MAC with MAC read from ByteBuf
                    boolean validMAC = true;
                    for (int x=0; x<algorithm.digestLen(); x++) {
                        if (recievedMAC[x]!=computedMAC[x]) {
                            validMAC = false;
                            break;
                        }
                    }

                    // If the MACs agree, add the SSH frame to the output list
                    if (validMAC) {
                        out.add(payload);
                    }
                } else {
                    in.resetReaderIndex();
                }
            } else {
                // Packet length cannot be greater than 35000 bytes according to RFC 4253 Section 6.1
                throw new PacketSizeException(String.format("Packet size of '%d' exceeds RFC 4253 recommendations and large packet support was not expressly enabled.", packetLen));
            }
        } else {
            in.resetReaderIndex();
        }
    }

    /**
     * Enable packets greater than 35000 bytes in length
     * @param enable Boolean TRUE if large packets should be allowed and FALSE if not.
     * @return A reference to this instance of {@link SSHFrameDecoder} for fluent composition
     */
    public SSHFrameDecoder largePacketSupport(boolean enable) {
        this.largePacketSupport = enable;
        return this;
    }
    
    /**
     * Indicate if large packet support is enabled
     * @return Boolean TRUE if large packets should be allowed and FALSE if not
     */
    public boolean largePacketSupport() {
        return this.largePacketSupport;
    }
}
