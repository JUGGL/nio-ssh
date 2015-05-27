/**
 * Copyright 2015, Deven Phillips
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.zanclus.ssh.transport;

import com.zanclus.ssh.errors.InvalidMACException;
import com.zanclus.ssh.errors.PacketSizeException;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * An extension to the {@link ByteToMessageDecoder} which will decode the {@link ByteBuf}
 * into an SSH Packet
 * @author <a href="https://github.com/InfoSec812">Deven Phillips</a>
 * @see <a href="https://tools.ietf.org/html/rfc4253">RFC 4253</a>
 */
@Slf4j
public class SSHFrameDecoder extends ByteToMessageDecoder {
    
    /**
     * The length of the packet header in bytes<br/>
     * <pre><tt>
     *     uint32    packet_length      4 bytes
     *     byte      padding_length     1 byte
     * </tt></pre>
     */
    private static final int HEADER_LEN = 5;
    
    private final KeyParameter key;
    private final HMAC algorithm;
    private final BufferedBlockCipher cipher;
    
    private boolean largePacketSupport = false;
    
    /**
     * Constructor for SSH decoder to be added to the {@link io.netty.channel.Channel} on which
     * a stream is received.
     * @param algorithm The {@link HMAC} algorithm which this connection uses for message authentication
     * @param key 
     */
    public SSHFrameDecoder(HMAC algorithm, BufferedBlockCipher cipher, KeyParameter key) {
        this.algorithm = algorithm;
        this.cipher = cipher;
        this.key = key;
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) throws Exception {
        in.markReaderIndex();
        if (in.readableBytes()>HEADER_LEN) {
            byte[] header = new byte[HEADER_LEN];
            in.readBytes(header);
            int packetLen = shift(header[0], 24) | shift(header[1], 16) | shift(header[2], 8) | shift(header[3], 0);
            if (largePacketSupport || packetLen<=35000) {
                int paddingLen = (int)header[4];
                int payloadLen = packetLen - paddingLen - HEADER_LEN;
                if (algorithm.equals(HMAC.NONE)) {
                    LOG.warn("HMAC algorithm set to NONE, this SHOULD only happen during inital key exchange."
                        + "See https://tools.ietf.org/html/rfc4253#section-6");
                }
                if (in.readableBytes()>=(payloadLen+paddingLen+algorithm.digestLen())) {

                    // Read the payload
                    byte[] payload = new byte[payloadLen];
                    in.readBytes(payload);
                    
                    byte[] plaintext = decryptPayload(payload);

                    // Skip the random padding
                    in.skipBytes(paddingLen);

                    byte[] computedMAC = calculateMAC(plaintext);

                    // Read MAC from ByteBuf
                    byte[] recievedMAC = new byte[algorithm.digestLen()];
                    in.readBytes(recievedMAC);

                    // Compare calculcated MAC with MAC read from ByteBuf
                    if (computedMAC.length>=algorithm.digestLen() && recievedMAC.length==algorithm.digestLen()) {
                        validateMAC(recievedMAC, computedMAC);
                    } else {
                        throw new InvalidMACException("Either the computed or received MAC size does not match "
                            + "expected length for the negotiated algorithm.");
                    }
                    LOG.debug("Message Packet decoded and MAC verified.");
                } else {
                    LOG.info("Insufficient bytes to finish decoding Packet. Resetting input buffer.");
                    in.resetReaderIndex();
                }
            } else {
                // Packet length cannot be greater than 35000 bytes according to RFC 4253 Section 6.1
                throw new PacketSizeException(String.format("Packet size of '%d' exceeds RFC 4253 recommendations and "
                    + "large packet support was not expressly enabled.", packetLen));
            }
        } else {
            LOG.info("Insufficient bytes to finish decoding Packet. Resetting input buffer.");
            in.resetReaderIndex();
        }
    }
    
    /**
     * Given a shared secret {@code key}, a {@code cipher}, and an encrypted payload; decrypt the
     * payload and return it as an array of {@code byte}s
     * @param payload The encrypted payload
     * @return An array of {@code byte}s containing the decrypted payload
     */
    private byte[] decryptPayload(byte[] payload) throws InvalidCipherTextException {
        cipher.init(true, key);
        byte[] plaintext = new byte[cipher.getOutputSize(payload.length)];
        int len = cipher.processBytes(payload, 0, payload.length, plaintext, 0);
        len += cipher.doFinal(plaintext, len);
        return plaintext;
    }

    /**
     * Calculate the MAC for the payload read from the ByteBuf
     * TODO: MAC MUST be calculated AFTER decryption!
     * @param payload The decrypted payload
     */
    private byte[] calculateMAC(byte[] payload) throws IllegalAccessException, InstantiationException {
        HMac mac = new HMac(algorithm.digest().newInstance());
        mac.init(key);
        mac.update(payload, 0, payload.length);
        int macSize = mac.getMacSize();
        byte[] computedMAC = new byte[macSize];
        mac.doFinal(computedMAC, 0);
        return computedMAC;
    }

    private void validateMAC(byte[] recievedMAC, byte[] computedMAC) throws InvalidMACException {
        for (int x=0; x<algorithm.digestLen(); x++) {
            if (recievedMAC[x]!=computedMAC[x]) {
                throw new InvalidMACException("Packet message cannot be authenticated.");
            }
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
    
    /**
     * Given a {@code byte} and an offset, left-shift the byte and return the resultant integer
     * @param b The {@code byte} to be shifted
     * @param offset The number of places to the left the byte should be shifted
     * @return An integer representing the shifted {@code byte}
     */
    private int shift(byte b, int offset) {
        return ((0xFF & b) << offset);
    }
}
