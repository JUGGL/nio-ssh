package com.zanclus.ssh.transport;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.zip.Deflater;

/**
 * A class representing a single SSH Packet. To be used with Message Encoders/Decoders
 * @author <a href="https://github.com/InfoSec812">Deven Phillips</a>
 */

public class Packet {

    /**
     * The packet payload data. Size is ({@code packetLength} - {@code paddingLength} - 1)
     */
    byte[] payload;

    /**
     * Raw binary data. Could be the same as payload if compression is not enabled.
     */
    byte[] data;

    /**
     * Arbitrary-length padding, such that the total length of (packet_length || padding_length || payload || random
     * padding) is a multiple of the cipher block size or 8, whichever is larger. There MUST be at least four bytes of
     * padding. The padding SHOULD consist of random bytes. The maximum amount of padding is 255 bytes.
     */
    byte[] randomPadding;

    /**
     * Enable or disable compression of data
     */
    boolean compress = false;

    /**
     * Message Authentication Code. If message authentication has been negotiated, this field contains the MAC bytes.
     * Initially, the MAC algorithm MUST be "none".
     */
    byte[] mac;
    
    /**
     * The HMAC algorithm for this packet
     */
    HMAC algorithm;

    /**
     * Create a new SSH packet. Data MUST NOT exceed 32768 bytes
     *
     * @param data
     */
    private Packet(byte[] data) {
        this.data = data;
    }

    private Packet(byte[] data, boolean compress) {
        this.data = data;
        this.compress = compress;
    }

    private boolean isValidPacketLength() {
        return ((mac.length + randomPadding.length + payload.length + 2) <= 35000);
    }

    public static final Packet create(byte[] data) {
        return new Packet(data);
    }

    public static final Packet create(byte[] data, boolean compress) {
        return new Packet(data, compress);
    }

    /**
     * Returns a completely formatted SSH packet in the format specified by
     * <a href="http://tools.ietf.org/html/rfc4253#section-6">RFC 4253 Section 6</a>
     *
     * @return A byte[] containing the formatted packet with optional compressed payload.
     */
    public byte[] toByteArray() {
        ByteBuf buffer = Unpooled.buffer(data.length);
        if (compress) {
            Deflater compresser = new Deflater();
            compresser.setInput(data);
            compresser.finish();
            payload = new byte[data.length];
            int compressedLength = compresser.deflate(payload);
        } else {
            payload = data;
        }
        byte[] paddedPayload;
        int shortBlockSize = (payload.length % 8);
        if (shortBlockSize != 0) {
            paddedPayload = Arrays.copyOf(payload, payload.length + (8 - shortBlockSize));
        } else {
            paddedPayload = payload;
        }

        int rndPaddingLen = Long.valueOf(Math.round(Math.random() * 255)).intValue();

        // Deteming if the padded (optionally compressed) packet length will overflow the suggested 35000 byte limit
        int overflow = 35000 - paddedPayload.length - rndPaddingLen - 4 - 1;

        // If the packet would go over the 35000 byte limit, reduce the size of the random padding.
        if (overflow < 0 && overflow > -255) {
            rndPaddingLen = rndPaddingLen + overflow;
        } else {
            rndPaddingLen = 0;
        }

        byte[] rndPad = this.generateRandomPadding(rndPaddingLen);

        return payload;
    }

    /**
     * Generate {@code size} bytes of random padding data to prevent frequency analysis attacks on the SSH protocol
     *
     * @param size The number of bytes of random data to be generated
     * @return A byte array containing {@code size} number of random bytes
     */
    private byte[] generateRandomPadding(int size) {
        byte[] rndPadding = new byte[size];
        new SecureRandom().nextBytes(rndPadding);
        return rndPadding;
    }
}
