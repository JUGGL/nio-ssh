package com.zanclus.ssh.errors;

/**
 * Indicates that an SSH packet was larger that 35000 bytes and large
 * packet support was not enabled
 * @author <a href="https://github.com/InfoSec812">Deven Phillips</a>
 */
public class PacketSizeException extends Exception {

    public PacketSizeException(String message, Throwable cause) {
        super(message, cause);
    }

    public PacketSizeException(Throwable cause) {
        super(cause);
    }

    public PacketSizeException(String message) {
        super(message);
    }

    public PacketSizeException() {
        super();
    }
}
