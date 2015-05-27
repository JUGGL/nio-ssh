package com.zanclus.ssh.errors;

/**
 * Thrown during packet decoding if the Message Authenticate Code (MAC) cannot be validated.
 * @author <a href="https://github.com/InfoSec812">Deven Phillips</a>
 */
public class InvalidMACException extends Exception {

    public InvalidMACException() {
    }

    public InvalidMACException(String message) {
        super(message);
    }

    public InvalidMACException(Throwable cause) {
        super(cause);
    }

    public InvalidMACException(String message, Throwable cause) {
        super(message, cause);
    }
}
