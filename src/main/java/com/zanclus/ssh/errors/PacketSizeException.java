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
