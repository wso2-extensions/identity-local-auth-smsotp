/*
 * Copyright (c) 2023-2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.local.auth.smsotp.provider.exception;

/**
 * This class represents the provider exception.
 *
 * @version 1.0.0
 * @since 1.0.0
 */
public class ProviderException extends Exception {

    private final String errorCode;

    /**
     * Constructs a new exception with the specified detail message.
     *
     * @param message The detail message.
     */
    public ProviderException(String message) {

        super(message);
        this.errorCode = null;
    }

    /**
     * Constructs a new exception with the specified detail message and cause.
     *
     * @param message The detail message.
     * @param cause   The cause.
     */
    public ProviderException(String message, Throwable cause) {

        super(message, cause);
        this.errorCode = null;
    }

    /**
     * Constructs a new exception with the specified error code, detail message and cause.
     *
     * @param errorCode The error code.
     * @param message   The detail message.
     * @param cause     The cause.
     */
    public ProviderException(String errorCode, String message, Throwable cause) {

        super(message, cause);
        this.errorCode = errorCode;
    }

    /**
     * Constructs a new exception with the specified error code and detail message.
     *
     * @param errorCode The error code.
     * @param message   The detail message.
     */
    public ProviderException(String errorCode, String message) {

        super(message);
        this.errorCode = errorCode;
    }

    /**
     * Constructs a new exception with the specified cause.
     *
     * @param cause The cause.
     */
    public ProviderException(Throwable cause) {

        super(cause);
        this.errorCode = null;
    }

    /**
     * Constructs a new exception with the specified detail message, cause, suppression enabled or disabled, and
     * writable stack trace enabled or disabled.
     * @param message The detail message.
     * @param cause The cause.
     * @param enableSuppression Whether or not suppression is enabled or disabled.
     * @param writableStackTrace Whether or not the stack trace should be writable.
     */
    public ProviderException(String message, Throwable cause, boolean enableSuppression,
                             boolean writableStackTrace) {

        super(message, cause, enableSuppression, writableStackTrace);
        this.errorCode = null;
    }

    /**
     * Returns the error code associated with this exception.
     *
     * @return The error code, or null if not set.
     */
    public String getErrorCode() {

        return errorCode;
    }
}
