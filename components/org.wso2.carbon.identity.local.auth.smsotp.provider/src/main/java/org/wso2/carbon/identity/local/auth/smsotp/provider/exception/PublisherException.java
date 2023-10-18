/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com). All Rights Reserved.
 *
 * This software is the property of WSO2 LLC. and its suppliers, if any.
 * Dissemination of any information or reproduction of any material contained
 * herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
 * You may not alter or remove any copyright or other notice from copies of this content.
 *
 */

package org.wso2.carbon.identity.local.auth.smsotp.provider.exception;

/**
 * This class represents the exceptions related to the
 * {@link org.wso2.carbon.identity.local.auth.smsotp.provider.http.HTTPPublisher}.
 *
 * @version 1.0.0
 * @since 1.0.0
 */
public class PublisherException extends Exception {

    /**
     * Constructs a new exception with the specified detail message.
     *
     * @param message The detail message.
     */
    public PublisherException(String message) {
        super(message);
    }

    /**
     * Constructs a new exception with the specified detail message and cause.
     *
     * @param message The detail message.
     * @param cause   The cause.
     */
    public PublisherException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new exception with the specified cause.
     *
     * @param cause The cause.
     */
    public PublisherException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new exception with the specified detail message, cause,
     * @param message The detail message.
     * @param cause The cause.
     * @param enableSuppression Whether or not suppression is enabled or disabled.
     * @param writableStackTrace Whether or not the stack trace should be writable.
     */
    public PublisherException(String message, Throwable cause, boolean enableSuppression,
                              boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
