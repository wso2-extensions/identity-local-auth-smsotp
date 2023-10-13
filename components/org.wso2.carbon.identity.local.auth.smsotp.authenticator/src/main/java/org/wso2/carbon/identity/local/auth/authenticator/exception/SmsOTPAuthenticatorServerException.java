/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com). All Rights Reserved.
 *
 * This software is the property of WSO2 LLC. and its suppliers, if any.
 * Dissemination of any information or reproduction of any material contained
 * herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
 * You may not alter or remove any copyright or other notice from copies of this content.
 *
 */

package org.wso2.carbon.identity.local.auth.authenticator.exception;

/**
 * Implementation of server errors.
 */
public class SmsOTPAuthenticatorServerException extends SmsOTPAuthenticatorException {

    private static final long serialVersionUID = -4635116841173579773L;

    /**
     * Constructs a new exception with an error code, detail message and throwable.
     *
     * @param errorCode The error code.
     * @param message   The detail message.
     * @param throwable Throwable.
     */
    public SmsOTPAuthenticatorServerException(String errorCode, String message, Throwable throwable) {

        super(errorCode, message, throwable);
        this.setErrorCode(errorCode);
    }
}
