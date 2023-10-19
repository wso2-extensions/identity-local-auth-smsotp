/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com). All Rights Reserved.
 *
 * This software is the property of WSO2 LLC. and its suppliers, if any.
 * Dissemination of any information or reproduction of any material contained
 * herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
 * You may not alter or remove any copyright or other notice from copies of this content.
 *
 */

package org.wso2.carbon.identity.local.auth.smsotp.provider.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * This class represents the provider utility.
 *
 * @version 1.0.0
 * @since 1.0.0
 */
public class ProviderUtil {

    private static final Log LOG = LogFactory.getLog(ProviderUtil.class);

    /**
     * Hash the given telephone number using SHA-256 to print in logs. This is to avoid printing the telephone
     * number as a PII.
     * @param telephoneNumber Telephone number to be hashed.
     * @return Hashed telephone number.
     */
    public static String hashTelephoneNumber(String telephoneNumber) {

        try {
            final MessageDigest digest = MessageDigest.getInstance("SHA3-256");
            final byte[] hash = digest.digest(telephoneNumber.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                final String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException ex) {
            LOG.error("Error while hashing the telephone number.", ex);
            return "---";
        }
    }
}
