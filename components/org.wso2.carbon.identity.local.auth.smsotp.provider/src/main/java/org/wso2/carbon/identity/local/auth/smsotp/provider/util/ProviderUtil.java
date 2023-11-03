/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
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
                hexString.append(String.format("%02X", b));
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException ex) {
            LOG.error("Error while hashing the telephone number.", ex);
            return "---";
        }
    }
}
