/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.local.auth.smsotp.authenticator.util;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants;
import org.wso2.carbon.identity.local.auth.smsotp.authenticator.internal.AuthenticatorDataHolder;
import org.wso2.carbon.identity.user.registration.engine.exception.RegistrationEngineServerException;

/**
 * Utility functions for SMS OTP Executor.
 */
public class SMSOTPExecutorUtils {

    private static final Log LOG = LogFactory.getLog(SMSOTPExecutorUtils.class);

    private SMSOTPExecutorUtils() {

    }

    /**
     * Get the OTP validity period based on the configuration.
     *
     * @param tenantDomain Tenant domain.
     * @return OTP validity period in milliseconds.
     * @throws RegistrationEngineServerException If an error occurred while getting the config value.
     */
    public static long getOTPValidityPeriod(String tenantDomain) throws RegistrationEngineServerException {

        String value = getSMSAuthenticatorConfig(SMSOTPConstants.ConnectorConfig.OTP_EXPIRY_TIME,
                tenantDomain);
        if (StringUtils.isBlank(value)) {
            return SMSOTPConstants.DEFAULT_SMS_OTP_VALIDITY_IN_MILLIS;
        }
        long validityTime;
        try {
            validityTime = Long.parseLong(value);
        } catch (NumberFormatException e) {
            LOG.error(String.format("SMS OTP validity period value: %s configured in tenant : %s is not a " +
                            "number. Therefore, default validity period: %s (milli-seconds) will be used.", value,
                    tenantDomain, SMSOTPConstants.DEFAULT_SMS_OTP_VALIDITY_IN_MILLIS));
            return SMSOTPConstants.DEFAULT_SMS_OTP_VALIDITY_IN_MILLIS;
        }
        // We don't need to send tokens with infinite validity.
        if (validityTime < 0) {
            LOG.error(String.format("SMS OTP validity period value: %s configured in tenant : %s cannot be a " +
                    "negative number. Therefore, default validity period: %s (milli-seconds) will " +
                    "be used.", value, tenantDomain, SMSOTPConstants.DEFAULT_SMS_OTP_VALIDITY_IN_MILLIS));
            return SMSOTPConstants.DEFAULT_SMS_OTP_VALIDITY_IN_MILLIS;
        }
        // Converting to milliseconds since the config is provided in seconds.
        return validityTime * 1000;
    }

    /**
     * Get the OTP length based on the configuration.
     *
     * @param tenantDomain Tenant domain.
     * @return OTP length.
     * @throws RegistrationEngineServerException If an error occurred while getting the config value.
     */
    public static int getOTPLength(String tenantDomain) throws RegistrationEngineServerException {

        String value = getSMSAuthenticatorConfig(SMSOTPConstants.ConnectorConfig.SMS_OTP_LENGTH,
                tenantDomain);
        if (StringUtils.isBlank(value)) {
            return SMSOTPConstants.DEFAULT_OTP_LENGTH;
        }
        int otpLength;
        try {
            otpLength = Integer.parseInt(value);
        } catch (NumberFormatException e) {
            LOG.error(String.format("SMS OTP length value: %s configured in tenant : %s is not a number. " +
                            "Therefore, default OTP length: %s will be used.", value, tenantDomain,
                    SMSOTPConstants.DEFAULT_OTP_LENGTH));
            return SMSOTPConstants.DEFAULT_OTP_LENGTH;
        }
        return otpLength;
    }

    /**
     * Get the OTP charset based on the configuration.
     *
     * @param tenantDomain Tenant domain.
     * @return OTP charset.
     * @throws RegistrationEngineServerException If an error occurred while getting the config value.
     */
    public static String getOTPCharset(String tenantDomain) throws RegistrationEngineServerException {

        String value = getSMSAuthenticatorConfig(SMSOTPConstants.ConnectorConfig.SMS_OTP_USE_NUMERIC_CHARS,
                tenantDomain);
        if (Boolean.parseBoolean(value)) {
            return AuthenticatorConstants.OTP_NUMERIC_CHAR_SET;
        } else {
            return AuthenticatorConstants.OTP_ALPHA_NUMERIC_CHAR_SET;
        }
    }

    /**
     * Get sms authenticator config related to the given key.
     *
     * @param key          Authenticator config key.
     * @param tenantDomain Tenant domain.
     * @return Value associated with the given config key.
     * @throws RegistrationEngineServerException If an error occurred while getting th config value.
     */
    public static String getSMSAuthenticatorConfig(String key, String tenantDomain)
            throws RegistrationEngineServerException {

        try {
            IdentityGovernanceService governanceService = AuthenticatorDataHolder.getIdentityGovernanceService();
            return governanceService.getConfiguration(new String[]{key}, tenantDomain)[0].getValue();
        } catch (IdentityGovernanceException e) {
            throw new RegistrationEngineServerException(
                    SMSOTPConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_CONFIG.getCode(),
                    SMSOTPConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_CONFIG.getMessage(),
                    "Error getting SMS OTP authenticator config.", e);
        }
    }
}
