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

package org.wso2.carbon.identity.local.auth.smsotp.authenticator.connector;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.ConnectorConfig.OTP_EXPIRY_TIME;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.ConnectorConfig.SMS_OTP_LENGTH;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.ConnectorConfig.SMS_OTP_RESEND_ATTEMPTS_COUNT;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.ConnectorConfig.SMS_OTP_USE_NUMERIC_CHARS;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.DEFAULT_OTP_LENGTH;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.DEFAULT_OTP_RESEND_ATTEMPTS;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.SMS_OTP_AUTHENTICATOR_FRIENDLY_NAME;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.SMS_OTP_AUTHENTICATOR_NAME;

/**
 * This class contains the authenticator config implementation.
 */
public class SMSOTPAuthenticatorConfigImpl implements IdentityConnectorConfig {

    @Override
    public String getName() {

        return SMS_OTP_AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {

        return SMS_OTP_AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getCategory() {

        return "Multi Factor Authenticators";
    }

    @Override
    public String getSubCategory() {

        return "DEFAULT";
    }

    @Override
    public int getOrder() {

        return 0;
    }

    @Override
    public Map<String, String> getPropertyNameMapping() {

        Map<String, String> nameMapping = new HashMap<>();
        nameMapping.put(OTP_EXPIRY_TIME, "SMS OTP expiry time");
        nameMapping.put(SMS_OTP_LENGTH, "SMS OTP token length");
        nameMapping.put(SMS_OTP_USE_NUMERIC_CHARS, "Use only numeric characters for OTP token");
        nameMapping.put(SMS_OTP_RESEND_ATTEMPTS_COUNT, "Number of allowed resend attempts");
        return nameMapping;
    }

    @Override
    public Map<String, String> getPropertyDescriptionMapping() {

        Map<String, String> descriptionMapping = new HashMap<>();
        descriptionMapping.put(OTP_EXPIRY_TIME, "Email OTP expiry time in seconds");
        descriptionMapping.put(SMS_OTP_LENGTH, "Number of characters in the OTP token");
        descriptionMapping.put(SMS_OTP_USE_NUMERIC_CHARS, "Enabling this will only generate OTP tokens with 0-9 " +
                "characters");
        descriptionMapping.put(SMS_OTP_RESEND_ATTEMPTS_COUNT, "Number of allowed resend attempts of a user");
        return descriptionMapping;
    }

    @Override
    public String[] getPropertyNames() {

        List<String> properties = new ArrayList<>();
        properties.add(OTP_EXPIRY_TIME);
        properties.add(SMS_OTP_LENGTH);
        properties.add(SMS_OTP_USE_NUMERIC_CHARS);
        properties.add(SMS_OTP_RESEND_ATTEMPTS_COUNT);
        return properties.toArray(new String[0]);
    }

    @Override
    public Properties getDefaultPropertyValues(String tenantDomain) throws IdentityGovernanceException {

        // 5 minutes in seconds.
        String otpExpiryTime = "300";
        String useNumericChars = "true";
        String otpLength = Integer.toString(DEFAULT_OTP_LENGTH);
        String resendAttempts = Integer.toString(DEFAULT_OTP_RESEND_ATTEMPTS);

        String otpExpiryTimeProperty = IdentityUtil.getProperty(OTP_EXPIRY_TIME);
        String useNumericCharsProperty = IdentityUtil.getProperty(SMS_OTP_USE_NUMERIC_CHARS);
        String otpLengthProperty = IdentityUtil.getProperty(SMS_OTP_LENGTH);
        String resendAttemptsProperty = IdentityUtil.getProperty(SMS_OTP_RESEND_ATTEMPTS_COUNT);

        if (StringUtils.isNotBlank(otpExpiryTimeProperty)) {
            otpExpiryTime = otpExpiryTimeProperty;
        }
        if (StringUtils.isNotBlank(useNumericCharsProperty)) {
            useNumericChars = useNumericCharsProperty;
        }
        if (StringUtils.isNotBlank(otpLengthProperty)) {
            otpLength = otpLengthProperty;
        }
        if (StringUtils.isNotBlank(resendAttemptsProperty)) {
            resendAttempts = resendAttemptsProperty;
        }
        Map<String, String> defaultProperties = new HashMap<>();
        defaultProperties.put(OTP_EXPIRY_TIME, otpExpiryTime);
        defaultProperties.put(SMS_OTP_USE_NUMERIC_CHARS, useNumericChars);
        defaultProperties.put(SMS_OTP_LENGTH, otpLength);
        defaultProperties.put(SMS_OTP_RESEND_ATTEMPTS_COUNT, resendAttempts);

        Properties properties = new Properties();
        properties.putAll(defaultProperties);
        return properties;
    }

    @Override
    public Map<String, String> getDefaultPropertyValues(String[] propertyNames, String tenantDomain)
            throws IdentityGovernanceException {

        return null;
    }
}
