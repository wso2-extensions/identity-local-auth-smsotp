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

package org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant;

/**
 * Constants class.
 */
public class SMSOTPConstants {

    public static final String SMS_OTP_AUTHENTICATOR_NAME = "sms-otp-authenticator";
    public static final String SMS_OTP_AUTHENTICATOR_FRIENDLY_NAME = "SMS OTP";

    private static final String SMS_AUTHENTICATOR_ERROR_PREFIX = "SMSOTP";
    public static final int DEFAULT_OTP_LENGTH = 6;
    public static final int DEFAULT_OTP_RESEND_ATTEMPTS = 5;
    public static final int MASKED_DIGITS = 4;
    public static final long DEFAULT_SMS_OTP_VALIDITY_IN_MILLIS = 300000;
    public static final String MOBILE_NUMBER = "MOBILE_NUMBER";
    public static final String ATTRIBUTE_SMS_SENT_TO = "send-to";
    public static final String TEMPLATE_TYPE = "TEMPLATE_TYPE";
    public static final String EVENT_NAME = "SMSOTP";
    public static final String PROVIDER = "provider";
    public static final String PUBLISHER = "Publisher";
    public static final String SMS_PROVIDER = "SMSPublisher";


    // OTP generation.
    public static final String SMS_OTP_NUMERIC_CHAR_SET = "9245378016";
    public static final String SMS_OTP_ALPHA_NUMERIC_CHAR_SET = "KIGXHOYSPRWCEFMVUQLZDNABJT9245378016";
    public static final String MOBILE_NUMBER_MASKING_CHARACTER = "*";
    public static final String RESEND = "resendCode";
    public static final String CODE = "OTPcode";
    public static final String OTP_TOKEN = "otpToken";
    public static final String OTP_EXPIRED = "isOTPExpired";
    public static final String OTP_GENERATED_TIME = "tokenGeneratedTime";
    public static final String OTP_RESEND_ATTEMPTS = "otpResendAttempts";

    // OTP validation states.
    public static final String STATUS_SUCCESS = "success";
    public static final String STATUS_OTP_EXPIRED = "otp-expired";
    public static final String STATUS_CODE_MISMATCH = "code-mismatch";

    // Endpoint URLs.
    public static final String ERROR_PAGE = "authenticationendpoint/smsOtpError.jsp";
    public static final String SMS_OTP_PAGE = "authenticationendpoint/smsOtp.jsp";

    public static final String OIDC_DIALECT_URI = "http://wso2.org/oidc/claim";
    public static final String MOBILE_ATTRIBUTE_KEY = "phone_number";

    // Query params.
    public static final String AUTHENTICATORS_QUERY_PARAM = "&authenticators=";
    public static final String RETRY_QUERY_PARAMS = "&authFailure=true&authFailureMsg=authentication.fail.message";
    public static final String ERROR_USER_ACCOUNT_LOCKED_QUERY_PARAMS =
            "&authFailure=true&authFailureMsg=user.account.locked";
    public static final String ERROR_PROVIDER_NOT_ENABLED = "&authFailure=true&authFailureMsg=smsotp.disable";
    public static final String ERROR_USER_MOBILE_NUMBER_NOT_FOUND_QUERY_PARAMS =
            "&authFailure=true&authFailureMsg=user.mobile.not.found";
    public static final String ERROR_USER_RESEND_COUNT_EXCEEDED_QUERY_PARAMS =
            "&authFailure=true&authFailureMsg=resent.count.exceeded";
    public static final String ERROR_SMS_QUOTA_COUNT_EXCEEDED_QUERY_PARAMS =
            "&authFailure=true&authFailureMsg=sms.quota.exceeded";
    public static final String SCREEN_VALUE_QUERY_PARAM = "&screenValue=";
    public static final String UNLOCK_QUERY_PARAM = "&unlockTime=";
    public static final String MULTI_OPTION_URI_PARAM = "&multiOptionURI=";
    public static final String USERNAME_PARAM = "&username=";
    public static final String CORRELATION_ID_MDC = "Correlation-ID";
    public static final String PROP_THROTTLER_SERVICE_CONNECTION = "sms_throttler.throttler_service_connection";
    public static final String PROP_THROTTLER_SERVICE_ENABLE = "sms_throttler.enable";

    /**
     * Authenticator config related configurations.
     */
    public static class ConnectorConfig {

        public static final String OTP_EXPIRY_TIME = "SmsOTP.ExpiryTime";
        public static final String SMS_OTP_LENGTH = "SmsOTP.OTPLength";
        public static final String SMS_OTP_USE_NUMERIC_CHARS = "SmsOTP.OtpRegex.UseNumericChars";
        public static final String SMS_OTP_RESEND_ATTEMPTS_COUNT = "SmsOTP.ResendAttemptsCount";
    }

    /**
     * User claim related constants.
     */
    public static class Claims {

        public static final String MOBILE_CLAIM = "http://wso2.org/claims/mobile";
        public static final String ACCOUNT_UNLOCK_TIME_CLAIM = "http://wso2.org/claims/identity/unlockTime";
        public static final String SMS_OTP_FAILED_ATTEMPTS_CLAIM =
                "http://wso2.org/claims/identity/failedSmsOtpAttempts";
    }

    /**
     * Types of providers.
     */
    public static class ProviderTypes {

        public static final String DEFAULT = "DEFAULT";
        public static final String CUSTOM = "CUSTOM";
    }

    /**
     * Enum which contains the error codes and corresponding error messages.
     */
    public enum ErrorMessages {

        ERROR_CODE_ERROR_GETTING_CONFIG("65001", "Error occurred while getting the authenticator " +
                "configuration"),
        ERROR_CODE_USER_ACCOUNT_LOCKED("65002", "Account is locked for the user: %s"),
        ERROR_CODE_EMPTY_OTP_CODE("65003", "OTP token is empty for user: %s"),
        ERROR_CODE_RETRYING_OTP_RESEND("65004", "User: %s is retrying to resend the OTP"),
        ERROR_CODE_EMPTY_GENERATED_TIME("65005", "Token generated time not specified"),
        ERROR_CODE_EMPTY_OTP_CODE_IN_CONTEXT("65006", "OTP token is empty in context for user: %s"),
        ERROR_CODE_ERROR_GETTING_BACKUP_CODES("65007",
                "Error occurred while getting backup codes for user: %s"),
        ERROR_CODE_ERROR_GETTING_ACCOUNT_UNLOCK_TIME("65008",
                "Error occurred while getting account unlock time for user: %s"),
        ERROR_CODE_ERROR_UPDATING_BACKUP_CODES("65009",
                "Error occurred while updating unused backup codes for user: %s"),
        ERROR_CODE_ERROR_GETTING_MOBILE_NUMBER("65010",
                "Error occurred while getting the mobile number for user: %s"),
        ERROR_CODE_ERROR_GETTING_USER_REALM("65011",
                "Error occurred while getting the user realm for tenant: %s"),
        ERROR_CODE_ERROR_REDIRECTING_TO_LOGIN_PAGE("65012",
                "Error occurred while redirecting to the login page"),
        ERROR_CODE_ERROR_TRIGGERING_EVENT("65013",
                "Error occurred while triggering event: %s for the user: %s"),
        ERROR_CODE_ERROR_REDIRECTING_TO_ERROR_PAGE("65014",
                "Error occurred while redirecting to the error page"),
        ERROR_CODE_NO_USER_FOUND("65015", "No user found from the authentication steps"),
        ERROR_CODE_EMPTY_USERNAME("65016", "Username can not be empty"),
        ERROR_CODE_ERROR_GETTING_USER_STORE_MANAGER("65017",
                "Error occurred while getting the user store manager for the user: %s"),
        ERROR_CODE_GETTING_ACCOUNT_STATE("65018", "Error occurred while checking the account locked " +
                "state for the user: %s"),
        ERROR_CODE_OTP_EXPIRED("65019", "OTP expired for user: %s"),
        ERROR_CODE_OTP_INVALID("65020", "Invalid coded provided by user: %s"),
        ERROR_CODE_ERROR_GETTING_FEDERATED_AUTHENTICATOR("65021", "Error occurred while getting IDP: " +
                "%s from tenant: %s"),
        ERROR_CODE_INVALID_FEDERATED_AUTHENTICATOR("65022", "No IDP found with the name IDP: " +
                "%s in tenant: %s"),
        ERROR_CODE_NO_CLAIM_CONFIGS_IN_FEDERATED_AUTHENTICATOR("65023", "No claim configurations " +
                "found in IDP: %s in tenant: %s"),
        ERROR_CODE_NO_MOBILE_CLAIM_MAPPINGS("65024", "No mobile claim mapping found in IDP: %s in " +
                "tenant: %s"),
        ERROR_CODE_NO_FEDERATED_USER("65025", "No federated user found"),
        ERROR_CODE_USER_ID_NOT_FOUND("65026", "User id is not available for user"),
        ERROR_CODE_ERROR_GETTING_APPLICATION("65027", "Error while getting the application id"),
        ERROR_CODE_CONNECTING_THROTTLER_SERVICE("65028", "Error connecting throttler service");

        private final String code;
        private final String message;

        ErrorMessages(String code, String message) {

            this.code = code;
            this.message = message;
        }

        public String getCode() {

            return SMS_AUTHENTICATOR_ERROR_PREFIX + "-" + code;
        }

        public String getMessage() {

            return message;
        }

        @Override
        public String toString() {

            return code + " - " + message;
        }
    }
}
