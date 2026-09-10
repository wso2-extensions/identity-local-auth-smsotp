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

package org.wso2.carbon.identity.local.auth.smsotp.provider.constant;

/**
 * Keep constants required by the SMS OTP Authenticator.
 */
public class Constants {

    public static final String FORM = "FORM";
    public static final String JSON = "JSON";
    public static final String HTTP_POST = "POST";
    public static final String CONTENT_TYPE = "Content-Type";
    public static final String APPLICATION_JSON = "application/json";
    public static final String APPLICATION_FORM = "application/x-www-form-urlencoded";

    public static final String VONAGE = "Vonage";
    public static final String TWILIO = "Twilio";

    public static final String HTTP_HEADERS = "http.headers";
    public static final String HTTP_METHOD = "http.method";
    public static final String HTTP_BODY = "body";
    public static final String TO_PLACEHOLDER = "{{mobile}}";
    public static final String BODY_PLACEHOLDER = "{{body}}";

    public static final String HTTP_URL_CONNECTION_TIMEOUT_CONFIG =
            "NotificationChannel.SMS.Custom.ConnectionTimeout";
    public static final String HTTP_URL_CONNECTION_READ_TIMEOUT_CONFIG =
            "NotificationChannel.SMS.Custom.ConnectionReadTimeout";
    public static final String RETRY_COUNT_AT_AUTH_FAILURE =
            "NotificationChannel.SMS.Custom.RetryCountAtAuthFailure";

    public static final int DEFAULT_HTTP_URL_CONNECTION_TIMEOUT = 5000;
    public static final int DEFAULT_HTTP_URL_CONNECTION_READ_TIMEOUT = 20000;

    public static final String SMS_OTP_SERVICE = "local-auth-smsotp";

    /**
     * Define action IDs for diagnostic logs.
     */
    public static class ActionIDs {

        public static final String SEND_SMS = "send-sms";
    }

    /**
     * Define input keys for diagnostic logs.
     */
    public static class InputKeys {

        public static final String PROVIDER_STATUS = "provider status";

        private InputKeys() {
        }
    }

    /**
     * Enum for error messages.
     */
    public enum ErrorMessage {

        UNAUTHORIZED("SP-65001",
                "The SMS could not be sent because authentication with the SMS service failed. "
                        + "Please contact your administrator."),
        FORBIDDEN("SP-65002",
                "The SMS could not be sent because the account does not have the required permissions. "
                        + "Please contact your administrator."),
        BAD_REQUEST("SP-65003",
                "The SMS could not be sent because the SMS service did not accept the request. "
                        + "Please contact your administrator."),
        TOO_MANY_REQUESTS("SP-65004",
                "The SMS could not be sent because the SMS service is temporarily busy. "
                        + "Please try again in a few moments."),
        SERVER_ERROR("SP-65005",
                "The SMS could not be sent because the SMS service encountered an unexpected error. "
                        + "Please try again or contact support."),
        SMS_SEND_FAILED("SP-65006",
                "The SMS could not be sent due to an unexpected error. "
                        + "Please try again or contact your administrator."),
        MESSAGE_DELIVERY_FAILED("SP-65007",
                "The SMS could not be delivered. "
                        + "Please try again or contact your administrator."),
        INVALID_CONFIGURATION("SP-65008",
                "The SMS could not be sent because the SMS service is not configured correctly. "
                        + "Please contact your administrator."),
        SERVICE_UNREACHABLE("SP-65009",
                "The SMS could not be sent because the SMS service cannot be reached. "
                        + "Please contact your administrator."),
        ACCOUNT_SUSPENDED("SP-65010",
                "The SMS could not be sent because the messaging account has been suspended. "
                        + "Please contact your administrator."),
        ACCOUNT_LIMIT_EXCEEDED("SP-65011",
                "The SMS could not be sent because the account limit has been reached. "
                        + "Please contact your administrator."),
        UNDELIVERABLE_NUMBER("SP-65012",
                "The SMS could not be delivered. The recipient's number may be switched off, "
                        + "out of coverage, or not a mobile number. Please check the number and try again."),
        CARRIER_FILTERED("SP-65013",
                "The SMS was blocked by the mobile carrier. This can happen due to content filtering "
                        + "or sender restrictions. Please contact your administrator."),
        NUMBER_BARRED("SP-65014",
                "The SMS could not be delivered because the recipient's number is not permitted. "
                        + "Please contact your administrator.");

        private final String code;
        private final String message;

        ErrorMessage(String code, String message) {
            this.code = code;
            this.message = message;
        }

        public String getCode() {
            return code;
        }

        public String getMessage() {
            return message;
        }
    }

}
