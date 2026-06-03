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

    public static final int DEFAULT_HTTP_URL_CONNECTION_TIMEOUT = 2000;
    public static final int DEFAULT_HTTP_URL_CONNECTION_READ_TIMEOUT = 3000;

    public static final String SMS_OTP_SERVICE = "local-auth-smsotp";

    /**
     * Define action IDs for diagnostic logs.
     */
    public static class ActionIDs {

        public static final String SEND_SMS = "send-sms";
        public static final String CIRCUIT_BREAKER_STATE_TRANSITION = "circuit-breaker-state-transition";
        public static final String CIRCUIT_BREAKER_REJECTION = "circuit-breaker-rejection";
    }

    /**
     * Enum for error messages.
     */
    public enum ErrorMessage {

        ERROR_UNAUTHORIZED_ACCESS("SMS-65001", "Unauthorized Access - Invalid Credentials provided.");

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
