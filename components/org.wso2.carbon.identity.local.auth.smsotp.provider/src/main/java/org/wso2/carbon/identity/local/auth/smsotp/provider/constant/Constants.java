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

    public static final int DEFAULT_HTTP_URL_CONNECTION_TIMEOUT = 5000;
    public static final int DEFAULT_HTTP_URL_CONNECTION_READ_TIMEOUT = 20000;
}
