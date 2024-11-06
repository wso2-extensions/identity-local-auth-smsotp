/*
 * Copyright (c) 2024, WSO2 LLC. (https://www.wso2.com).
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

package org.wso2.carbon.identity.local.auth.smsotp.event.handler.notification;

import org.wso2.carbon.identity.event.event.Event;

import java.util.HashMap;
import java.util.Map;

public class TestableSMSNotificationHandler extends SMSNotificationHandler {

    public static Map<String, String> notificationData;

    static {
        resetNotificationData();
    }

    public static void resetNotificationData() {

        notificationData = new HashMap<>();
        notificationData.put("send-to", "+11110000");
        notificationData.put("TEMPLATE_TYPE", "SMSOTP");
        notificationData.put("application-name", "sms_otp_singlepage_App");
        notificationData.put("notification-channel", "smsotp");
        notificationData.put("notification-event", "smsotp");
        notificationData.put("mobile", "+11110000");
        notificationData.put("otpToken", "874090");
        notificationData.put("userstore-domain", "DEFAULT");
        notificationData.put("locale", "en_US");
        notificationData.put("body", "Your one-time password for the sms_otp_singlepage_App is 874090. " +
                "This expires in 5 minutes.");
        notificationData.put("tenant-domain", "tenant1");
        notificationData.put("otp-expiry-time", "5");
        notificationData.put("user-name", "wso2@gmail.com");
        notificationData.put("body-template", "Your one-time password for the {{application-name}} " +
                "is {{otpToken}}. This expires in {{otp-expiry-time}} minutes.,");
    }

    protected void publishToStream(Map<String, String> dataMap, Event event) {

    }

    protected Map<String, String> buildNotificationData(Event event) {

        return notificationData;
    }
}
