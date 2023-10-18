/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com). All Rights Reserved.
 *
 * This software is the property of WSO2 LLC. and its suppliers, if any.
 * Dissemination of any information or reproduction of any material contained
 * herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
 * You may not alter or remove any copyright or other notice from copies of this content.
 *
 */

package org.wso2.carbon.identity.local.auth.smsotp.event.handler.notification;

/**
 * Keep constants required by the SMS OTP Notification Event Handler.
 */
public class SMSNotificationConstants {

    public static final String NOTIFICATION_HANDLER_NAME = "SMSNotificationHandler";
    public static final String SMS_NOTIFICATION_HUB_TOPIC_SUFFIX = "NOTIFICATIONS";
    public static final String SMS_NOTIFICATION_EVENT_URI = "urn:ietf:params:notifications:smsOtp";
    public static final String SMS_MESSAGE_BODY_NAME = "body";
    public static final String SMS_MASSAGE_TO_NAME = "send-to";
    public static final String SMS_PUBLISHER_NAME = "SMSPublisher";
}
