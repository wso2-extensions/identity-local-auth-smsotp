/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com). All Rights Reserved.
 *
 * This software is the property of WSO2 LLC. and its suppliers, if any.
 * Dissemination of any information or reproduction of any material contained
 * herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
 * You may not alter or remove any copyright or other notice from copies of this content.
 *
 */

package org.wso2.carbon.identity.local.auth.smsotp.event.handler.notification.internal;

import org.wso2.carbon.identity.notification.sender.tenant.config.NotificationSenderManagementService;
import org.wso2.carbon.identity.local.auth.smsotp.provider.Provider;

import java.util.HashMap;
import java.util.Map;

/**
 * SMS Notification Handler service component's value holder.
 */
public class SMSNotificationHandlerDataHolder {

    private static final SMSNotificationHandlerDataHolder instance = new SMSNotificationHandlerDataHolder();

    private NotificationSenderManagementService notificationSenderManagementService;
    private final Map<String, Provider> providers = new HashMap<>();

    private SMSNotificationHandlerDataHolder() {
        super();
    }

    public static SMSNotificationHandlerDataHolder getInstance() {
        return instance;
    }

    public void addProvider(String providerName, Provider provider) {
        providers.put(providerName, provider);
    }

    public void removeProvider(String providerName) {
        providers.remove(providerName);
    }

    public Provider getProvider(String providerName) {
        return providers.get(providerName);
    }

    public NotificationSenderManagementService getNotificationSenderManagementService() {
        return notificationSenderManagementService;
    }

    public void setNotificationSenderManagementService(
            NotificationSenderManagementService notificationSenderManagementService) {
        this.notificationSenderManagementService = notificationSenderManagementService;
    }
}
