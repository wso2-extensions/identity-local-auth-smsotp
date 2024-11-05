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

package org.wso2.carbon.identity.local.auth.smsotp.event.handler.notification.internal;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.wso2.carbon.identity.governance.service.notification.NotificationTemplateManager;
import org.wso2.carbon.identity.local.auth.smsotp.provider.Provider;
import org.wso2.carbon.identity.notification.sender.tenant.config.NotificationSenderManagementService;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.HashMap;
import java.util.Map;

/**
 * SMS Notification Handler service component's value holder.
 */
@SuppressFBWarnings({"EI_EXPOSE_RE", "MS_EXPOSE_REP", "EI_EXPOSE_REP2"})
public class SMSNotificationHandlerDataHolder {

    private static final SMSNotificationHandlerDataHolder instance = new SMSNotificationHandlerDataHolder();

    private NotificationTemplateManager notificationTemplateManager;
    private NotificationSenderManagementService notificationSenderManagementService;
    private OrganizationManager organizationManager;
    private RealmService realmService;
    private final Map<String, Provider> providers = new HashMap<>();

    private SMSNotificationHandlerDataHolder() {
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

    public void setNotificationTemplateManager(NotificationTemplateManager notificationTemplateManager) {

        this.notificationTemplateManager = notificationTemplateManager;
    }

    public NotificationTemplateManager getNotificationTemplateManager() {

        return notificationTemplateManager;
    }

    public OrganizationManager getOrganizationManager() {

        return organizationManager;
    }

    public void setOrganizationManager(OrganizationManager organizationManager) {

        this.organizationManager = organizationManager;
    }

    public RealmService getRealmService() {
        return realmService;
    }

    public void setRealmService(RealmService realmService) {
        this.realmService = realmService;
    }
}
