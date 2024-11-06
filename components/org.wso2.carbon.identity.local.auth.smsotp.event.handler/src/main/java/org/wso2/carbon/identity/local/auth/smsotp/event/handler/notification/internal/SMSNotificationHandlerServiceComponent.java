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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.governance.service.notification.NotificationTemplateManager;
import org.wso2.carbon.identity.local.auth.smsotp.event.handler.notification.SMSNotificationHandler;
import org.wso2.carbon.identity.local.auth.smsotp.provider.Provider;
import org.wso2.carbon.identity.notification.sender.tenant.config.NotificationSenderManagementService;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * SMS Notification Handler service component.
 */
@Component(
        name = "identity.local.auth.smsotp.event.handler.notification",
        immediate = true)
public class SMSNotificationHandlerServiceComponent {

    private static final Log LOG = LogFactory.getLog(SMSNotificationHandlerServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        try {
            context.getBundleContext().registerService(AbstractEventHandler.class.getName(),
                    new SMSNotificationHandler(), null);
        } catch (Throwable e) {
            LOG.error("Error occurred while activating SMS Notification Handler Service Component", e);
            return;
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("SMS Notification Handler service is activated");
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("SMS Notification Handler service is de-activated");
        }
    }

    @Reference(
            name = "org.wso2.carbon.identity.notification.sender.tenant.config",
            service = NotificationSenderManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetNotificationSenderManagementService"
    )
    protected void setNotificationSenderManagementService(
            NotificationSenderManagementService notificationSenderManagementService) {

        SMSNotificationHandlerDataHolder.getInstance()
                .setNotificationSenderManagementService(notificationSenderManagementService);
    }

    protected void unsetNotificationSenderManagementService(
            NotificationSenderManagementService notificationSenderManagementService) {

        SMSNotificationHandlerDataHolder.getInstance().setNotificationSenderManagementService(null);
    }

    @Reference(
            name = "org.wso2.carbon.identity.local.auth.smsotp.provider",
            service = Provider.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetProvider"
    )
    protected void setProvider(Provider provider) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Provider: " + provider.getName() + " is registered.");
        }
        SMSNotificationHandlerDataHolder.getInstance().addProvider(provider.getName(), provider);
    }

    protected void unsetProvider(Provider provider) {

        SMSNotificationHandlerDataHolder.getInstance().removeProvider(provider.getName());
    }

    @Reference(name = "notificationTemplateManager.service",
            service = org.wso2.carbon.identity.governance.service.notification.NotificationTemplateManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetNotificationTemplateManager")
    protected void setNotificationTemplateManager(NotificationTemplateManager notificationTemplateManager) {

        LOG.debug("Setting the Notification Template Manager");
        SMSNotificationHandlerDataHolder.getInstance().setNotificationTemplateManager(notificationTemplateManager);
    }

    protected void unsetNotificationTemplateManager(NotificationTemplateManager notificationTemplateManager) {

        LOG.debug("UnSetting the Notification Email Template Manager");
        SMSNotificationHandlerDataHolder.getInstance().setNotificationTemplateManager(null);
    }

    @Reference(name = "identity.organization.management.component",
            service = OrganizationManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationManager")
    protected void setOrganizationManager(OrganizationManager organizationManager) {

        LOG.debug("Setting the Organization Manager");
        SMSNotificationHandlerDataHolder.getInstance().setOrganizationManager(organizationManager);
    }

    protected void unsetOrganizationManager(OrganizationManager organizationManager) {

        LOG.debug("UnSetting the Organization Manager");
        SMSNotificationHandlerDataHolder.getInstance().setOrganizationManager(null);
    }

    @Reference(
            name = "realm.service",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        LOG.debug("Setting the Realm Service");
        SMSNotificationHandlerDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        LOG.debug("UnSetting the Realm Service");
        SMSNotificationHandlerDataHolder.getInstance().setRealmService(null);
    }
}
