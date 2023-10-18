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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.*;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.notification.sender.tenant.config.NotificationSenderManagementService;
import org.wso2.carbon.identity.local.auth.smsotp.event.handler.notification.SMSNotificationHandler;
import org.wso2.carbon.identity.local.auth.smsotp.provider.Provider;

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
}
