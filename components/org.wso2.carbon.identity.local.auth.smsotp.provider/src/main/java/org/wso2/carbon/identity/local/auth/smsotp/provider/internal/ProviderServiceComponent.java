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

package org.wso2.carbon.identity.local.auth.smsotp.provider.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.local.auth.smsotp.provider.Provider;
import org.wso2.carbon.identity.local.auth.smsotp.provider.impl.CustomProvider;
import org.wso2.carbon.identity.local.auth.smsotp.provider.impl.TwilioProvider;
import org.wso2.carbon.identity.local.auth.smsotp.provider.impl.VonageProvider;
import org.wso2.carbon.identity.local.auth.smsotp.provider.resilience.ResilientProvider;
import org.wso2.carbon.identity.notification.sender.tenant.config.NotificationSenderManagementService;

/**
 * Service component for SMS OTP Provider.
 */
@Component(
        name = "org.wso2.carbon.identity.local.auth.smsotp.provider",
        immediate = true
)
public class ProviderServiceComponent {

    private static final Log LOG = LogFactory.getLog(ProviderServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        try {
            context.getBundleContext().registerService(Provider.class.getName(),
                    new ResilientProvider(new TwilioProvider()), null);
            context.getBundleContext().registerService(Provider.class.getName(),
                    new ResilientProvider(new VonageProvider()), null);
            context.getBundleContext().registerService(Provider.class.getName(),
                    new ResilientProvider(new CustomProvider()), null);
        } catch (Throwable e) {
            LOG.error("Error occurred while activating Provider Service Component", e);
            return;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Provider Service Component bundle activated successfully.");
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Provider Service Component bundle is deactivated.");
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

        SMSNotificationProviderDataHolder.getInstance()
                .setNotificationSenderManagementService(notificationSenderManagementService);
    }

    protected void unsetNotificationSenderManagementService(
            NotificationSenderManagementService notificationSenderManagementService) {

        SMSNotificationProviderDataHolder.getInstance().setNotificationSenderManagementService(null);
    }
}
