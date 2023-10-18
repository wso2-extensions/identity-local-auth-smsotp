/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com). All Rights Reserved.
 *
 * This software is the property of WSO2 LLC. and its suppliers, if any.
 * Dissemination of any information or reproduction of any material contained
 * herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
 * You may not alter or remove any copyright or other notice from copies of this content.
 *
 */

package org.wso2.carbon.identity.local.auth.smsotp.provider.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.wso2.carbon.identity.local.auth.smsotp.provider.Provider;
import org.wso2.carbon.identity.local.auth.smsotp.provider.impl.CustomProvider;
import org.wso2.carbon.identity.local.auth.smsotp.provider.impl.TwilioProvider;
import org.wso2.carbon.identity.local.auth.smsotp.provider.impl.VonageProvider;

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
            context.getBundleContext().registerService(Provider.class.getName(), new TwilioProvider(), null);
            context.getBundleContext().registerService(Provider.class.getName(), new VonageProvider(), null);
            context.getBundleContext().registerService(Provider.class.getName(), new CustomProvider(), null);
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
}
