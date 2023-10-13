/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com). All Rights Reserved.
 *
 * This software is the property of WSO2 LLC. and its suppliers, if any.
 * Dissemination of any information or reproduction of any material contained
 * herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
 * You may not alter or remove any copyright or other notice from copies of this content.
 *
 */

package org.wso2.carbon.identity.local.auth.authenticator.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.identity.local.auth.authenticator.SMSOTPAuthenticator;
import org.wso2.carbon.identity.local.auth.authenticator.connector.SmsOTPAuthenticatorConfigImpl;

/**
 * SMS OTP service component.
 */
@Component(
        name = "identity.local.auth.sms.otp.component",
        immediate = true
)
public class AuthenticatorServiceComponent {

    private static final Log log = LogFactory.getLog(AuthenticatorServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        try {
            BundleContext bundleContext = context.getBundleContext();
            bundleContext.registerService(IdentityConnectorConfig.class.getName(), new SmsOTPAuthenticatorConfigImpl(),
                    null);
            bundleContext.registerService(ApplicationAuthenticator.class.getName(), new SMSOTPAuthenticator(),
                    null);
            if (log.isDebugEnabled()) {
                log.debug("SMS OTP authenticator is activated");
            }
        } catch (Throwable e) {
            log.error("Error while activating the SMS OTP authenticator", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        if (log.isDebugEnabled()) {
            log.debug("SMS OTP authenticator is deactivated");
        }
    }

    @Reference(
            name = "RealmService",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        AuthenticatorDataHolder.setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        AuthenticatorDataHolder.setRealmService(null);
    }

    @Reference(
            name = "AccountLockService",
            service = org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetAccountLockService"
    )
    protected void setAccountLockService(AccountLockService accountLockService) {

        AuthenticatorDataHolder.setAccountLockService(accountLockService);
    }

    protected void unsetAccountLockService(AccountLockService accountLockService) {

        AuthenticatorDataHolder.setAccountLockService(null);
    }

    @Reference(
            name = "IdentityGovernanceService",
            service = org.wso2.carbon.identity.governance.IdentityGovernanceService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityGovernanceService")
    protected void setIdentityGovernanceService(IdentityGovernanceService idpManager) {

        AuthenticatorDataHolder.setIdentityGovernanceService(idpManager);
    }

    protected void unsetIdentityGovernanceService(IdentityGovernanceService idpManager) {

        AuthenticatorDataHolder.setIdentityGovernanceService(null);
    }


    @Reference(
            name = "EventMgtService",
            service = org.wso2.carbon.identity.event.services.IdentityEventService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityEventService")
    protected void setIdentityEventService(IdentityEventService eventService) {

        AuthenticatorDataHolder.setIdentityEventService(eventService);
    }

    protected void unsetIdentityEventService(IdentityEventService eventService) {

        AuthenticatorDataHolder.setIdentityEventService(null);
    }

    @Reference(
            name = "claim.meta.mgt.service",
            service = ClaimMetadataManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetClaimMetaMgtService")
    protected void setClaimMetaMgtService(ClaimMetadataManagementService claimMetaMgtService) {

        AuthenticatorDataHolder.setClaimMetadataManagementService(claimMetaMgtService);
    }

    protected void unsetClaimMetaMgtService(ClaimMetadataManagementService claimMetaMgtService) {

        AuthenticatorDataHolder.setClaimMetadataManagementService(null);
    }

    @Reference(
            name = "org.wso2.carbon.idp.mgt.IdpManager",
            service = IdpManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityProviderManagementService"
    )
    protected void setIdentityProviderManagementService(IdpManager idpManager) {

        AuthenticatorDataHolder.setIdpManager(idpManager);
    }

    protected void unsetIdentityProviderManagementService(IdpManager idpManager) {

        AuthenticatorDataHolder.setIdpManager(null);
    }

    @Reference(
            name = "org.wso2.carbon.application.mgt.ApplicationManagementService",
            service = ApplicationManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetApplicationManagementService"
    )
    protected void setApplicationManagementService(ApplicationManagementService applicationManagementService) {

        AuthenticatorDataHolder.setApplicationManagementService(applicationManagementService);
    }

    protected void unsetApplicationManagementService(ApplicationManagementService applicationManagementService) {

        AuthenticatorDataHolder.setApplicationManagementService(null);
    }

    @Reference(
            name = "resource.configuration.manager",
            service = org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unregisterConfigurationManager"
    )
    protected void registerConfigurationManager(ConfigurationManager configurationManager) {

        AuthenticatorDataHolder.setConfigurationManager(configurationManager);
    }

    protected void unregisterConfigurationManager(ConfigurationManager configurationManager) {

        AuthenticatorDataHolder.setConfigurationManager(null);
    }
}
