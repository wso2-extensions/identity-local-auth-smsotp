/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com). All Rights Reserved.
 *
 * This software is the property of WSO2 LLC. and its suppliers, if any.
 * Dissemination of any information or reproduction of any material contained
 * herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
 * You may not alter or remove any copyright or other notice from copies of this content.
 *
 */

package org.wso2.carbon.identity.local.auth.authenticator;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticatorUtil;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.*;
import org.wso2.carbon.identity.auth.otp.core.AbstractOTPAuthenticator;
import org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.auth.otp.core.model.OTP;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.governance.service.notification.NotificationChannels;
import org.wso2.carbon.identity.local.auth.authenticator.constant.SmsOTPConstants;
import org.wso2.carbon.identity.local.auth.authenticator.exception.SmsOTPAuthenticatorServerException;
import org.wso2.carbon.identity.local.auth.authenticator.internal.AuthenticatorDataHolder;
import org.wso2.carbon.identity.local.auth.authenticator.util.AuthenticatorUtils;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants.AuthenticationScenarios.*;
import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.*;
import static org.wso2.carbon.identity.event.IdentityEventConstants.Event.POST_NON_BASIC_AUTHENTICATION;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.*;
import static org.wso2.carbon.user.core.UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME;

/**
 * This class contains the implementation of sms OTP authenticator.
 */
public class SMSOTPAuthenticator extends AbstractOTPAuthenticator implements LocalApplicationAuthenticator {

    private static final Log log = LogFactory.getLog(SMSOTPAuthenticator.class);
    private static final long serialVersionUID = 850244886656426295L;

    @Override
    public boolean canHandle(HttpServletRequest request) {

        if (log.isDebugEnabled()) {
            log.debug("Inside SMSOTPAuthenticator canHandle method and check the existence of mobile number and " +
                    "otp code");
        }
        return ((StringUtils.isNotEmpty(request.getParameter(SmsOTPConstants.RESEND))
                && StringUtils.isEmpty(request.getParameter(SmsOTPConstants.CODE)))
                || StringUtils.isNotEmpty(request.getParameter(SmsOTPConstants.CODE))
                || StringUtils.isNotEmpty(request.getParameter(SmsOTPConstants.MOBILE_NUMBER)));
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        return request.getRequestedSessionId();
    }

    @Override
    public String getFriendlyName() {

        return SmsOTPConstants.SMS_OTP_AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {

        return SmsOTPConstants.SMS_OTP_AUTHENTICATOR_NAME;
    }

    @Override
    public int getOTPLength(String tenantDomain) throws AuthenticationFailedException {

        try {
            String configuredOTPLength = AuthenticatorUtils
                    .getSmsAuthenticatorConfig(SmsOTPConstants.ConnectorConfig.SMS_OTP_LENGTH, tenantDomain);
            if (NumberUtils.isNumber(configuredOTPLength)) {
                return Integer.parseInt(configuredOTPLength);
            }
            return SmsOTPConstants.DEFAULT_OTP_LENGTH;
        } catch (SmsOTPAuthenticatorServerException exception) {
            throw handleAuthErrorScenario(SmsOTPConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_CONFIG);
        }
    }

    @Override
    public void handleOtpVerificationFail(AuthenticatedUser user) throws AuthenticationFailedException {

        UserStoreManager userStoreManager = getUserStoreManager(user);
        // Add required meta properties to the event.
        Map<String, Object> metaProperties = new HashMap<>();
        metaProperties.put(AUTHENTICATOR_NAME, SmsOTPConstants.SMS_OTP_AUTHENTICATOR_NAME);
        metaProperties.put(PROPERTY_FAILED_LOGIN_ATTEMPTS_CLAIM, SmsOTPConstants.Claims.SMS_OTP_FAILED_ATTEMPTS_CLAIM);
        metaProperties.put(USER_STORE_MANAGER, userStoreManager);
        metaProperties.put(OPERATION_STATUS, false);

        triggerEvent(POST_NON_BASIC_AUTHENTICATION, user, metaProperties);
    }

    @Override
    public void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                              AuthenticationContext context) throws AuthenticationFailedException {

        AuthenticatedUser authenticatedUserFromContext = getAuthenticatedUserFromContext(context);
        String applicationTenantDomain = context.getTenantDomain();

        // We need to identify the username that the server is using to identify the user. This is needed to handle
        // federated scenarios, since for federated users, the username in the authentication context is not same as the
        // username when the user is provisioned to the server.
        String mappedLocalUsername = getMappedLocalUsername(authenticatedUserFromContext, context);

        // If the mappedLocalUsername is blank, that means this is an initial login attempt by a non-provisioned
        // federated user.
        boolean isInitialFederationAttempt = StringUtils.isBlank(mappedLocalUsername);
        AuthenticatedUser authenticatingUser = resolveAuthenticatingUser(authenticatedUserFromContext,
                mappedLocalUsername, applicationTenantDomain, isInitialFederationAttempt);
        if (!isInitialFederationAttempt && AuthenticatorUtils.isAccountLocked(authenticatingUser)) {
            throw handleAuthErrorScenario(SmsOTPConstants.ErrorMessages.ERROR_CODE_USER_ACCOUNT_LOCKED,
                    authenticatingUser.getUserName());
        }
        if (StringUtils.isBlank(request.getParameter(SmsOTPConstants.CODE))) {
            throw handleInvalidCredentialsScenario(SmsOTPConstants.ErrorMessages.ERROR_CODE_EMPTY_OTP_CODE,
                    authenticatedUserFromContext.getUserName());
        }
        if (Boolean.parseBoolean(request.getParameter(SmsOTPConstants.RESEND))) {
            throw handleInvalidCredentialsScenario(SmsOTPConstants.ErrorMessages.ERROR_CODE_RETRYING_OTP_RESEND,
                    authenticatedUserFromContext.getUserName());
        }
        boolean isSuccessfulAttempt = isSuccessfulAuthAttempt(request.getParameter(SmsOTPConstants.CODE),
                applicationTenantDomain, authenticatingUser, context);
        if (isSuccessfulAttempt) {
            // It reached here means the authentication was successful.
            if (log.isDebugEnabled()) {
                log.debug(String.format("User: %s authenticated successfully via SMS OTP",
                        authenticatedUserFromContext.getUserName()));
            }
            if (!isInitialFederationAttempt) {
                // A mapped user is not available for isInitialFederationAttempt true scenario.
                resetOtpFailedAttempts(authenticatingUser);
            }
            publishPostOTPValidatedEvent(null, authenticatedUserFromContext, true,
                    false, request, context);
            return;
        }

        // Handle when the sms OTP is unsuccessful. At this point user account is not locked. Locked scenario is
        // handled from the above steps.
        if (!isInitialFederationAttempt) {
            // A mapped user is not available for isInitialFederationAttempt true scenario.
            handleOtpVerificationFail(authenticatingUser);
        }
        if (Boolean.parseBoolean(context.getProperty(SmsOTPConstants.OTP_EXPIRED).toString())) {
            publishPostOTPValidatedEvent(null, authenticatedUserFromContext, false,
                    true, request, context);
            throw handleAuthErrorScenario(SmsOTPConstants.ErrorMessages.ERROR_CODE_OTP_EXPIRED,
                    authenticatedUserFromContext.getUserName());
        } else {
            publishPostOTPValidatedEvent(null, authenticatedUserFromContext, false,
                    false, request, context);
            throw handleAuthErrorScenario(SmsOTPConstants.ErrorMessages.ERROR_CODE_OTP_INVALID,
                    authenticatedUserFromContext.getUserName());
        }
    }

    @Override
    public void resetOtpFailedAttempts(AuthenticatedUser user) throws AuthenticationFailedException {

        UserStoreManager userStoreManager = getUserStoreManager(user);
        // Add required meta properties to the event.
        Map<String, Object> metaProperties = new HashMap<>();
        metaProperties.put(AUTHENTICATOR_NAME, SmsOTPConstants.SMS_OTP_AUTHENTICATOR_NAME);
        metaProperties.put(PROPERTY_FAILED_LOGIN_ATTEMPTS_CLAIM, SmsOTPConstants.Claims.SMS_OTP_FAILED_ATTEMPTS_CLAIM);
        metaProperties.put(USER_STORE_MANAGER, userStoreManager);
        metaProperties.put(OPERATION_STATUS, true);

        triggerEvent(POST_NON_BASIC_AUTHENTICATION, user, metaProperties);
    }

    @Override
    public AuthenticatorConstants.AuthenticationScenarios resolveScenario(HttpServletRequest request,
                                                                          AuthenticationContext context) {

        if (context.isLogoutRequest()) {
            return LOGOUT;
        } else if (!context.isRetrying()
                && StringUtils.isBlank(request.getParameter(SmsOTPConstants.CODE))
                && StringUtils.isBlank(request.getParameter(SmsOTPConstants.RESEND))) {
            return INITIAL_OTP;
        } else if (context.isRetrying()
                && StringUtils.isNotBlank(request.getParameter(SmsOTPConstants.RESEND))
                && Boolean.parseBoolean(request.getParameter(SmsOTPConstants.RESEND))) {
            return RESEND_OTP;
        }
        return SUBMIT_OTP;
    }

    @Override
    public boolean retryAuthenticationEnabled() {

        return true;
    }

    @Override
    public void triggerEvent(String eventName, AuthenticatedUser user, Map<String, Object> metaProperties)
            throws AuthenticationFailedException {

        HashMap<String, Object> properties = new HashMap<>();
        properties.put(IdentityEventConstants.EventProperty.USER_NAME, user.getUserName());
        properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, user.getUserStoreDomain());
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, user.getTenantDomain());
        if (metaProperties != null) {
            for (Map.Entry<String, Object> metaProperty : metaProperties.entrySet()) {
                if (StringUtils.isNotBlank(metaProperty.getKey()) && metaProperty.getValue() != null) {
                    properties.put(metaProperty.getKey(), metaProperty.getValue());
                }
            }
        }
        Event identityMgtEvent = new Event(eventName, properties);
        try {
            AuthenticatorDataHolder.getIdentityEventService().handleEvent(identityMgtEvent);
        } catch (IdentityEventException e) {
            throw handleAuthErrorScenario(SmsOTPConstants.ErrorMessages.ERROR_CODE_ERROR_TRIGGERING_EVENT, e, eventName,
                    user.getUserName());
        }
    }

    @Override
    protected String getAuthenticatorErrorPrefix() {
        return "";
    }

    @Override
    protected String getErrorPageURL(AuthenticationContext authenticationContext)
            throws AuthenticationFailedException {
        return AuthenticatorUtils.getSMSOTPErrorPageUrl();
    }

    @Override
    protected String getMaskedUserClaimValue(AuthenticatedUser authenticatedUser, String tenantDomain,
                                             boolean isInitialFederationAttempt,
                                             AuthenticationContext authenticationContext)
            throws AuthenticationFailedException {

        String mobile = resolveMobileNoOfAuthenticatedUser(authenticatedUser, tenantDomain, authenticationContext,
                isInitialFederationAttempt);
        int screenAttributeLength = mobile.length();
        String screenValue = mobile.substring(screenAttributeLength - SmsOTPConstants.MASKED_DIGITS,
                screenAttributeLength);
        String hiddenScreenValue = mobile.substring(0, screenAttributeLength - SmsOTPConstants.MASKED_DIGITS);
        screenValue = new String(new char[hiddenScreenValue.length()]).
                replace("\0", SmsOTPConstants.MOBILE_NUMBER_MASKING_CHARACTER).concat(screenValue);
        return screenValue;
    }

    @Override
    protected String getOTPLoginPageURL(AuthenticationContext authenticationContext)
            throws AuthenticationFailedException {
        return AuthenticatorUtils.getSMSOTPLoginPageUrl();
    }

    @Override
    protected void publishPostOTPGeneratedEvent(OTP otp, AuthenticatedUser authenticatedUser,
                                                HttpServletRequest httpServletRequest,
                                                AuthenticationContext authenticationContext)
            throws AuthenticationFailedException {

        String tenantDomain = authenticationContext.getTenantDomain();
        Map<String, Object> eventProperties = new HashMap<>();

        try {
            eventProperties.put(IdentityEventConstants.EventProperty.CORRELATION_ID,
                    authenticationContext.getCallerSessionKey());
            eventProperties.put(IdentityEventConstants.EventProperty.APPLICATION_ID,
                    getApplicationId(authenticationContext.getServiceProviderName(),
                            authenticationContext.getTenantDomain()));
            eventProperties.put(IdentityEventConstants.EventProperty.TENANT_ID,
                    IdentityTenantUtil.getTenantId(tenantDomain));
            eventProperties.put(SmsOTPConstants.PROVIDER, getProviderType(tenantDomain));
            eventProperties.put(IdentityEventConstants.EventProperty.USER_ID, authenticatedUser.getUserId());
            eventProperties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN,
                    authenticatedUser.getUserStoreDomain());
            if (StringUtils.isNotBlank(httpServletRequest.getParameter(SmsOTPConstants.RESEND))) {
                eventProperties.put(IdentityEventConstants.EventProperty.RESEND_CODE,
                        httpServletRequest.getParameter(SmsOTPConstants.RESEND));
            } else {
                eventProperties.put(IdentityEventConstants.EventProperty.RESEND_CODE, false);
            }
            // Add OTP generated time and OTP expiry time to the event.
            Object otpGeneratedTimeProperty = authenticationContext.getProperty(SmsOTPConstants.OTP_GENERATED_TIME);
            if (otpGeneratedTimeProperty != null) {
                long otpGeneratedTime = (long) otpGeneratedTimeProperty;
                eventProperties.put(SmsOTPConstants.OTP_GENERATED_TIME, otpGeneratedTime);

                // Calculate OTP expiry time.
                long expiryTime = otpGeneratedTime + getOtpValidityPeriod(tenantDomain);
                eventProperties.put(SmsOTPConstants.ConnectorConfig.OTP_EXPIRY_TIME, expiryTime);
            }
        } catch (UserIdNotFoundException e) {
            throw handleAuthErrorScenario(SmsOTPConstants.ErrorMessages.ERROR_CODE_USER_ID_NOT_FOUND, e, (Object) null);
        }
        triggerEvent(IdentityEventConstants.Event.POST_GENERATE_SMS_OTP, authenticatedUser, eventProperties);
    }

    @Override
    protected void publishPostOTPValidatedEvent(OTP otp, AuthenticatedUser authenticatedUser,
                                                boolean isAuthenticationPassed, boolean isExpired,
                                                HttpServletRequest httpServletRequest,
                                                AuthenticationContext authenticationContext)
            throws AuthenticationFailedException {

        String tenantDomain = authenticationContext.getTenantDomain();

        Map<String, Object> eventProperties = new HashMap<>();
        eventProperties.put(IdentityEventConstants.EventProperty.CORRELATION_ID,
                authenticationContext.getCallerSessionKey());
        eventProperties.put(IdentityEventConstants.EventProperty.APPLICATION_NAME,
                authenticationContext.getServiceProviderName());
        eventProperties.put(IdentityEventConstants.EventProperty.USER_INPUT_OTP,
                httpServletRequest.getParameter(SmsOTPConstants.CODE));
        eventProperties.put(IdentityEventConstants.EventProperty.OTP_USED_TIME, System.currentTimeMillis());
        // Add otp status to the event properties.
        if (isAuthenticationPassed) {
            eventProperties.put(IdentityEventConstants.EventProperty.OTP_STATUS, SmsOTPConstants.STATUS_SUCCESS);
            eventProperties.put(IdentityEventConstants.EventProperty.GENERATED_OTP,
                    httpServletRequest.getParameter(SmsOTPConstants.CODE));
        } else {
            if (isExpired) {
                eventProperties.put(IdentityEventConstants.EventProperty.OTP_STATUS,
                        SmsOTPConstants.STATUS_OTP_EXPIRED);
                // Add generated time and expiry time info for the event.
                long otpGeneratedTime = (long) authenticationContext.getProperty(SmsOTPConstants.OTP_GENERATED_TIME);
                eventProperties.put(SmsOTPConstants.OTP_GENERATED_TIME, otpGeneratedTime);
                long expiryTime = otpGeneratedTime + getOtpValidityPeriod(tenantDomain);
                eventProperties.put(SmsOTPConstants.ConnectorConfig.OTP_EXPIRY_TIME, expiryTime);
            } else {
                eventProperties.put(IdentityEventConstants.EventProperty.OTP_STATUS,
                        SmsOTPConstants.STATUS_CODE_MISMATCH);
            }
        }
        triggerEvent(IdentityEventConstants.Event.POST_VALIDATE_SMS_OTP, authenticatedUser, eventProperties);
    }

    @Override
    protected void sendOtp(AuthenticatedUser authenticatedUser, OTP otp, boolean b,
                           HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
                           AuthenticationContext authenticationContext) throws AuthenticationFailedException {

        authenticationContext.setProperty(SmsOTPConstants.OTP_TOKEN, otp);
        authenticationContext.setProperty(SmsOTPConstants.OTP_GENERATED_TIME, System.currentTimeMillis());
        authenticationContext.setProperty(SmsOTPConstants.OTP_EXPIRED, Boolean.toString(false));

        String tenantDomain = authenticationContext.getTenantDomain();
        boolean isInitialFederationAttempt = StringUtils
                .isBlank(getMappedLocalUsername(authenticatedUser, authenticationContext));
        String mobileNumber = resolveMobileNoOfAuthenticatedUser(authenticatedUser, tenantDomain,
                authenticationContext, isInitialFederationAttempt);

        Map<String, Object> metaProperties = new HashMap<>();
        metaProperties.put(IdentityEventConstants.EventProperty.NOTIFICATION_CHANNEL,
                NotificationChannels.SMS_CHANNEL.getChannelType());
        metaProperties.put(SmsOTPConstants.ATTRIBUTE_SMS_SENT_TO, mobileNumber);
        metaProperties.put(SmsOTPConstants.OTP_TOKEN, otp);
        metaProperties.put(IdentityEventConstants.EventProperty.APPLICATION_NAME,
                authenticationContext.getServiceProviderName());
        metaProperties.put(SmsOTPConstants.ConnectorConfig.OTP_EXPIRY_TIME,
                String.valueOf(getOtpValidityPeriod(authenticationContext.getTenantDomain()) / 60000));
        metaProperties.put(SmsOTPConstants.TEMPLATE_TYPE, SmsOTPConstants.EVENT_NAME);

        triggerEvent(IdentityEventConstants.Event.TRIGGER_SMS_NOTIFICATION, authenticatedUser, metaProperties);
    }

    @Override
    protected int getMaximumResendAttempts(String tenantDomain) throws AuthenticationFailedException {

        try {
            String allowedResendCount = AuthenticatorUtils.getSmsAuthenticatorConfig(SmsOTPConstants.ConnectorConfig
                    .SMS_OTP_RESEND_ATTEMPTS_COUNT, tenantDomain);
            if (NumberUtils.isNumber(allowedResendCount)) {
                return Integer.parseInt(allowedResendCount);
            }
            return SmsOTPConstants.DEFAULT_OTP_RESEND_ATTEMPTS;
        } catch (SmsOTPAuthenticatorServerException exception) {
            throw handleAuthErrorScenario(SmsOTPConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_CONFIG);
        }
    }

    private String getApplicationId(String applicationName, String tenantDomain) throws AuthenticationFailedException {

        try {
            ServiceProvider serviceProvider = AuthenticatorDataHolder.getApplicationManagementService().
                    getServiceProvider(applicationName, tenantDomain);
            return serviceProvider.getApplicationResourceId();
        } catch (IdentityApplicationManagementException e) {
            throw handleAuthErrorScenario(SmsOTPConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_APPLICATION, e,
                    (Object) null);
        }
    }

    /**
     * Get the authenticated user by iterating though auth steps.
     *
     * @param context AuthenticationContext.
     * @return AuthenticatedUser.
     * @throws AuthenticationFailedException If no authenticated user was found.
     */
    private AuthenticatedUser getAuthenticatedUserFromContext(AuthenticationContext context)
            throws AuthenticationFailedException {

        Map<Integer, StepConfig> stepConfigMap = context.getSequenceConfig().getStepMap();
        for (StepConfig stepConfig : stepConfigMap.values()) {
            AuthenticatedUser user = stepConfig.getAuthenticatedUser();
            if (stepConfig.isSubjectAttributeStep()) {
                if (user == null) {
                    throw handleAuthErrorScenario(SmsOTPConstants.ErrorMessages.ERROR_CODE_NO_USER_FOUND);
                }
                AuthenticatedUser authenticatedUser = new AuthenticatedUser(user);
                if (StringUtils.isBlank(authenticatedUser.toFullQualifiedUsername())) {
                    if (log.isDebugEnabled()) {
                        log.debug("Username can not be empty");
                    }
                    throw handleAuthErrorScenario(SmsOTPConstants.ErrorMessages.ERROR_CODE_EMPTY_USERNAME);
                }
                return authenticatedUser;
            }
        }
        // If authenticated user cannot be found from the previous steps.
        throw handleAuthErrorScenario(SmsOTPConstants.ErrorMessages.ERROR_CODE_NO_USER_FOUND);
    }

    /**
     * Retrieve the claim dialect of the federated authenticator.
     *
     * @param context AuthenticationContext.
     * @return The claim dialect of the federated authenticator.
     */
    private String getFederatedAuthenticatorDialect(AuthenticationContext context) {

        String dialect = null;
        Map<Integer, StepConfig> stepConfigMap = context.getSequenceConfig().getStepMap();
        for (StepConfig stepConfig : stepConfigMap.values()) {
            if (stepConfig.isSubjectAttributeStep()) {
                dialect = stepConfig.getAuthenticatedAutenticator().getApplicationAuthenticator().getClaimDialectURI();
                break;
            }
        }
        return dialect;
    }

    /**
     * Get the JIT provisioning userStore domain of the authenticated user.
     *
     * @param user         AuthenticatedUser.
     * @param tenantDomain Tenant domain.
     * @return JIT provisioning userStore domain.
     * @throws AuthenticationFailedException If an error occurred.
     */
    private String getFederatedUserStoreDomain(AuthenticatedUser user, String tenantDomain)
            throws AuthenticationFailedException {

        String federatedIdp = user.getFederatedIdPName();
        IdentityProvider idp = getIdentityProvider(federatedIdp, tenantDomain);
        JustInTimeProvisioningConfig provisioningConfig = idp.getJustInTimeProvisioningConfig();
        if (provisioningConfig == null) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("No JIT provisioning configs for idp: %s in tenant: %s", federatedIdp,
                        tenantDomain));
            }
            return null;
        }
        String provisionedUserStore = provisioningConfig.getProvisioningUserStore();
        if (log.isDebugEnabled()) {
            log.debug(String.format("Setting user store: %s as the provisioning user store for user: %s in tenant: %s",
                    provisionedUserStore, user.getUserName(), tenantDomain));
        }
        return provisionedUserStore;
    }

    private IdentityProvider getIdentityProvider(String idpName, String tenantDomain) throws
            AuthenticationFailedException {

        try {
            IdentityProvider idp = AuthenticatorDataHolder.getIdpManager().getIdPByName(idpName, tenantDomain);
            if (idp == null) {
                throw handleAuthErrorScenario(SmsOTPConstants.ErrorMessages.ERROR_CODE_INVALID_FEDERATED_AUTHENTICATOR,
                        idpName, tenantDomain);
            }
            return idp;
        } catch (IdentityProviderManagementException e) {
            throw handleAuthErrorScenario(SmsOTPConstants.ErrorMessages
                    .ERROR_CODE_ERROR_GETTING_FEDERATED_AUTHENTICATOR, idpName, tenantDomain);
        }
    }

    /**
     * Retrieve the provisioned username of the authenticated user. If this is a federated scenario, the
     * authenticated username will be same as the username in context. If the flow is for a JIT provisioned user, the
     * provisioned username will be returned.
     *
     * @param authenticatedUser AuthenticatedUser.
     * @param context           AuthenticationContext.
     * @return Provisioned username
     * @throws AuthenticationFailedException If an error occurred while getting the provisioned username.
     */
    private String getMappedLocalUsername(AuthenticatedUser authenticatedUser, AuthenticationContext context)
            throws AuthenticationFailedException {

        if (!authenticatedUser.isFederatedUser()) {
            return authenticatedUser.getUserName();
        }

        // If the user is federated, we need to check whether the user is already provisioned to the organization.
        String federatedUsername = FederatedAuthenticatorUtil.getLoggedInFederatedUser(context);
        if (StringUtils.isBlank(federatedUsername)) {
            throw handleAuthErrorScenario(SmsOTPConstants.ErrorMessages.ERROR_CODE_NO_FEDERATED_USER);
        }
        String associatedLocalUsername =
                FederatedAuthenticatorUtil.getLocalUsernameAssociatedWithFederatedUser(MultitenantUtils.
                        getTenantAwareUsername(federatedUsername), context);
        if (StringUtils.isNotBlank(associatedLocalUsername)) {
            return associatedLocalUsername;
        }
        return null;
    }

    /**
     * Retrieve the mobile number of the federated user.
     *
     * @param user         AuthenticatedUser.
     * @param tenantDomain Application tenant domain.
     * @param context      AuthenticationContext.
     * @return Mobile number of the federated user.
     * @throws AuthenticationFailedException If an error occurred while getting the mobile number of the federated user.
     */
    private String getMobileNoForFederatedUser(AuthenticatedUser user, String tenantDomain,
                                               AuthenticationContext context) throws AuthenticationFailedException {

        String mobileAttributeKey = resolveMobileNoAttribute(user, tenantDomain, context);
        Map<ClaimMapping, String> userAttributes = user.getUserAttributes();
        String mobile = null;
        for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
            String key = String.valueOf(entry.getKey().getLocalClaim().getClaimUri());
            if (key.equals(mobileAttributeKey)) {
                String value = entry.getValue();
                mobile = String.valueOf(value);
                break;
            }
        }
        return mobile;
    }

    private long getOtpValidityPeriod(String tenantDomain) throws AuthenticationFailedException {

        try {
            String value = AuthenticatorUtils.getSmsAuthenticatorConfig(SmsOTPConstants.ConnectorConfig.OTP_EXPIRY_TIME,
                    tenantDomain);
            if (StringUtils.isBlank(value)) {
                return SmsOTPConstants.DEFAULT_SMS_OTP_VALIDITY_IN_MILLIS;
            }
            long validityTime;
            try {
                validityTime = Long.parseLong(value);
            } catch (NumberFormatException e) {
                log.error(String.format("Email OTP validity period value: %s configured in tenant : %s is not a " +
                                "number. Therefore, default validity period: %s (milli-seconds) will be used", value,
                        tenantDomain, SmsOTPConstants.DEFAULT_SMS_OTP_VALIDITY_IN_MILLIS));
                return SmsOTPConstants.DEFAULT_SMS_OTP_VALIDITY_IN_MILLIS;
            }
            // We don't need to send tokens with infinite validity.
            if (validityTime < 0) {
                log.error(String.format("Email OTP validity period value: %s configured in tenant : %s cannot be a " +
                        "negative number. Therefore, default validity period: %s (milli-seconds) will " +
                        "be used", value, tenantDomain, SmsOTPConstants.DEFAULT_SMS_OTP_VALIDITY_IN_MILLIS));
                return SmsOTPConstants.DEFAULT_SMS_OTP_VALIDITY_IN_MILLIS;
            }
            // Converting to milliseconds since the config is provided in seconds.
            return validityTime * 1000;
        } catch (SmsOTPAuthenticatorServerException exception) {
            throw handleAuthErrorScenario(SmsOTPConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_CONFIG, exception);
        }
    }

    private String getProviderType(String tenantDomain) {

        try {
            Resource resource = AuthenticatorDataHolder.getConfigurationManager().getResource(SmsOTPConstants.PUBLISHER,
                    SmsOTPConstants.SMS_PROVIDER);
            if (resource != null) {
                return SmsOTPConstants.ProviderTypes.CUSTOM;
            }
        } catch (ConfigurationManagementException e) {
            if (e.getErrorCode()
                    .equals(ERROR_CODE_FEATURE_NOT_ENABLED.getCode())) {
                log.warn("Configuration store is disabled. Super tenant configurations are using for the tenant "
                        + "domain: " + tenantDomain);
            } else if (e.getErrorCode()
                    .equals(ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getCode())) {
                log.warn("Configuration store does not contain resource SMSPublisher. Super "
                        + "tenant configurations are using for the tenant domain: " + tenantDomain);
            } else if (e.getErrorCode()
                    .equals(ERROR_CODE_RESOURCE_TYPE_DOES_NOT_EXISTS.getCode())) {
                log.warn("Configuration store does not contain  publisher resource type. Super "
                        + "tenant configurations are using for the tenant domain: " + tenantDomain);
            } else {
                log.error("Error occurred while fetching the tenant specific publisher configuration files " +
                        "from configuration store for the tenant domain: " + tenantDomain, e);
            }
        }
        return SmsOTPConstants.ProviderTypes.DEFAULT;
    }

    /**
     * Get the UserRealm for the user given user.
     *
     * @param tenantDomain Tenant domain.
     * @return UserRealm.
     * @throws AuthenticationFailedException If an error occurred while getting the UserRealm.
     */
    private UserRealm getTenantUserRealm(String tenantDomain) throws AuthenticationFailedException {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        UserRealm userRealm;
        try {
            userRealm = (AuthenticatorDataHolder.getRealmService()).getTenantUserRealm(tenantId);
        } catch (UserStoreException e) {
            throw handleAuthErrorScenario(SmsOTPConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_USER_REALM, e,
                    tenantDomain);
        }
        if (userRealm == null) {
            throw handleAuthErrorScenario(SmsOTPConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_USER_REALM,
                    tenantDomain);
        }
        return userRealm;
    }

    /**
     * Get user claim value.
     *
     * @param authenticatedUser AuthenticatedUser.
     * @return User claim value.
     * @throws AuthenticationFailedException If an error occurred while getting the claim value.
     */
    private String getUserClaimValueFromUserStore(AuthenticatedUser authenticatedUser)
            throws AuthenticationFailedException {

        UserStoreManager userStoreManager = getUserStoreManager(authenticatedUser);
        try {
            Map<String, String> claimValues =
                    userStoreManager.getUserClaimValues(MultitenantUtils.getTenantAwareUsername(
                            authenticatedUser.toFullQualifiedUsername()),
                            new String[]{SmsOTPConstants.Claims.MOBILE_CLAIM}, null);
            return claimValues.get(SmsOTPConstants.Claims.MOBILE_CLAIM);
        } catch (UserStoreException e) {
            throw handleAuthErrorScenario(SmsOTPConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_MOBILE_NUMBER, e,
                    authenticatedUser.getUserName());
        }
    }

    /**
     * Get UserStoreManager for the given user.
     *
     * @param authenticatedUser AuthenticatedUser.
     * @return UserStoreManager.
     * @throws AuthenticationFailedException If an error occurred while getting the UserStoreManager.
     */
    private UserStoreManager getUserStoreManager(AuthenticatedUser authenticatedUser)
            throws AuthenticationFailedException {

        UserRealm userRealm = getTenantUserRealm(authenticatedUser.getTenantDomain());
        String username = MultitenantUtils.getTenantAwareUsername(authenticatedUser.toFullQualifiedUsername());
        String userStoreDomain = authenticatedUser.getUserStoreDomain();
        try {
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            if (userStoreManager == null) {
                throw handleAuthErrorScenario(SmsOTPConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_USER_STORE_MANAGER,
                        username);
            }
            if (StringUtils.isBlank(userStoreDomain) || PRIMARY_DEFAULT_DOMAIN_NAME.equals(userStoreDomain)) {
                return userStoreManager;
            }
            return ((AbstractUserStoreManager) userStoreManager).getSecondaryUserStoreManager(userStoreDomain);
        } catch (UserStoreException e) {
            throw handleAuthErrorScenario(SmsOTPConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_USER_STORE_MANAGER, e,
                    username);
        }
    }

    private AuthenticationFailedException handleAuthErrorScenario(SmsOTPConstants.ErrorMessages error) {

        return handleAuthErrorScenario(error, (Object) null);
    }

    private AuthenticationFailedException handleAuthErrorScenario(SmsOTPConstants.ErrorMessages error,
                                                                  Object... data) {

        return handleAuthErrorScenario(error, null, data);
    }

    /**
     * Handle the scenario by returning AuthenticationFailedException which has the details of the error scenario.
     *
     * @param error     {@link SmsOTPConstants.ErrorMessages} error message.
     * @param throwable Throwable.
     * @param data      Additional data related to the scenario.
     * @return AuthenticationFailedException.
     */
    private AuthenticationFailedException handleAuthErrorScenario(SmsOTPConstants.ErrorMessages error,
                                                                  Throwable throwable, Object... data) {

        String message = error.getMessage();
        if (data != null) {
            message = String.format(message, data);
        }
        String errorCode = error.getCode();
        if (throwable == null) {
            return new AuthenticationFailedException(errorCode, message);
        }
        return new AuthenticationFailedException(errorCode, message, throwable);
    }

    private InvalidCredentialsException handleInvalidCredentialsScenario(SmsOTPConstants.ErrorMessages error,
                                                                         String... data) {

        String message = error.getMessage();
        if (data != null) {
            message = String.format(message, (Object) data);
        }
        if (log.isDebugEnabled()) {
            log.debug(message);
        }
        return new InvalidCredentialsException(error.getCode(), message);
    }

    /**
     * Checks whether otp is Expired or not.
     *
     * @param tenantDomain Tenant domain.
     * @param context      Authentication Context.
     */
    private boolean isOtpExpired(String tenantDomain, AuthenticationContext context)
            throws AuthenticationFailedException {

        if (context.getProperty(SmsOTPConstants.OTP_GENERATED_TIME) == null) {
            throw handleAuthErrorScenario(SmsOTPConstants.ErrorMessages.ERROR_CODE_EMPTY_GENERATED_TIME);
        }
        long generatedTime = (long) context.getProperty(SmsOTPConstants.OTP_GENERATED_TIME);
        long expireTime = getOtpValidityPeriod(tenantDomain);
        return System.currentTimeMillis() >= generatedTime + expireTime;
    }

    /**
     * Check whether the given OTP value is valid.
     *
     * @param userToken    User given otp.
     * @param tenantDomain Tenant domain.
     * @param user         AuthenticatedUser.
     * @param context      AuthenticationContext.
     * @return True if the OTP is valid.
     * @throws AuthenticationFailedException If error occurred while validating the OTP.
     */
    private boolean isSuccessfulAuthAttempt(String userToken, String tenantDomain, AuthenticatedUser user,
                                            AuthenticationContext context) throws AuthenticationFailedException {

        String tokenInContext = (String) context.getProperty(SmsOTPConstants.OTP_TOKEN);
        if (StringUtils.isBlank(userToken)) {
            throw handleAuthErrorScenario(SmsOTPConstants.ErrorMessages.ERROR_CODE_EMPTY_OTP_CODE, user.getUserName());
        }
        if (StringUtils.isBlank(tokenInContext)) {
            throw handleAuthErrorScenario(SmsOTPConstants.ErrorMessages.ERROR_CODE_EMPTY_OTP_CODE_IN_CONTEXT,
                    user.getUserName());
        }
        boolean isExpired = isOtpExpired(tenantDomain, context);
        if (userToken.equals(tokenInContext)) {
            if (isExpired) {
                context.setProperty(SmsOTPConstants.OTP_EXPIRED, Boolean.toString(true));
                return false;
            } else {
                context.setProperty(SmsOTPConstants.OTP_EXPIRED, Boolean.toString(false));
                context.setProperty(SmsOTPConstants.OTP_TOKEN, StringUtils.EMPTY);
                context.setProperty(SmsOTPConstants.OTP_GENERATED_TIME, StringUtils.EMPTY);
                context.setProperty(SmsOTPConstants.OTP_RESEND_ATTEMPTS, StringUtils.EMPTY);
                context.setSubject(user);
                return true;
            }
        }
        // This is the OTP mismatched scenario.
        if (log.isDebugEnabled()) {
            log.debug("Invalid OTP given by the user: " + user.getUserName());
        }
        return false;
    }

    /**
     * Identify the AuthenticatedUser that the authenticator trying to authenticate. This needs to be done to
     * identify the locally mapped user for federated authentication scenarios.
     *
     * @param authenticatedUserInContext AuthenticatedUser retrieved from context.
     * @param mappedLocalUsername        Mapped local username if available.
     * @param tenantDomain               Application tenant domain.
     * @param isInitialFederationAttempt Whether auth attempt by a not JIT provisioned federated user.
     * @return AuthenticatedUser that the authenticator trying to authenticate.
     * @throws AuthenticationFailedException If an error occurred.
     */
    private AuthenticatedUser resolveAuthenticatingUser(AuthenticatedUser authenticatedUserInContext,
                                                        String mappedLocalUsername,
                                                        String tenantDomain, boolean isInitialFederationAttempt)
            throws AuthenticationFailedException {

        // This is a federated initial authentication scenario.
        if (isInitialFederationAttempt) {
            return authenticatedUserInContext;
        }
        // Handle local users.
        if (!authenticatedUserInContext.isFederatedUser()) {
            return authenticatedUserInContext;
        }

        // At this point, the authenticating user is in our system but has a different mapped username compared to the
        // identifier that is in the authentication context. Therefore, we need to have a new AuthenticatedUser object
        // with the mapped local username to identify the user.
        AuthenticatedUser authenticatingUser = new AuthenticatedUser(authenticatedUserInContext);
        authenticatingUser.setUserName(mappedLocalUsername);
        authenticatingUser.setUserStoreDomain(getFederatedUserStoreDomain(authenticatedUserInContext, tenantDomain));
        return authenticatingUser;
    }

    /**
     * Resolve the mobile number attribute for the federated user by evaluating the federated IDP.
     *
     * @param user         AuthenticatedUser.
     * @param tenantDomain Application tenant domain.
     * @param context      AuthenticationContext.
     * @return mobile number attribute.
     * @throws AuthenticationFailedException If an error occurred while resolving mobile number attribute.
     */
    private String resolveMobileNoAttribute(AuthenticatedUser user, String tenantDomain,
                                            AuthenticationContext context) throws AuthenticationFailedException {

        String dialect = getFederatedAuthenticatorDialect(context);
        if (SmsOTPConstants.OIDC_DIALECT_URI.equals(dialect)) {
            return SmsOTPConstants.MOBILE_ATTRIBUTE_KEY;
        }
        // If the dialect is not OIDC we need to check claim mappings for the mobile claim mapped attribute.
        String idpName = user.getFederatedIdPName();
        IdentityProvider idp = getIdentityProvider(idpName, tenantDomain);
        ClaimConfig claimConfigs = idp.getClaimConfig();
        if (claimConfigs == null) {
            throw handleAuthErrorScenario(SmsOTPConstants.ErrorMessages
                    .ERROR_CODE_NO_CLAIM_CONFIGS_IN_FEDERATED_AUTHENTICATOR, idpName, tenantDomain);
        }
        ClaimMapping[] claimMappings = claimConfigs.getClaimMappings();
        if (ArrayUtils.isEmpty(claimMappings)) {
            throw handleAuthErrorScenario(SmsOTPConstants.ErrorMessages
                            .ERROR_CODE_NO_CLAIM_CONFIGS_IN_FEDERATED_AUTHENTICATOR, idpName, tenantDomain);
        }

        String mobileAttributeKey = null;
        for (ClaimMapping claimMapping : claimMappings) {
            if (SmsOTPConstants.Claims.MOBILE_CLAIM.equals(claimMapping.getLocalClaim().getClaimUri())) {
                mobileAttributeKey = claimMapping.getRemoteClaim().getClaimUri();
                break;
            }
        }
        if (StringUtils.isBlank(mobileAttributeKey)) {
            throw handleAuthErrorScenario(SmsOTPConstants.ErrorMessages.ERROR_CODE_NO_MOBILE_CLAIM_MAPPINGS,
                    idpName, tenantDomain);
        }
        return mobileAttributeKey;
    }

    /**
     * Resolve the mobile number of the authenticated user.
     *
     * @param user                       Authenticated user.
     * @param tenantDomain               Application tenant domain.
     * @param context                    AuthenticationContext.
     * @param isInitialFederationAttempt Whether auth attempt by a not JIT provisioned federated user.
     * @return Mobile number of the authenticated user.
     * @throws AuthenticationFailedException If an error occurred while resolving the mobile number.
     */
    private String resolveMobileNoOfAuthenticatedUser(AuthenticatedUser user, String tenantDomain,
                                                      AuthenticationContext context, boolean isInitialFederationAttempt)
            throws AuthenticationFailedException {

        String mobile;
        if (isInitialFederationAttempt) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Getting the mobile number of the initially federating user: %s",
                        user.getUserName()));
            }
            mobile = getMobileNoForFederatedUser(user, tenantDomain, context);
        } else {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Getting the mobile number of the local user: %s in user store: %s in " +
                        "tenant: %s", user.getUserName(), user.getUserStoreDomain(), user.getTenantDomain()));
            }
            mobile = getUserClaimValueFromUserStore(user);
        }
        return mobile;
    }
}
