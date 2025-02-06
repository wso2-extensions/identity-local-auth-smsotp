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

package org.wso2.carbon.identity.local.auth.smsotp.event.handler.notification.internal;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.auth.otp.core.model.OTP;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.local.auth.smsotp.event.handler.notification.SMSNotificationConstants;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementClientException;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.user.api.Tenant;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.wso2.carbon.identity.local.auth.smsotp.event.handler.notification.SMSNotificationConstants.ACCEPTED_SMS_PLACEHOLDERS;
import static org.wso2.carbon.identity.local.auth.smsotp.event.handler.notification.SMSNotificationConstants.OTP_TOKEN_STRING_PROPERTY_NAME;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ORGANIZATION_NOT_FOUND_FOR_TENANT;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

/**
 * Utility class for SMS notifications.
 */
public class SMSNotificationUtil {

    /**
     * Replace placeholders in the SMS template with the values in the valuesMap.
     *
     * @param template          SMS template.
     * @param notificationData  All resolved notification data.
     * @return SMS body with placeholders replaced with values.
     */
    public static String replacePlaceholders(String template, Map<String, String> notificationData) {

        Map<String, String> filteredPlaceholderData = filterPlaceHolderData(notificationData);
        // Regular expression to match placeholders in the format {{placeholder-name}}
        Matcher placeHolderMatcher = Pattern.compile(SMSNotificationConstants.PLACE_HOLDER_REGEX).matcher(template);
        StringBuilder smsBody = new StringBuilder();
        while (placeHolderMatcher.find()) {
            String placeholder = placeHolderMatcher.group(1);
            String replacement = filteredPlaceholderData.get(placeholder);
            if (StringUtils.isBlank(replacement)) {
                continue;
            }
            placeHolderMatcher.appendReplacement(smsBody, Matcher.quoteReplacement(replacement));
        }
        placeHolderMatcher.appendTail(smsBody);
        return smsBody.toString();
    }

    /**
     * Resolve OTP values in the event properties and add them to the notification data.
     *
     * @param dataMap Notification data.
     */
    public static void resolveOTPValues(Map<String, Object> dataMap, Map<String, String> notificationData) {

        OTP otp = (OTP) dataMap.get(SMSNotificationConstants.OTP_TOKEN_PROPERTY_NAME);
        if (otp != null) {
            notificationData.put(SMSNotificationConstants.PLACE_HOLDER_CONFIRMATION_CODE, otp.getValue());
            notificationData.put(SMSNotificationConstants.PLACE_HOLDER_OTP_EXPIRY_TIME,
                    String.valueOf(TimeUnit.MILLISECONDS.toMinutes(otp.getValidityPeriodInMillis())));
        } else {
            String otpCode = (String) dataMap.get(OTP_TOKEN_STRING_PROPERTY_NAME);
            if (StringUtils.isNotBlank(otpCode)) {
                notificationData.put(SMSNotificationConstants.PLACE_HOLDER_CONFIRMATION_CODE, otpCode);
            }
        }
    }

    /**
     * Filter out the placeholders that are not accepted in the SMS template.
     *
     * @param notificationData Notification data.
     * @return Filtered notification data.
     */
    public static Map<String, String> filterPlaceHolderData(Map<String, String> notificationData) {

        Map<String, String> result = new HashMap<>();
        for (Map.Entry<String, String> entry : notificationData.entrySet()) {
            if (ACCEPTED_SMS_PLACEHOLDERS.contains(entry.getKey())) {
                result.put(entry.getKey(), entry.getValue());
            }
        }
        return result;
    }

    /**
     * If the tenant domain is a UUID, resolve the organization name from the associated organization resource.
     *
     * @param tenantDomain Tenant domain.
     * @return Human-readable name related to the represented organization space.
     * @throws IdentityEventException Error while resolving organization name.
     */
    public static String resolveHumanReadableOrganizationName(String tenantDomain) throws IdentityEventException {

        String organizationName = tenantDomain;
        try {
            if (SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
                return organizationName;
            }
            RealmService realmService = SMSNotificationHandlerDataHolder.getInstance().getRealmService();
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            Tenant tenant = realmService.getTenantManager().getTenant(tenantId);
            if (tenant == null) {
                return organizationName;
            }
            String associatedOrganizationUUID = tenant.getAssociatedOrganizationUUID();
            if (StringUtils.isBlank(associatedOrganizationUUID)) {
                return organizationName;
            }
            OrganizationManager organizationManager =
                    SMSNotificationHandlerDataHolder.getInstance().getOrganizationManager();
            organizationName = organizationManager.getOrganizationNameById(associatedOrganizationUUID);
        } catch (OrganizationManagementClientException e) {
            if (!ERROR_CODE_ORGANIZATION_NOT_FOUND_FOR_TENANT.getCode().equals(e.getErrorCode())) {
                throw new IdentityEventException(e.getMessage(), e);
            }
        } catch (OrganizationManagementException | UserStoreException e) {
            throw new IdentityEventException(e.getMessage(), e);
        }
        return organizationName;
    }

}
