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

package org.wso2.carbon.identity.local.auth.smsotp.provider.impl;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.Header;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.local.auth.smsotp.provider.Provider;
import org.wso2.carbon.identity.local.auth.smsotp.provider.constant.Constants;
import org.wso2.carbon.identity.local.auth.smsotp.provider.exception.NonBlockingProviderException;
import org.wso2.carbon.identity.local.auth.smsotp.provider.exception.ProviderException;
import org.wso2.carbon.identity.local.auth.smsotp.provider.exception.PublisherException;
import org.wso2.carbon.identity.local.auth.smsotp.provider.http.HTTPPublisher;
import org.wso2.carbon.identity.local.auth.smsotp.provider.internal.SMSNotificationProviderDataHolder;
import org.wso2.carbon.identity.local.auth.smsotp.provider.model.SMSData;
import org.wso2.carbon.identity.local.auth.smsotp.provider.util.ProviderUtil;
import org.wso2.carbon.identity.notification.sender.tenant.config.dto.Authentication;
import org.wso2.carbon.identity.notification.sender.tenant.config.dto.SMSSenderDTO;
import org.wso2.carbon.identity.notification.sender.tenant.config.exception.NotificationSenderManagementException;
import org.wso2.carbon.utils.DiagnosticLog;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.identity.local.auth.smsotp.provider.constant.Constants.ErrorMessage.ERROR_UNAUTHORIZED_ACCESS;

/**
 * Implementation for the custom SMS provider. This provider is used to send the SMS using the custom SMS gateway.
 * Configuration details are available in {@link SMSSenderDTO}.
 *
 * @version 1.0.0
 * @since 1.0.0
 */
public class CustomProvider implements Provider {

    private static final Log LOG = LogFactory.getLog(CustomProvider.class);

    @Override
    public String getName() {
        return "Custom";
    }

    @Override
    public void send(SMSData smsData, SMSSenderDTO smsSenderDTO, String tenantDomain) throws ProviderException {

        if (StringUtils.isBlank(smsData.getToNumber())) {
            throw new ProviderException("To number is null or blank. Cannot send SMS");
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Sending SMS to " + ProviderUtil.hashTelephoneNumber(smsData.getToNumber())
                    + " using custom provider");
        }

        if (StringUtils.isBlank(smsSenderDTO.getContentType())
                || Constants.JSON.equals(smsSenderDTO.getContentType())) {
            smsData.setContentType(Constants.APPLICATION_JSON);
        } else if (Constants.FORM.equals(smsSenderDTO.getContentType())) {
            smsData.setContentType(Constants.APPLICATION_FORM);
        }

        Map<String, String> headers = constructHeaders(smsSenderDTO.getProperties().get(Constants.HTTP_HEADERS));
        addAuthHeader(headers, smsSenderDTO);
        smsData.setHeaders(headers);
        smsData.setHttpMethod(smsSenderDTO.getProperties().get(Constants.HTTP_METHOD));

        // If we have additional payload to be sent to the custom provider, we will append it to the SMS body.
        String template = smsSenderDTO.getProperties().get(Constants.HTTP_BODY);
        if (StringUtils.isBlank(template)) {
            throw new ProviderException("Template is null or blank. Cannot send SMS");
        }
        smsData.setBody(resolveTemplate(smsData.getContentType(), template, smsData.getToNumber(), smsData.getBody()));

        try {
            publish(smsData, smsSenderDTO, headers);
        } catch (PublisherException e) {
            String errorText = StringUtils.isNotBlank(e.getMessage()) ? e.getMessage() : e.getCause().getMessage();
            ProviderUtil.triggerDiagnosticLogEvent(
                    String.format("Error occurred while sending SMS. Error: %s", errorText), smsData.getToNumber(),
                    smsSenderDTO.getProvider(), DiagnosticLog.ResultStatus.FAILED);
            LOG.warn("Error occurred while sending SMS to "
                    + ProviderUtil.hashTelephoneNumber(smsData.getToNumber()) + " using custom provider."
                    + ". Error: " + errorText);
            throw new NonBlockingProviderException(
                    "Error occurred while publishing the SMS data to the custom provider", e);
        } catch (NotificationSenderManagementException e) {
            throw new ProviderException(
                    "Error occurred while building authentication header for the notification provider", e);
        }
    }

    private void publish(SMSData smsData, SMSSenderDTO smsSenderDTO, Map<String, String> headers)
            throws PublisherException, NotificationSenderManagementException {

        HTTPPublisher publisher = new HTTPPublisher();
        int allowedAttempts = getRetryCountAtAuthFailure() + 1;

        for (int attempt = 1; attempt <= allowedAttempts;) {
            try {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Publishing SMS to SMS notification provider. Attempt: " + attempt + ".");
                }
                publisher.publish(smsData, smsSenderDTO.getProviderURL());
                return;
            } catch (PublisherException e) {
                if (!ERROR_UNAUTHORIZED_ACCESS.getCode().equals(e.getErrorCode()) || attempt >= allowedAttempts) {
                    throw e;
                }
                Header newAuthHeader = SMSNotificationProviderDataHolder.getInstance()
                        .getNotificationSenderManagementService()
                        .rebuildAuthHeaderWithNewToken(smsSenderDTO);
                if (newAuthHeader == null) {
                    throw e;
                }
                headers.put(newAuthHeader.getName(), newAuthHeader.getValue());
                smsData.setHeaders(headers);
            }
            attempt++;
        }
    }


    private void addAuthHeader(Map<String, String> headers, SMSSenderDTO smsSenderDTO)
            throws ProviderException {

        try {
            if (smsSenderDTO.getAuthentication() == null) {
                return;
            }
            if (smsSenderDTO.getAuthentication().getAuthHeader() == null) {
                if (Authentication.Type.CLIENT_CREDENTIAL != smsSenderDTO.getAuthentication().getType()) {
                    return;
                }
                SMSNotificationProviderDataHolder.getInstance().getNotificationSenderManagementService()
                        .rebuildAuthHeaderWithNewToken(smsSenderDTO);
            }
            headers.put(
                    smsSenderDTO.getAuthentication().getAuthHeader().getName(),
                    smsSenderDTO.getAuthentication().getAuthHeader().getValue());
        } catch (NotificationSenderManagementException e) {
            throw new ProviderException("Error while retrieving the authentication header for custom provider", e);
        }
    }

    private Map<String, String> constructHeaders(String headers) {

        if (StringUtils.isBlank(headers)) {
            return new HashMap<>();
        }

        String[] headerList = headers.split(",");
        Map<String, String> headerMap = new HashMap<>();

        // From the list of headers, construct the header map by splitting the header name and value using ':'.
        for (String header : headerList) {
            String[] headerArray = header.split(":");
            if (headerArray.length == 2) {
                headerMap.put(headerArray[0], headerArray[1]);
            }
        }
        return headerMap;
    }

    private String resolveTemplate(String contentType, String template, String to, String body)
            throws ProviderException {

        if (Constants.APPLICATION_FORM.equals(contentType)) {
            try {
                return template
                        .replace(Constants.TO_PLACEHOLDER, URLEncoder.encode(to, StandardCharsets.UTF_8.name()))
                        .replace(Constants.BODY_PLACEHOLDER, URLEncoder.encode(body, StandardCharsets.UTF_8.name()));
            } catch (UnsupportedEncodingException e) {
                throw new ProviderException("The specified encoding is not supported.");
            }
        }
        return template
                .replace(Constants.TO_PLACEHOLDER, "\"" + to + "\"")
                .replace(Constants.BODY_PLACEHOLDER, "\"" + body + "\"");
    }

    private int getRetryCountAtAuthFailure() {

        return ProviderUtil.parsePositiveOrDefault(IdentityUtil.getProperty(Constants.RETRY_COUNT_AT_AUTH_FAILURE), 1);
    }
}
