/*
 * Copyright (c) 2023-2026, WSO2 LLC. (https://www.wso2.com).
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

import com.vonage.client.VonageClient;
import com.vonage.client.sms.MessageStatus;
import com.vonage.client.sms.SmsSubmissionResponse;
import com.vonage.client.sms.messages.TextMessage;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.local.auth.smsotp.provider.Provider;
import org.wso2.carbon.identity.local.auth.smsotp.provider.constant.Constants;
import org.wso2.carbon.identity.local.auth.smsotp.provider.exception.ProviderException;
import org.wso2.carbon.identity.local.auth.smsotp.provider.model.SMSData;
import org.wso2.carbon.identity.local.auth.smsotp.provider.util.ProviderUtil;
import org.wso2.carbon.identity.notification.sender.tenant.config.dto.SMSSenderDTO;
import org.wso2.carbon.utils.DiagnosticLog;

/**
 * Implementation for the Vonage SMS provider for Vonage SMS gateway.
 *
 * @version 1.0.0
 * @since 1.0.0
 */
public class VonageProvider implements Provider {

    private static final Log LOG = LogFactory.getLog(VonageProvider.class);

    @Override
    public String getName() {
        return Constants.VONAGE;
    }

    @Override
    public void send(SMSData smsData, SMSSenderDTO smsSenderDTO, String tenantDomain) throws ProviderException {

        if (StringUtils.isBlank(smsData.getToNumber())) {
            throw new ProviderException("To number is null or blank. Cannot send SMS");
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Sending SMS to " + ProviderUtil.hashTelephoneNumber(smsData.getToNumber())
                    + " using Vonage provider");
        }

        try {
            String apiKey = smsSenderDTO.getKey();
            String apiSecret = smsSenderDTO.getSecret();
            String senderName = smsSenderDTO.getSender();

            VonageClient client = new VonageClient.Builder()
                    .apiKey(apiKey)
                    .apiSecret(apiSecret)
                    .build();
            TextMessage message = new TextMessage(senderName, smsData.getToNumber(), smsData.getBody());
            SmsSubmissionResponse response = client.getSmsClient().submitMessage(message);

            if (response.getMessages().get(0).getStatus() != MessageStatus.OK) {
                MessageStatus status = response.getMessages().get(0).getStatus();
                String errorText = response.getMessages().get(0).getErrorText();
                ProviderUtil.triggerDiagnosticLogEvent(
                        String.format("Error occurred while sending SMS. Status : %s. Error: %s", status, errorText),
                        smsData.getToNumber(), Constants.VONAGE, ProviderUtil.toProviderStatus(status),
                        DiagnosticLog.ResultStatus.FAILED);
                LOG.warn("Error occurred while sending SMS to "
                        + ProviderUtil.hashTelephoneNumber(smsData.getToNumber()) + " using Vonage."
                        + " Status: " + response.getMessages().get(0).getStatus() + ". Error: " + errorText);
                Constants.ErrorMessage error = resolveVonageError(status);
                throw new ProviderException(error.getCode(), error.getMessage());
            } else {
                ProviderUtil.triggerDiagnosticLogEvent("SMS was accepted by the SMS provider.",
                        smsData.getToNumber(), Constants.VONAGE,
                        ProviderUtil.toProviderStatus(response.getMessages().get(0).getStatus()),
                        DiagnosticLog.ResultStatus.SUCCESS);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("SMS sent to " + ProviderUtil.hashTelephoneNumber(smsData.getToNumber())
                            + " using Vonage");
                }
            }
        } catch (ProviderException e) {
            // Re-throw without wrapping so the structured SP- error code is preserved for the caller.
            throw e;
        } catch (Throwable throwable) {
            throw new ProviderException("Error occurred while sending SMS to "
                    + ProviderUtil.hashTelephoneNumber(smsData.getToNumber())
                    + " using Vonage", throwable);
        }
    }

    private Constants.ErrorMessage resolveVonageError(MessageStatus status) {

        if (status == null) {
            return Constants.ErrorMessage.MESSAGE_DELIVERY_FAILED;
        }
        switch (status) {
            case THROTTLED:
                return Constants.ErrorMessage.TOO_MANY_REQUESTS;
            case INVALID_CREDENTIALS:
                return Constants.ErrorMessage.UNAUTHORIZED;
            case INTERNAL_ERROR:
                return Constants.ErrorMessage.SERVER_ERROR;
            case PARTNER_QUOTA_EXCEEDED:
                return Constants.ErrorMessage.ACCOUNT_LIMIT_EXCEEDED;
            case NUMBER_BARRED:
                return Constants.ErrorMessage.NUMBER_BARRED;
            case MISSING_PARAMS:
            case INVALID_PARAMS:
                return Constants.ErrorMessage.INVALID_CONFIGURATION;
            case PARTNER_ACCOUNT_BARRED:
                return Constants.ErrorMessage.ACCOUNT_SUSPENDED;
            default:
                return Constants.ErrorMessage.MESSAGE_DELIVERY_FAILED;
        }
    }
}
