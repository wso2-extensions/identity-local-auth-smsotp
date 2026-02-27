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

import com.twilio.Twilio;
import com.twilio.exception.ApiException;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.local.auth.smsotp.provider.Provider;
import org.wso2.carbon.identity.local.auth.smsotp.provider.constant.Constants;
import org.wso2.carbon.identity.local.auth.smsotp.provider.exception.NonBlockingProviderException;
import org.wso2.carbon.identity.local.auth.smsotp.provider.exception.ProviderException;
import org.wso2.carbon.identity.local.auth.smsotp.provider.model.SMSData;
import org.wso2.carbon.identity.local.auth.smsotp.provider.util.ProviderUtil;
import org.wso2.carbon.identity.notification.sender.tenant.config.dto.SMSSenderDTO;
import org.wso2.carbon.utils.DiagnosticLog;

/**
 * Implementation for the Twilio SMS provider for Twilio SMS gateway.
 *
 * @version 1.0.0
 * @since 1.0.0
 */
public class TwilioProvider implements Provider {

    private static final Log LOG = LogFactory.getLog(TwilioProvider.class);

    @Override
    public String getName() {
        return Constants.TWILIO;
    }

    @Override
    public void send(SMSData smsData, SMSSenderDTO smsSenderDTO, String tenantDomain) throws ProviderException {

        if (StringUtils.isBlank(smsData.getToNumber())) {
            throw new ProviderException("To number is null or blank. Cannot send SMS");
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Sending SMS to " + ProviderUtil.hashTelephoneNumber(smsData.getToNumber())
                    + " using Twilio provider");
        }

        try {
            String accountSid = smsSenderDTO.getKey();
            String authToken = smsSenderDTO.getSecret();
            String senderName = smsSenderDTO.getSender();

            Twilio.init(accountSid, authToken);
            PhoneNumber to = new PhoneNumber(smsData.getToNumber());
            PhoneNumber from = new PhoneNumber(senderName);
            Message message = Message.creator(to, from, smsData.getBody()).create();

            if (message.getStatus() == Message.Status.FAILED) {
                Message.Status status = message.getStatus();
                String errorText = message.getErrorMessage();

                ProviderUtil.triggerDiagnosticLogEvent(
                        String.format("Error occurred while sending SMS. Status : %s. Error: %s", status, errorText),
                        smsData.getToNumber(), Constants.TWILIO, DiagnosticLog.ResultStatus.FAILED);
                LOG.warn("Error occurred while sending SMS to "
                        + ProviderUtil.hashTelephoneNumber(smsData.getToNumber()) + " using Twilio."
                        + " Status: " + status + ". Error: " + errorText);
                throw new NonBlockingProviderException("Error occurred while sending SMS to "
                        + ProviderUtil.hashTelephoneNumber(smsData.getToNumber())
                        + " using Twilio. Status: " + status + ". Error: " + errorText);
            } else if (LOG.isDebugEnabled()) {
                LOG.debug("SMS sent to " + ProviderUtil.hashTelephoneNumber(smsData.getToNumber())
                        + " using Twilio." + " Status: " + message.getStatus());
            }
        } catch (ApiException e) {
            Integer status = e.getStatusCode();
            String errorText = StringUtils.isNotBlank(e.getMessage()) ? e.getMessage() : e.getCause().getMessage();

            ProviderUtil.triggerDiagnosticLogEvent(
                    String.format("Error occurred while sending SMS. Status : %s. Error: %s", status, errorText),
                    smsData.getToNumber(), Constants.TWILIO, DiagnosticLog.ResultStatus.FAILED);
            LOG.warn("Error occurred while sending SMS to "
                    + ProviderUtil.hashTelephoneNumber(smsData.getToNumber()) + " using Twilio."
                    + " Status: " + e.getStatusCode() + ". Error: " + errorText);
            throw new NonBlockingProviderException("Error occurred while sending SMS to "
                    + ProviderUtil.hashTelephoneNumber(smsData.getToNumber())
                    + " using Twilio. Status: " + status + ". Error: " + errorText, e);
        } catch (NonBlockingProviderException e) {
            // Re-throw explicitly: NonBlockingProviderException extends ProviderException, so without
            // this clause it would be re-wrapped by the Exception handler below.
            throw e;
        } catch (Exception e) {
            throw new ProviderException("Error occurred while sending SMS to "
                    + ProviderUtil.hashTelephoneNumber(smsData.getToNumber())
                    + " using Twilio", e);
        }
    }
}
