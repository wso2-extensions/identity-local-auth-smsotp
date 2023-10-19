/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com). All Rights Reserved.
 *
 * This software is the property of WSO2 LLC. and its suppliers, if any.
 * Dissemination of any information or reproduction of any material contained
 * herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
 * You may not alter or remove any copyright or other notice from copies of this content.
 *
 */

package org.wso2.carbon.identity.local.auth.smsotp.provider.impl;

import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.local.auth.smsotp.provider.constant.Constants;
import org.wso2.carbon.identity.local.auth.smsotp.provider.exception.ProviderException;
import org.wso2.carbon.identity.local.auth.smsotp.provider.model.SMSData;
import org.wso2.carbon.identity.local.auth.smsotp.provider.util.ProviderUtil;
import org.wso2.carbon.identity.notification.sender.tenant.config.dto.SMSSenderDTO;
import org.wso2.carbon.identity.local.auth.smsotp.provider.Provider;

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
            Message message = Message.creator(to, from, smsData.getSMSBody()).create();

            if (message.getStatus() != Message.Status.SENT) {
                LOG.warn("Error occurred while sending SMS to "
                        + ProviderUtil.hashTelephoneNumber(smsData.getToNumber()) + " using Twilio."
                        + " Status: " + message.getStatus() + " Message: " + message.getErrorMessage());
            } else if (LOG.isDebugEnabled()) {
                LOG.debug("SMS sent to " + ProviderUtil.hashTelephoneNumber(smsData.getToNumber())
                        + " using Twilio");
            }
        } catch (Exception e) {
            throw new ProviderException("Error occurred while sending SMS to "
                    + ProviderUtil.hashTelephoneNumber(smsData.getToNumber())
                    + " using Twilio", e);
        }
    }
}
