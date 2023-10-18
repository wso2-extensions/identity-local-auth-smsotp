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
import org.wso2.carbon.identity.local.auth.smsotp.provider.model.SMSData;
import org.wso2.carbon.identity.notification.sender.tenant.config.dto.SMSSenderDTO;
import org.wso2.carbon.identity.local.auth.smsotp.provider.Provider;

/**
 * Implementation for the Twilio SMS provider for Twilio SMS gateway.
 *
 * @version 1.0.0
 * @since 1.0.0
 */
public class TwilioProvider implements Provider {

    private static final Log log = LogFactory.getLog(TwilioProvider.class);

    private String accountSid;
    private String authToken;
    private String senderName;
    private String tenantDomain;
    private boolean initialized;

    @Override
    public String getName() {
        return "Twilio";
    }

    @Override
    public void init(SMSSenderDTO smsSenderDTO, String tenantDomain) {
        this.accountSid = smsSenderDTO.getKey();
        this.authToken = smsSenderDTO.getSecret();
        this.senderName = smsSenderDTO.getName();
        this.tenantDomain = tenantDomain;
        initialized = true;
    }

    @Override
    public void send(SMSData smsData) {

        if (!initialized) {
            throw new RuntimeException("Twilio Provider not initialized");
        }

        Twilio.init(accountSid, authToken);
        PhoneNumber to = new PhoneNumber(smsData.getToNumber());
        PhoneNumber from = new PhoneNumber(senderName);
        Message message = Message.creator(to, from, smsData.getSMSBody()).create();

        if (message.getStatus() != Message.Status.SENT) {
            log.warn("Error occurred while sending SMS to " + smsData.getToNumber() + " using Twilio");
        } else if (log.isDebugEnabled()) {
            log.debug("SMS sent to " + smsData.getToNumber() + " using Twilio");
        }
    }
}
