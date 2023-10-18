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

import com.vonage.client.VonageClient;
import com.vonage.client.sms.MessageStatus;
import com.vonage.client.sms.SmsSubmissionResponse;
import com.vonage.client.sms.messages.TextMessage;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.local.auth.smsotp.provider.Provider;
import org.wso2.carbon.identity.local.auth.smsotp.provider.model.SMSData;
import org.wso2.carbon.identity.notification.sender.tenant.config.dto.SMSSenderDTO;

/**
 * Implementation for the Vonage SMS provider for Vonage SMS gateway.
 *
 * @version 1.0.0
 * @since 1.0.0
 */
public class VonageProvider implements Provider {

    private static final Log log = LogFactory.getLog(VonageProvider.class);

    private String apiKey;
    private String apiSecret;
    private String senderName;
    private boolean initialized;

    @Override
    public String getName() {
        return "Vonage";
    }

    @Override
    public void init(SMSSenderDTO smsSenderDTO, String tenantDomain) {

        this.apiKey = smsSenderDTO.getKey();
        this.apiSecret = smsSenderDTO.getSecret();
        this.senderName = smsSenderDTO.getName();
        initialized = true;
    }

    @Override
    public void send(SMSData smsData) {

        if (!initialized) {
            throw new RuntimeException("Vonage Provider not initialized");
        }

        VonageClient client = new VonageClient.Builder()
                .apiKey(apiKey)
                .apiSecret(apiSecret)
                .build();
        TextMessage message = new TextMessage(senderName, smsData.getToNumber(), smsData.getSMSBody());
        SmsSubmissionResponse response = client.getSmsClient().submitMessage(message);

        if (response.getMessages().get(0).getStatus() != MessageStatus.OK) {
            log.warn("Error occurred while sending SMS to " + smsData.getToNumber() + " using Vonage");
        } else if (log.isDebugEnabled()) {
            log.debug("SMS sent to " + smsData.getToNumber() + " using Vonage");
        }
    }
}
