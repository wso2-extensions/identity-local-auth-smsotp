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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.local.auth.smsotp.provider.model.SMSData;
import org.wso2.carbon.identity.local.auth.smsotp.provider.model.SMSMetadata;
import org.wso2.carbon.identity.notification.sender.tenant.config.dto.SMSSenderDTO;
import org.wso2.carbon.identity.local.auth.smsotp.provider.Provider;
import org.wso2.carbon.identity.local.auth.smsotp.provider.exception.PublisherException;
import org.wso2.carbon.identity.local.auth.smsotp.provider.http.HTTPPublisher;

/**
 * Implementation for the custom SMS provider.
 *
 * @version 1.0.0
 * @since 1.0.0
 */
public class CustomProvider implements Provider {

    private static final Log log = LogFactory.getLog(CustomProvider.class);

    private SMSSenderDTO smsSenderDTO;
    private boolean initialized;

    @Override
    public String getName() {
        return "Custom";
    }

    @Override
    public void init(SMSSenderDTO smsSenderDTO) {
        this.smsSenderDTO = smsSenderDTO;
        initialized = true;
    }

    @Override
    public void send(SMSData smsData) {

        if (!initialized) {
            throw new RuntimeException("Custom Provider not initialized");
        }

        SMSMetadata smsMetadata = new SMSMetadata();

        smsMetadata.setKey(smsSenderDTO.getKey());
        smsMetadata.setSecret(smsSenderDTO.getSecret());
        smsMetadata.setSender(smsSenderDTO.getSender());
        smsMetadata.setContentType(smsSenderDTO.getContentType());
        smsData.setSmsMetadata(smsMetadata);

        HTTPPublisher publisher = new HTTPPublisher(smsSenderDTO.getProviderURL());
        try {
            publisher.publish(smsData);
        } catch (PublisherException e) {
            log.error("Error occurred while publishing the SMS data to the custom provider", e);
        }
    }
}
