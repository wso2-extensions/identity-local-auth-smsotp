/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com). All Rights Reserved.
 *
 * This software is the property of WSO2 LLC. and its suppliers, if any.
 * Dissemination of any information or reproduction of any material contained
 * herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
 * You may not alter or remove any copyright or other notice from copies of this content.
 *
 */

package org.wso2.carbon.identity.local.auth.smsotp.provider;

import org.wso2.carbon.identity.local.auth.smsotp.provider.model.SMSData;
import org.wso2.carbon.identity.notification.sender.tenant.config.dto.SMSSenderDTO;

/**
 * This interface represents the SMS provider.
 *
 * @version 1.0.0
 * @since 1.0.0
 */
public interface Provider {

    /**
     * Returns the name of the provider.
     *
     * @return Name of the provider.
     */
    String getName();

    /**
     * Initializes the provider.
     *
     * @param smsSenderDTO SMS sender DTO.
     */
    void init(SMSSenderDTO smsSenderDTO);

    /**
     * Sends the SMS.
     *
     * @param smsData SMS data.
     */
    void send(SMSData smsData);
}
