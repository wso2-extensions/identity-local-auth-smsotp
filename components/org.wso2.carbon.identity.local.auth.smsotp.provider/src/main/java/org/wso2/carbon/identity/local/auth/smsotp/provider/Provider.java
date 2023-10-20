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

package org.wso2.carbon.identity.local.auth.smsotp.provider;

import org.wso2.carbon.identity.local.auth.smsotp.provider.exception.ProviderException;
import org.wso2.carbon.identity.local.auth.smsotp.provider.model.SMSData;
import org.wso2.carbon.identity.notification.sender.tenant.config.dto.SMSSenderDTO;

/**
 * This interface represents the SMS provider. Which is a physical representation of the SMS provider we use to send
 * the SMS and act as the SMS gat
 *
 * @version 1.0.0
 * @since 1.0.0
 */
public interface Provider {

    /**
     * Returns the unique name of the provider. This name will be used to identify the provider and send the necessary
     * data using the provider metadata.
     *
     * @return Name of the provider.
     */
    String getName();

    /**
     * Sends the SMS using the provider SMS gateway.
     *
     * @param smsData SMS data.
     * @param smsSenderDTO SMS sender DTO.
     * @param tenantDomain Tenant domain.
     */
    void send(SMSData smsData, SMSSenderDTO smsSenderDTO, String tenantDomain) throws ProviderException;
}
