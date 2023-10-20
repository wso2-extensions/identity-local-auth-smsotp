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

package org.wso2.carbon.identity.local.auth.smsotp.event.handler.notification;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.notification.DefaultNotificationHandler;
import org.wso2.carbon.identity.event.handler.notification.NotificationConstants;
import org.wso2.carbon.identity.local.auth.smsotp.event.handler.notification.internal.SMSNotificationHandlerDataHolder;
import org.wso2.carbon.identity.local.auth.smsotp.provider.exception.ProviderException;
import org.wso2.carbon.identity.notification.sender.tenant.config.dto.SMSSenderDTO;
import org.wso2.carbon.identity.notification.sender.tenant.config.exception.NotificationSenderManagementException;
import org.wso2.carbon.identity.local.auth.smsotp.provider.Provider;
import org.wso2.carbon.identity.local.auth.smsotp.provider.model.SMSData;

import java.util.List;
import java.util.Map;

/**
 * This class represents the SMS notification handler.
 *
 * @version 1.0.0
 * @since 1.0.0
 */
public class SMSNotificationHandler extends DefaultNotificationHandler {

    private static final Log LOG = LogFactory.getLog(SMSNotificationHandler.class);

    @Override
    public String getName() {

        return SMSNotificationConstants.NOTIFICATION_HANDLER_NAME;
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        String tenantDomain = (String) event.getEventProperties().get(NotificationConstants.TENANT_DOMAIN);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Handling SMS notification event for " + tenantDomain);
        }

        try {
            // Get the registered SMS senders from the database. This is done to support multiple SMS senders
            // in the future. However, in the current implementation, only one SMS sender is supported through the UI.
            List<SMSSenderDTO> smsSenders = SMSNotificationHandlerDataHolder
                    .getInstance()
                    .getNotificationSenderManagementService()
                    .getSMSSenders();
            if (smsSenders != null) {
                for (SMSSenderDTO smsSenderDTO : smsSenders) {
                    // This is to get the supported SMS providers. We can include SMS providers through OSGi.
                    Provider provider = SMSNotificationHandlerDataHolder
                            .getInstance()
                            .getProvider(smsSenderDTO.getName());
                    if (provider == null) {
                        throw new IdentityEventException("No SMS provider found for the name: "
                                + smsSenderDTO.getName());
                    }
                    provider.send(constructSMSOTPPayload(event.getEventProperties()), smsSenderDTO, tenantDomain);
                }
            }
        } catch (NotificationSenderManagementException e) {
            throw new IdentityEventException("Error while retrieving SMS Sender: "
                    + SMSNotificationConstants.SMS_PUBLISHER_NAME, e);
        } catch (ProviderException e) {
            throw new IdentityEventException("Error while sending SMS", e);
        }
    }

    private SMSData constructSMSOTPPayload(Map<String, Object> eventProperties) {

        SMSData smsData = new SMSData();

        smsData.setSMSBody((String) eventProperties.get(SMSNotificationConstants.SMS_MESSAGE_BODY_NAME));
        smsData.setToNumber((String) eventProperties.get(SMSNotificationConstants.SMS_MASSAGE_TO_NAME));

        return smsData;
    }
}
