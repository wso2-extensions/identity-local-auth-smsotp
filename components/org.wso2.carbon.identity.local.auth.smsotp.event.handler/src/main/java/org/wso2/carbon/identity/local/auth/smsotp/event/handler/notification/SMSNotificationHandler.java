/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com). All Rights Reserved.
 *
 * This software is the property of WSO2 LLC. and its suppliers, if any.
 * Dissemination of any information or reproduction of any material contained
 * herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
 * You may not alter or remove any copyright or other notice from copies of this content.
 *
 */

package org.wso2.carbon.identity.local.auth.smsotp.event.handler.notification;

import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.notification.DefaultNotificationHandler;
import org.wso2.carbon.identity.local.auth.smsotp.event.handler.notification.internal.SMSNotificationHandlerDataHolder;
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

    @Override
    public String getName() {

        return SMSNotificationConstants.NOTIFICATION_HANDLER_NAME;
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        try {
            List<SMSSenderDTO> smsSenders = SMSNotificationHandlerDataHolder
                    .getInstance()
                    .getNotificationSenderManagementService()
                    .getSMSSenders();
            if (smsSenders != null) {
                for (SMSSenderDTO smsSenderDTO : smsSenders) {
                    Provider provider = SMSNotificationHandlerDataHolder.getInstance()
                            .getProvider(smsSenderDTO.getName());
                    provider.init(smsSenderDTO);
                    provider.send(constructSMSOTPPayload(event.getEventProperties()));
                }
            }
        } catch (NotificationSenderManagementException e) {
            throw new IdentityEventException("Error while retrieving SMS Sender: "
                    + SMSNotificationConstants.SMS_PUBLISHER_NAME, e);
        }
    }

    private SMSData constructSMSOTPPayload(Map<String, Object> eventProperties) {

        SMSData smsData = new SMSData();

        smsData.setSMSBody((String) eventProperties.get(SMSNotificationConstants.SMS_MESSAGE_BODY_NAME));
        smsData.setToNumber((String) eventProperties.get(SMSNotificationConstants.SMS_MASSAGE_TO_NAME));

        return smsData;
    }
}
