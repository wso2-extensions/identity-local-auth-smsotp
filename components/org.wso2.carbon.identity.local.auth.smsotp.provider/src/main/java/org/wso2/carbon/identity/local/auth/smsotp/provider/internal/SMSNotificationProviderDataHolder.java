/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.local.auth.smsotp.provider.internal;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.wso2.carbon.identity.notification.sender.tenant.config.NotificationSenderManagementService;

/**
 * SMS Notification Provider service component's component holder.
 */
@SuppressFBWarnings({"EI_EXPOSE_RE", "MS_EXPOSE_REP", "EI_EXPOSE_REP2"})
public class SMSNotificationProviderDataHolder {

    private static final SMSNotificationProviderDataHolder instance = new SMSNotificationProviderDataHolder();

    private NotificationSenderManagementService notificationSenderManagementService;

    private SMSNotificationProviderDataHolder() {
    }

    /**
     * Get SMSNotificationProviderDataHolder instance.
     *
     * @return SMSNotificationProviderDataHolder instance.
     */
    public static SMSNotificationProviderDataHolder getInstance() {

        return instance;
    }

    /**
     * Set NotificationSenderManagementService.
     *
     * @param notificationSenderManagementService NotificationSenderManagementService.
     */
    public void setNotificationSenderManagementService(
            NotificationSenderManagementService notificationSenderManagementService) {

        this.notificationSenderManagementService = notificationSenderManagementService;
    }

    /**
     * Get NotificationSenderManagementService.
     *
     * @return NotificationSenderManagementService.
     */
    public NotificationSenderManagementService getNotificationSenderManagementService() {

        return notificationSenderManagementService;
    }
}
