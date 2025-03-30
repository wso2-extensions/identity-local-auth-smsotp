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

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.auth.otp.core.model.OTP;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.local.auth.smsotp.event.handler.notification.internal.SMSNotificationHandlerDataHolder;
import org.wso2.carbon.identity.local.auth.smsotp.event.handler.notification.internal.SMSNotificationUtil;
import org.wso2.carbon.identity.local.auth.smsotp.provider.impl.CustomProvider;
import org.wso2.carbon.identity.local.auth.smsotp.provider.impl.TwilioProvider;
import org.wso2.carbon.identity.local.auth.smsotp.provider.model.SMSData;
import org.wso2.carbon.identity.notification.sender.tenant.config.NotificationSenderManagementConstants;
import org.wso2.carbon.identity.notification.sender.tenant.config.NotificationSenderManagementService;
import org.wso2.carbon.identity.notification.sender.tenant.config.dto.SMSSenderDTO;
import org.wso2.carbon.identity.notification.sender.tenant.config.exception.NotificationSenderManagementException;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link SMSNotificationHandler}.
 */
public class SMSNotificationHandlerTest {

    private final String tenantDomain = "tenant1";

    @Mock
    NotificationSenderManagementService notificationSenderManagementService;

    private SMSNotificationHandler smsNotificationHandler;
    private MockedStatic<IdentityTenantUtil> mockedStaticIdentityTenantUtil;

    @BeforeClass
    public void beforeTest() {

        mockIdentityTenantUtil();
    }

    @AfterClass
    public void afterTest() {

        closeMockedIdentityTenantUtil();
    }

    @BeforeTest
    public void setup() {

        MockitoAnnotations.openMocks(this);
        TestableSMSNotificationHandler.resetNotificationData();
        smsNotificationHandler = new TestableSMSNotificationHandler();
        SMSNotificationHandlerDataHolder
                .getInstance()
                .setNotificationSenderManagementService(notificationSenderManagementService);

        SMSNotificationHandlerDataHolder
                .getInstance()
                .addProvider("TwilioSMSProvider", new TwilioProvider());

        SMSNotificationHandlerDataHolder
                .getInstance()
                .addProvider("SMSProvider", new CustomProvider());
    }

    @Test(dataProvider = "handleEventDataProvider")
    public void testHandleEvent(List<SMSSenderDTO> smsSenderDTOS) throws IdentityEventException,
            NotificationSenderManagementException {

        Event event = constructSMSOTPEvent();
        when(notificationSenderManagementService.getSMSSenders()).thenReturn(smsSenderDTOS);
        try {
            smsNotificationHandler.handleEvent(event);
        } catch (IdentityEventException e) {
            Assert.assertNotNull(e.getMessage());
        }
    }

    @Test
    public void testConstructSMSOTPPayload() throws IdentityEventException {

        Event testEvent = constructSMSOTPEvent();
        try (MockedStatic<SMSNotificationUtil> mockedSMSNotificationUtil = mockStatic(SMSNotificationUtil.class)) {
            mockedSMSNotificationUtil.when(() -> SMSNotificationUtil.replacePlaceholders(
                    TestableSMSNotificationHandler.notificationData.get(SMSNotificationConstants.BODY_TEMPLATE),
                    TestableSMSNotificationHandler.notificationData)).thenReturn("success");
            SMSData smsData = smsNotificationHandler.constructSMSOTPPayload(testEvent);
            Assert.assertEquals(smsData.getBody(), "success");
        }
    }

    @Test(expectedExceptions = IdentityEventException.class)
    public void testConstructSMSOTPPayloadWithNoTemplate() throws IdentityEventException {

        Event testEvent = constructSMSOTPEvent();
        try (MockedStatic<SMSNotificationUtil> mockedSMSNotificationUtil = mockStatic(SMSNotificationUtil.class)) {
            mockedSMSNotificationUtil.when(() -> SMSNotificationUtil.replacePlaceholders(
                    TestableSMSNotificationHandler.notificationData.get(SMSNotificationConstants.BODY_TEMPLATE),
                    TestableSMSNotificationHandler.notificationData)).thenReturn("success");
            TestableSMSNotificationHandler.notificationData.remove(SMSNotificationConstants.BODY_TEMPLATE);
            smsNotificationHandler.constructSMSOTPPayload(testEvent);
        } finally {
            TestableSMSNotificationHandler.notificationData.put(SMSNotificationConstants.BODY_TEMPLATE,
                    "Your one-time password for the {{application-name}} is {{otpToken}}. This expires " +
                            "in {{otp-expiry-time}} minutes.,");
            TestableSMSNotificationHandler.notificationData.remove(
                    SMSNotificationConstants.PLACEHOLDER_ORGANIZATION_NAME);
        }
    }

    @Test
    public void testConstructSMSOTPPayloadWithPlaceHolders() throws IdentityEventException {

        Event testEvent = constructSMSOTPEvent();
        testEvent.addEventProperty("otpToken", new OTP("874090", 300000, 300000));
        testEvent.addEventProperty("tenant-domain", "carbon.super");

        String givenName = "John";
        String lastName = "Doe";
        String currentYear = String.valueOf(Calendar.getInstance().get(Calendar.YEAR));
        String smsBody = "Hi John Doe,\n\nYour one-time password for the sms_otp_singlepage_App " +
                "is 874090. This expires in 5 minutes.\n\nCopyright " + currentYear + ", WSO2.";
        String bodyTemplate = "Hi {{user.claim.givenname}} {{user.claim.lastname}}," +
                "\n\nYour one-time password for the {{application-name}} is {{otpToken}}. " +
                "This expires in {{otp-expiry-time}} minutes.\n\nCopyright {{current-year}}, WSO2.";

        String prevBody = TestableSMSNotificationHandler.notificationData.get(
                SMSNotificationConstants.SMS_MESSAGE_BODY_NAME);
        String prevTemplate = TestableSMSNotificationHandler.notificationData.get(
                SMSNotificationConstants.BODY_TEMPLATE);

        try {
            testEvent.addEventProperty("body", smsBody);
            testEvent.addEventProperty("body-template", bodyTemplate);
            testEvent.addEventProperty("user.claim.givenname", givenName);
            testEvent.addEventProperty("user.claim.lastname", lastName);
            TestableSMSNotificationHandler.notificationData.put(
                    SMSNotificationConstants.SMS_MESSAGE_BODY_NAME, smsBody);
            TestableSMSNotificationHandler.notificationData.put(
                    SMSNotificationConstants.BODY_TEMPLATE, bodyTemplate);
            TestableSMSNotificationHandler.notificationData.put("user.claim.givenname", givenName);
            TestableSMSNotificationHandler.notificationData.put("user.claim.lastname", lastName);

            SMSData smsData = smsNotificationHandler.constructSMSOTPPayload(testEvent);
            Assert.assertNotNull(smsData);
            Assert.assertEquals(smsData.getBody(), smsBody);
        } finally {
            TestableSMSNotificationHandler.notificationData.put(
                    SMSNotificationConstants.SMS_MESSAGE_BODY_NAME, prevBody);
            TestableSMSNotificationHandler.notificationData.put(
                    SMSNotificationConstants.BODY_TEMPLATE, prevTemplate);
            TestableSMSNotificationHandler.notificationData.remove("user.claim.givenname");
            TestableSMSNotificationHandler.notificationData.remove("user.claim.lastname");
        }
    }

    @Test(expectedExceptions = IdentityEventException.class)
    public void testHandleEventIdentityEventException() throws IdentityEventException,
            NotificationSenderManagementException {

        Event event = constructSMSOTPEvent();
        when(notificationSenderManagementService.getSMSSenders()).
                thenThrow(new NotificationSenderManagementException(NotificationSenderManagementConstants
                        .ErrorMessage.ERROR_CODE_ERROR_GETTING_NOTIFICATION_SENDERS_BY_TYPE));
        smsNotificationHandler.handleEvent(event);
    }

    @Test(expectedExceptions = IdentityEventException.class)
    public void testHandleEventIdentityWebSubAdapterException() throws IdentityEventException,
            NotificationSenderManagementException {

        List<SMSSenderDTO> smsSenderDTOS = new ArrayList<>();
        Map<String, String> propertyMap = new HashMap<>();
        propertyMap.put("channel.type", "choreo");
        smsSenderDTOS.add(constructSMSSenderDTO("SMSProvider", propertyMap));
        Event event = constructSMSOTPEvent();
        smsNotificationHandler.handleEvent(event);
    }

    @Test
    public void testGetName() {

        Assert.assertEquals(smsNotificationHandler.getName(), SMSNotificationConstants.NOTIFICATION_HANDLER_NAME);
    }

    @DataProvider(name = "handleEventDataProvider")
    public Object[][] provideSMSSenderDTOData() {

        Map<String, String> propertyMap1 = new HashMap<>();
        propertyMap1.put("channel.type", "choreo");

        Map<String, String> propertyMap2 = new HashMap<>();
        propertyMap2.put("channel.type", "default");

        List<SMSSenderDTO> smsSenderDTOS1 = new ArrayList<>();
        smsSenderDTOS1.add(constructSMSSenderDTO("SMSProvider", propertyMap1));

        List<SMSSenderDTO> smsSenderDTOS2 = new ArrayList<>();
        smsSenderDTOS2.add(constructSMSSenderDTO("TwilioSMSProvider", propertyMap1));

        List<SMSSenderDTO> smsSenderDTOS3 = new ArrayList<>();
        smsSenderDTOS3.add(constructSMSSenderDTO("SMSProvider", propertyMap2));

        List<SMSSenderDTO> smsSenderDTOS4 = new ArrayList<>();
        smsSenderDTOS4.add(constructSMSSenderDTO("TwilioSMSProvider", propertyMap2));

        return new Object[][]{
                //sms sender dto list
                {smsSenderDTOS1},
                {smsSenderDTOS2},
                {smsSenderDTOS3},
                {smsSenderDTOS4},
                {new ArrayList<>()},
                {null}
        };
    }

    public void mockIdentityTenantUtil() {

        mockedStaticIdentityTenantUtil = mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(tenantDomain)).thenReturn(1);
    }

    public void closeMockedIdentityTenantUtil() {

        mockedStaticIdentityTenantUtil.close();
    }

    private SMSSenderDTO constructSMSSenderDTO(String name, Map<String, String> propertyMap) {

        SMSSenderDTO smsSenderDTO = new SMSSenderDTO();
        smsSenderDTO.setName(name);
        smsSenderDTO.setProperties(propertyMap);
        return smsSenderDTO;
    }

    private Event constructSMSOTPEvent() {

        Event smsOtpEvent = new Event("NOTIFICATION");

        smsOtpEvent.addEventProperty("send-to", "+11110000");
        smsOtpEvent.addEventProperty("TEMPLATE_TYPE", "SMSOTP");
        smsOtpEvent.addEventProperty("application-name", "sms_otp_singlepage_App");
        smsOtpEvent.addEventProperty("notification-channel", "smsotp");
        smsOtpEvent.addEventProperty("notification-event", "smsotp");
        smsOtpEvent.addEventProperty("mobile", "+11110000");
        smsOtpEvent.addEventProperty("otpToken", "874090");
        smsOtpEvent.addEventProperty("userstore-domain", "DEFAULT");
        smsOtpEvent.addEventProperty("locale", "en_US");
        smsOtpEvent.addEventProperty("body", "Your one-time password for the sms_otp_singlepage_App is 874090. " +
                "This expires in 5 minutes.");
        smsOtpEvent.addEventProperty("tenant-domain", tenantDomain);
        smsOtpEvent.addEventProperty("otp-expiry-time", "5");
        smsOtpEvent.addEventProperty("user-name", "wso2@gmail.com");
        smsOtpEvent.addEventProperty("body-template", "Your one-time password for the " +
                "{{application-name}} is {{otpToken}}. This expires in {{otp-expiry-time}} minutes.,");

        return smsOtpEvent;
    }
}
