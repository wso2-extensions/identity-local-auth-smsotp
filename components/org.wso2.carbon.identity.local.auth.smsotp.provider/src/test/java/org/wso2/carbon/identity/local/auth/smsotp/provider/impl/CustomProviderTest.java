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

package org.wso2.carbon.identity.local.auth.smsotp.provider.impl;

import org.apache.http.Header;
import org.apache.http.message.BasicHeader;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.local.auth.smsotp.provider.constant.Constants;
import org.wso2.carbon.identity.local.auth.smsotp.provider.exception.ProviderException;
import org.wso2.carbon.identity.local.auth.smsotp.provider.exception.PublisherException;
import org.wso2.carbon.identity.local.auth.smsotp.provider.http.HTTPPublisher;
import org.wso2.carbon.identity.local.auth.smsotp.provider.internal.SMSNotificationProviderDataHolder;
import org.wso2.carbon.identity.local.auth.smsotp.provider.model.SMSData;
import org.wso2.carbon.identity.notification.sender.tenant.config.NotificationSenderManagementService;
import org.wso2.carbon.identity.notification.sender.tenant.config.dto.Authentication;
import org.wso2.carbon.identity.notification.sender.tenant.config.dto.SMSSenderDTO;
import org.wso2.carbon.identity.notification.sender.tenant.config.exception.NotificationSenderManagementException;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class CustomProviderTest {

    private CustomProvider customProvider;
    private Map<String, String> propertiesMap = new HashMap<>();
    private static final String TO_NUMBER = "+1234567890";

    @Mock
    private SMSSenderDTO smsSenderDTO = Mockito.mock(SMSSenderDTO.class);
    private static MockedStatic<LoggerUtils> mockedLoggerUtils;

    @BeforeClass
    public void setUp() {

        mockedLoggerUtils = mockStatic(LoggerUtils.class);
    }

    @AfterClass
    public void tearDown() {

        if (mockedLoggerUtils != null) {
            mockedLoggerUtils.close();
        }
    }

    @BeforeTest
    public void init() {
        propertiesMap.put(Constants.HTTP_HEADERS, "Authorization: Basic QUNiMziOTIyNT");
        propertiesMap.put(Constants.HTTP_BODY, "Body={{body}}&To={{mobile}}");
        propertiesMap.put(Constants.HTTP_METHOD, "POST");
    }

    @BeforeTest
    public void createNewObject() {
        customProvider = new CustomProvider();
    }

    @Test
    public void testGetName() {
        String name = customProvider.getName();
        Assert.assertNotNull(name);
    }

    @Test(expectedExceptions = ProviderException.class)
    public void testInitNotInit() throws ProviderException {

        SMSData smsData = new SMSData();
        smsData.setToNumber(TO_NUMBER);

        customProvider.send(smsData, smsSenderDTO, "carbon.super");
    }

    @Test
    public void testNullTelephoneNumberTest() {

        SMSData smsData = new SMSData();
        try {
            customProvider.send(smsData, smsSenderDTO, "carbon.super");
        } catch (ProviderException e) {
            Assert.assertEquals(e.getMessage(), "To number is null or blank. Cannot send SMS");
        }
    }

    @Test
    public void testNullTemplateTest() {

        SMSData smsData = new SMSData();
        smsData.setToNumber(TO_NUMBER);
        try {
            customProvider.send(smsData, smsSenderDTO, "carbon.super");
        } catch (ProviderException e) {
            Assert.assertEquals(e.getMessage(), "Template is null or blank. Cannot send SMS");
        }
    }

    @Test(expectedExceptions = {PublisherException.class, ProviderException.class})
    public void testInitSuccess() throws ProviderException {

        when(smsSenderDTO.getProviderURL()).thenReturn("https://localhost:8888");
        when(smsSenderDTO.getKey()).thenReturn("key");
        when(smsSenderDTO.getSecret()).thenReturn("secret");
        when(smsSenderDTO.getSender()).thenReturn("sender");
        when(smsSenderDTO.getContentType()).thenReturn("contentType");

        SMSData smsData = new SMSData();
        smsData.setToNumber(TO_NUMBER);

        customProvider.send(smsData, smsSenderDTO, "carbon.super");
    }

    @Test
    public void testSend() {

        when(smsSenderDTO.getProviderURL()).thenReturn("https://localhost:8888");
        when(smsSenderDTO.getKey()).thenReturn("key");
        when(smsSenderDTO.getSecret()).thenReturn("secret");
        when(smsSenderDTO.getSender()).thenReturn("sender");
        when(smsSenderDTO.getContentType()).thenReturn("contentType");
        when(smsSenderDTO.getProperties()).thenReturn(propertiesMap);

        SMSData smsData = new SMSData();
        smsData.setToNumber(TO_NUMBER);

        try {
            customProvider.send(smsData, smsSenderDTO, "carbon.super");
        } catch (ProviderException e) {
            Assert.assertEquals(e.getMessage(), "Error occurred while publishing the SMS data to the custom provider");
        }
    }

    @Test
    public void resolveFormTemplateTest()
            throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {

        CustomProvider customProvider = new CustomProvider();
        Method method = CustomProvider.class.getDeclaredMethod(
                "resolveTemplate", String.class, String.class, String.class, String.class);
        method.setAccessible(true);

        String template = (String) method.invoke(customProvider,
                Constants.APPLICATION_FORM,
                "Body={{body}}&To={{mobile}}", TO_NUMBER, "Verification Code: 769317");
        Assert.assertEquals(template, "Body=Verification+Code%3A+769317&To=%2B1234567890");
    }

    @Test
    public void  resolveJsonTemplateTest()
            throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {

        CustomProvider customProvider = new CustomProvider();
        Method method = CustomProvider.class.getDeclaredMethod(
                "resolveTemplate", String.class, String.class, String.class, String.class);
        method.setAccessible(true);

        String template = (String) method.invoke(customProvider,
                Constants.APPLICATION_JSON,
                "{\"content\": {{body}},\"to\": {{mobile}}}", TO_NUMBER, "Verification Code: 769317");
        Assert.assertEquals(template, "{\"content\": \"Verification Code: 769317\",\"to\": \"+1234567890\"}");
    }

    @Test
    public void testSendWithAuthentication() throws NotificationSenderManagementException {

        Map<String, String> authProperties = new HashMap<>();
        authProperties.put(Authentication.Property.ACCESS_TOKEN.getName(), "test-token-value");
        CustomProvider customProvider = new CustomProvider();
        Authentication authentication = new Authentication.AuthenticationBuilder(
                Authentication.Type.BEARER.toString(), authProperties).build();

        // Mock the behavior chain using Answer to handle the return type properly
        when(smsSenderDTO.getProviderURL()).thenReturn("https://localhost:8888");
        when(smsSenderDTO.getSender()).thenReturn("sender");
        when(smsSenderDTO.getContentType()).thenReturn("contentType");
        when(smsSenderDTO.getProperties()).thenReturn(propertiesMap);
        when(smsSenderDTO.getAuthentication()).thenReturn(authentication);

        SMSData smsData = new SMSData();
        smsData.setToNumber(TO_NUMBER);

        try {
            customProvider.send(smsData, smsSenderDTO, "carbon.super");
            Assert.assertEquals(smsData.getHeaders().get("authorization"), "Bearer test-token-value");
        } catch (ProviderException e) {
            Assert.assertEquals(e.getMessage(), "Error occurred while publishing the SMS data to the custom provider");
        }
    }

    @Test
    public void testPublishWithNonUnauthorizedError() throws Exception {

        CustomProvider customProvider = new CustomProvider();
        SMSData smsData = new SMSData();
        smsData.setToNumber(TO_NUMBER);
        smsData.setBody("Test message");
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer token123");
        smsData.setHeaders(headers);

        SMSSenderDTO smsSenderDTO = Mockito.mock(SMSSenderDTO.class);
        when(smsSenderDTO.getProviderURL()).thenReturn("https://localhost:8888");

        // Mock HTTPPublisher to throw a non-unauthorized error
        try (MockedConstruction<HTTPPublisher> mockedPublisher = mockConstruction(HTTPPublisher.class,
                (mock, context) -> doThrow(new PublisherException("Server Error"))
                        .when(mock).publish(smsData, "https://localhost:8888"))) {

            Method publishMethod = CustomProvider.class.getDeclaredMethod(
                    "publish", SMSData.class, SMSSenderDTO.class, Map.class);
            publishMethod.setAccessible(true);

            try {
                publishMethod.invoke(customProvider, smsData, smsSenderDTO, headers);
                Assert.fail("Expected PublisherException to be thrown");
            } catch (InvocationTargetException e) {
                Throwable cause = e.getCause();
                // With a different error code, exception should be thrown immediately
                Assert.assertTrue(cause instanceof PublisherException);
            }
        }
    }

    @Test
    public void testPublishWithUnauthorizedErrorAndHeaderUpdate() throws Exception {

        CustomProvider customProvider = new CustomProvider();
        SMSData smsData = new SMSData();
        smsData.setToNumber(TO_NUMBER);
        smsData.setBody("Test message");
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer oldToken");
        headers.put("Content-Type", "application/json");
        smsData.setHeaders(headers);

        SMSSenderDTO smsSenderDTO = Mockito.mock(SMSSenderDTO.class);
        when(smsSenderDTO.getProviderURL()).thenReturn("https://localhost:8888");

        // Mock the data holder and notification service
        SMSNotificationProviderDataHolder dataHolder = Mockito.mock(SMSNotificationProviderDataHolder.class);
        NotificationSenderManagementService notificationService = 
                Mockito.mock(NotificationSenderManagementService.class);
        
        // Create new auth header with different token
        Header newAuthHeader = new BasicHeader("Authorization", "Bearer refreshedToken123");
        when(notificationService.rebuildAuthHeaderWithNewToken(smsSenderDTO)).thenReturn(newAuthHeader);
        when(dataHolder.getNotificationSenderManagementService()).thenReturn(notificationService);

        // Mock HTTPPublisher to throw unauthorized error on first attempt, then continue failing
        try (MockedConstruction<HTTPPublisher> mockedPublisher = mockConstruction(HTTPPublisher.class,
                (mock, context) -> doThrow(new PublisherException(
                        Constants.ErrorMessage.ERROR_UNAUTHORIZED_ACCESS.getCode(),
                        Constants.ErrorMessage.ERROR_UNAUTHORIZED_ACCESS.getMessage()))
                        .when(mock).publish(smsData, "https://localhost:8888"));
             MockedStatic<SMSNotificationProviderDataHolder> mockedDataHolder = 
                mockStatic(SMSNotificationProviderDataHolder.class)) {
            mockedDataHolder.when(SMSNotificationProviderDataHolder::getInstance).thenReturn(dataHolder);

            Method publishMethod = CustomProvider.class.getDeclaredMethod(
                    "publish", SMSData.class, SMSSenderDTO.class, Map.class);
            publishMethod.setAccessible(true);

            try {
                publishMethod.invoke(customProvider, smsData, smsSenderDTO, headers);
            } catch (InvocationTargetException e) {
                // Expected to fail at publish, but headers should be updated
                Throwable cause = e.getCause();
                Assert.assertTrue(cause instanceof PublisherException);
            }

            // Verify that the headers were updated with the new token
            Assert.assertEquals(smsData.getHeaders().get("Authorization"), "Bearer refreshedToken123");
            // Verify that other headers remain unchanged
            Assert.assertEquals(smsData.getHeaders().get("Content-Type"), "application/json");
            
            // Verify that rebuildAuthHeaderWithNewToken was called
            verify(notificationService, times(1)).rebuildAuthHeaderWithNewToken(smsSenderDTO);
        }
    }
}
