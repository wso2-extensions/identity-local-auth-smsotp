/*
 * Copyright (c) 2023-2026, WSO2 LLC. (https://www.wso2.com).
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

import com.vonage.client.VonageClient;
import com.vonage.client.sms.MessageStatus;
import com.vonage.client.sms.SmsClient;
import com.vonage.client.sms.SmsSubmissionResponse;
import com.vonage.client.sms.SmsSubmissionResponseMessage;
import io.jsonwebtoken.lang.Assert;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.local.auth.smsotp.provider.constant.Constants;
import org.wso2.carbon.identity.local.auth.smsotp.provider.exception.ProviderException;
import org.wso2.carbon.identity.local.auth.smsotp.provider.exception.PublisherException;
import org.wso2.carbon.identity.local.auth.smsotp.provider.model.SMSData;
import org.wso2.carbon.identity.notification.sender.tenant.config.dto.SMSSenderDTO;

import java.lang.reflect.Method;
import java.util.Arrays;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;

public class VonageProviderTest {

    private VonageProvider vonageProvider;

    @Mock
    private SMSSenderDTO smsSenderDTO = Mockito.mock(SMSSenderDTO.class);
    private static MockedStatic<LoggerUtils> mockedLoggerUtils;

    @BeforeClass
    public void setUp() {

        mockedLoggerUtils = mockStatic(LoggerUtils.class);
        /* Diagnostic logging is enabled so that the diagnostic log building code of the provider is
         exercised. The actual log publishing remains mocked out. */
        mockedLoggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);
    }

    @AfterClass
    public void tearDown() {

        if (mockedLoggerUtils != null) {
            mockedLoggerUtils.close();
        }
    }

    @BeforeTest
    public void createNewObject() {
        vonageProvider = new VonageProvider();
    }

    @Test
    public void testGetName() {
        String name = vonageProvider.getName();
        Assert.notNull(name);
    }

    @Test(expectedExceptions = {PublisherException.class, ProviderException.class})
    public void testInitNotInit() throws ProviderException {

        SMSData smsData = new SMSData();
        smsData.setToNumber("1234567890");

        vonageProvider.send(smsData, smsSenderDTO, "carbon.super");
    }

    @Test(expectedExceptions = {ProviderException.class})
    public void testNullTelephoneNumberTest() throws ProviderException {

        SMSData smsData = new SMSData();
        vonageProvider.send(smsData, smsSenderDTO, "carbon.super");
    }

    @Test
    public void testInitSuccess() throws ProviderException {

        when(smsSenderDTO.getProviderURL()).thenReturn("http://localhost:8080");
        when(smsSenderDTO.getKey()).thenReturn("key");
        when(smsSenderDTO.getSecret()).thenReturn("secret");
        when(smsSenderDTO.getSender()).thenReturn("sender");
        when(smsSenderDTO.getContentType()).thenReturn("contentType");

        SMSData smsData = new SMSData();
        smsData.setToNumber("1234567890");

        VonageClient mockClient = Mockito.mock(VonageClient.class);
        SmsClient mockSmsClient = Mockito.mock(SmsClient.class);
        SmsSubmissionResponse mockResponse = Mockito.mock(SmsSubmissionResponse.class);
        SmsSubmissionResponseMessage mockSmsMessage = Mockito.mock(SmsSubmissionResponseMessage.class);
        when(mockSmsMessage.getStatus()).thenReturn(MessageStatus.OK);
        when(mockResponse.getMessages()).thenReturn(Arrays.asList(mockSmsMessage));
        when(mockSmsClient.submitMessage(any())).thenReturn(mockResponse);
        when(mockClient.getSmsClient()).thenReturn(mockSmsClient);

        try (MockedConstruction<VonageClient.Builder> mockedBuilder = mockConstruction(VonageClient.Builder.class,
                (mock, context) -> {
                    when(mock.apiKey(anyString())).thenReturn(mock);
                    when(mock.apiSecret(anyString())).thenReturn(mock);
                    when(mock.build()).thenReturn(mockClient);
                })) {
            vonageProvider.send(smsData, smsSenderDTO, "carbon.super");
        }
    }

    @Test
    public void testSend() throws ProviderException {

        when(smsSenderDTO.getProviderURL()).thenReturn("http://localhost:8080");
        when(smsSenderDTO.getKey()).thenReturn("key");
        when(smsSenderDTO.getSecret()).thenReturn("secret");
        when(smsSenderDTO.getSender()).thenReturn("sender");
        when(smsSenderDTO.getContentType()).thenReturn("contentType");

        SMSData smsData = new SMSData();
        smsData.setToNumber("1234567890");

        VonageClient mockClient = Mockito.mock(VonageClient.class);
        SmsClient mockSmsClient = Mockito.mock(SmsClient.class);
        SmsSubmissionResponse mockResponse = Mockito.mock(SmsSubmissionResponse.class);
        SmsSubmissionResponseMessage mockSmsMessage = Mockito.mock(SmsSubmissionResponseMessage.class);
        when(mockSmsMessage.getStatus()).thenReturn(MessageStatus.OK);
        when(mockResponse.getMessages()).thenReturn(Arrays.asList(mockSmsMessage));
        when(mockSmsClient.submitMessage(any())).thenReturn(mockResponse);
        when(mockClient.getSmsClient()).thenReturn(mockSmsClient);

        try (MockedConstruction<VonageClient.Builder> mockedBuilder = mockConstruction(VonageClient.Builder.class,
                (mock, context) -> {
                    when(mock.apiKey(anyString())).thenReturn(mock);
                    when(mock.apiSecret(anyString())).thenReturn(mock);
                    when(mock.build()).thenReturn(mockClient);
                })) {
            vonageProvider.send(smsData, smsSenderDTO, "carbon.super");
        }
    }

    @Test
    public void testSendLogsProviderStatusWhenSubmissionFails() {

        when(smsSenderDTO.getKey()).thenReturn("key");
        when(smsSenderDTO.getSecret()).thenReturn("secret");
        when(smsSenderDTO.getSender()).thenReturn("sender");

        SMSData smsData = new SMSData();
        smsData.setToNumber("1234567890");

        VonageClient mockClient = Mockito.mock(VonageClient.class);
        SmsClient mockSmsClient = Mockito.mock(SmsClient.class);
        SmsSubmissionResponse mockResponse = Mockito.mock(SmsSubmissionResponse.class);
        SmsSubmissionResponseMessage mockSmsMessage = Mockito.mock(SmsSubmissionResponseMessage.class);
        when(mockSmsMessage.getStatus()).thenReturn(MessageStatus.THROTTLED);
        when(mockSmsMessage.getErrorText()).thenReturn("Throttled");
        when(mockResponse.getMessages()).thenReturn(Arrays.asList(mockSmsMessage));
        when(mockSmsClient.submitMessage(any())).thenReturn(mockResponse);
        when(mockClient.getSmsClient()).thenReturn(mockSmsClient);

        try (MockedConstruction<VonageClient.Builder> mockedBuilder = mockConstruction(VonageClient.Builder.class,
                (mock, context) -> {
                    when(mock.apiKey(anyString())).thenReturn(mock);
                    when(mock.apiSecret(anyString())).thenReturn(mock);
                    when(mock.build()).thenReturn(mockClient);
                })) {
            vonageProvider.send(smsData, smsSenderDTO, "carbon.super");
            Assert.isTrue(false, "Expected ProviderException when Vonage reports a non OK status");
        } catch (ProviderException e) {
            Assert.isTrue(Constants.ErrorMessage.TOO_MANY_REQUESTS.getCode().equals(e.getErrorCode()),
                    "The Vonage status should be mapped to the corresponding error code");
        }
    }

    @DataProvider(name = "vonageErrorStatuses")
    public Object[][] vonageErrorStatuses() {

        return new Object[][]{
                {null, Constants.ErrorMessage.MESSAGE_DELIVERY_FAILED},
                {MessageStatus.THROTTLED, Constants.ErrorMessage.TOO_MANY_REQUESTS},
                {MessageStatus.INVALID_CREDENTIALS, Constants.ErrorMessage.UNAUTHORIZED},
                {MessageStatus.INTERNAL_ERROR, Constants.ErrorMessage.SERVER_ERROR},
                {MessageStatus.PARTNER_QUOTA_EXCEEDED, Constants.ErrorMessage.ACCOUNT_LIMIT_EXCEEDED},
                {MessageStatus.NUMBER_BARRED, Constants.ErrorMessage.NUMBER_BARRED},
                {MessageStatus.MISSING_PARAMS, Constants.ErrorMessage.INVALID_CONFIGURATION},
                {MessageStatus.INVALID_PARAMS, Constants.ErrorMessage.INVALID_CONFIGURATION},
                {MessageStatus.PARTNER_ACCOUNT_BARRED, Constants.ErrorMessage.ACCOUNT_SUSPENDED},
                {MessageStatus.UNKNOWN, Constants.ErrorMessage.MESSAGE_DELIVERY_FAILED},
        };
    }

    @Test(dataProvider = "vonageErrorStatuses")
    public void testResolveVonageError(MessageStatus status, Constants.ErrorMessage expected) throws Exception {

        Method method = VonageProvider.class.getDeclaredMethod("resolveVonageError", MessageStatus.class);
        method.setAccessible(true);

        Constants.ErrorMessage result = (Constants.ErrorMessage) method.invoke(vonageProvider, status);
        assertEquals(result, expected,
                "resolveVonageError(" + status + ") should return " + expected);
    }
}
