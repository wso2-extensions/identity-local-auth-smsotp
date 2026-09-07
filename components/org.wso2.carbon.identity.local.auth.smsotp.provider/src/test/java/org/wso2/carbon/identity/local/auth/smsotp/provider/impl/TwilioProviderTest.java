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

import com.twilio.Twilio;
import com.twilio.exception.ApiException;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.rest.api.v2010.account.MessageCreator;
import com.twilio.type.PhoneNumber;
import io.jsonwebtoken.lang.Assert;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
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
import org.wso2.carbon.utils.DiagnosticLog;

import java.lang.reflect.Method;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

public class TwilioProviderTest {

    private TwilioProvider twilioProvider;

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
        twilioProvider = new TwilioProvider();
    }

    @Test
    public void testGetName() {
        String name = twilioProvider.getName();
        Assert.notNull(name);
    }

    @Test(expectedExceptions = {PublisherException.class, ProviderException.class})
    public void testInitNotInit() throws ProviderException {

        SMSData smsData = new SMSData();
        smsData.setToNumber("1234567890");

        twilioProvider.send(smsData, smsSenderDTO, "carbon.super");
    }

    @Test(expectedExceptions = {ProviderException.class})
    public void testNullTelephoneNumberTest() throws ProviderException {

        SMSData smsData = new SMSData();
        twilioProvider.send(smsData, smsSenderDTO, "carbon.super");
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

        MessageCreator mockCreator = Mockito.mock(MessageCreator.class);
        Message mockMessage = Mockito.mock(Message.class);
        when(mockMessage.getStatus()).thenReturn(Message.Status.SENT);
        when(mockCreator.create()).thenReturn(mockMessage);

        try (MockedStatic<Twilio> mockedTwilio = mockStatic(Twilio.class);
             MockedStatic<Message> mockedMessage = mockStatic(Message.class)) {
            mockedMessage.when(() -> Message.creator(any(PhoneNumber.class), any(PhoneNumber.class),
                            nullable(String.class)))
                    .thenReturn(mockCreator);
            twilioProvider.send(smsData, smsSenderDTO, "carbon.super");
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

        MessageCreator mockCreator = Mockito.mock(MessageCreator.class);
        Message mockMessage = Mockito.mock(Message.class);
        when(mockMessage.getStatus()).thenReturn(Message.Status.SENT);
        when(mockCreator.create()).thenReturn(mockMessage);

        try (MockedStatic<Twilio> mockedTwilio = mockStatic(Twilio.class);
             MockedStatic<Message> mockedMessage = mockStatic(Message.class)) {
            mockedMessage.when(() -> Message.creator(any(PhoneNumber.class), any(PhoneNumber.class),
                            nullable(String.class)))
                    .thenReturn(mockCreator);
            twilioProvider.send(smsData, smsSenderDTO, "carbon.super");
        }
    }

    @Test
    public void testSendLogsProviderStatusWhenMessageFails() {

        when(smsSenderDTO.getKey()).thenReturn("key");
        when(smsSenderDTO.getSecret()).thenReturn("secret");
        when(smsSenderDTO.getSender()).thenReturn("sender");

        SMSData smsData = new SMSData();
        smsData.setToNumber("1234567890");

        MessageCreator mockCreator = Mockito.mock(MessageCreator.class);
        Message mockMessage = Mockito.mock(Message.class);
        when(mockMessage.getStatus()).thenReturn(Message.Status.FAILED);
        when(mockMessage.getErrorCode()).thenReturn(30003);
        when(mockMessage.getErrorMessage()).thenReturn("Unreachable destination handset");
        when(mockCreator.create()).thenReturn(mockMessage);

        try (MockedStatic<Twilio> mockedTwilio = mockStatic(Twilio.class);
             MockedStatic<Message> mockedMessage = mockStatic(Message.class)) {
            mockedMessage.when(() -> Message.creator(any(PhoneNumber.class), any(PhoneNumber.class),
                            nullable(String.class)))
                    .thenReturn(mockCreator);
            twilioProvider.send(smsData, smsSenderDTO, "carbon.super");
            Assert.isTrue(false, "Expected ProviderException when Twilio reports a FAILED message status");
        } catch (ProviderException e) {
            /* The exception raised for a FAILED message status is re-wrapped by the generic catch block of
             TwilioProvider#send, so the resolved error code is carried by the cause. */
            Assert.isInstanceOf(ProviderException.class, e.getCause());
            assertEquals(((ProviderException) e.getCause()).getErrorCode(),
                    Constants.ErrorMessage.UNDELIVERABLE_NUMBER.getCode());
        }
    }

    /**
     * Test that a status which Twilio does not report as failed, but which does not confirm the message was
     * accepted, is recorded as a failed diagnostic log carrying the reported status rather than as a sent SMS.
     */
    @Test
    public void testSendDoesNotClaimSuccessForUndeliveredStatus() throws ProviderException {

        when(smsSenderDTO.getKey()).thenReturn("key");
        when(smsSenderDTO.getSecret()).thenReturn("secret");
        when(smsSenderDTO.getSender()).thenReturn("sender");

        SMSData smsData = new SMSData();
        smsData.setToNumber("1234567890");

        MessageCreator mockCreator = Mockito.mock(MessageCreator.class);
        Message mockMessage = Mockito.mock(Message.class);
        when(mockMessage.getStatus()).thenReturn(Message.Status.UNDELIVERED);
        when(mockCreator.create()).thenReturn(mockMessage);

        try (MockedStatic<Twilio> mockedTwilio = mockStatic(Twilio.class);
             MockedStatic<Message> mockedMessage = mockStatic(Message.class)) {
            mockedMessage.when(() -> Message.creator(any(PhoneNumber.class), any(PhoneNumber.class),
                            nullable(String.class)))
                    .thenReturn(mockCreator);

            twilioProvider.send(smsData, smsSenderDTO, "carbon.super");

            DiagnosticLog diagnosticLog = captureLastDiagnosticLog();
            assertEquals(diagnosticLog.getResultStatus(), DiagnosticLog.ResultStatus.FAILED.name(),
                    "An undelivered SMS should not be recorded as a successfully sent SMS.");
            assertEquals(diagnosticLog.getInput().get(Constants.InputKeys.PROVIDER_STATUS),
                    Message.Status.UNDELIVERED.toString(),
                    "The status reported by the provider should be recorded in the log.");
        }
    }

    /**
     * Test that a message for which Twilio reports no status at all is not recorded as a failure. The provider not
     * reporting a status is not the provider rejecting the SMS, and the request did reach the provider.
     */
    @Test
    public void testSendDoesNotClaimFailureWhenNoStatusIsReported() throws ProviderException {

        when(smsSenderDTO.getKey()).thenReturn("key");
        when(smsSenderDTO.getSecret()).thenReturn("secret");
        when(smsSenderDTO.getSender()).thenReturn("sender");

        SMSData smsData = new SMSData();
        smsData.setToNumber("1234567890");

        MessageCreator mockCreator = Mockito.mock(MessageCreator.class);
        Message mockMessage = Mockito.mock(Message.class);
        when(mockMessage.getStatus()).thenReturn(null);
        when(mockCreator.create()).thenReturn(mockMessage);

        try (MockedStatic<Twilio> mockedTwilio = mockStatic(Twilio.class);
             MockedStatic<Message> mockedMessage = mockStatic(Message.class)) {
            mockedMessage.when(() -> Message.creator(any(PhoneNumber.class), any(PhoneNumber.class),
                            nullable(String.class)))
                    .thenReturn(mockCreator);

            twilioProvider.send(smsData, smsSenderDTO, "carbon.super");

            DiagnosticLog diagnosticLog = captureLastDiagnosticLog();
            assertEquals(diagnosticLog.getResultStatus(), DiagnosticLog.ResultStatus.SUCCESS.name(),
                    "A missing provider status should not be recorded as a failed send.");
            assertNull(diagnosticLog.getInput().get(Constants.InputKeys.PROVIDER_STATUS),
                    "No provider status should be recorded when the provider did not report one.");
            assertTrue(diagnosticLog.getResultMessage().contains("reported no status"),
                    "The log should state that the provider reported no status instead of claiming it accepted "
                            + "the SMS.");
        }
    }

    /**
     * Test that a successfully accepted SMS is recorded as a success along with the status reported by Twilio.
     */
    @Test
    public void testSendLogsProviderStatusOnSuccess() throws ProviderException {

        when(smsSenderDTO.getKey()).thenReturn("key");
        when(smsSenderDTO.getSecret()).thenReturn("secret");
        when(smsSenderDTO.getSender()).thenReturn("sender");

        SMSData smsData = new SMSData();
        smsData.setToNumber("1234567890");

        MessageCreator mockCreator = Mockito.mock(MessageCreator.class);
        Message mockMessage = Mockito.mock(Message.class);
        when(mockMessage.getStatus()).thenReturn(Message.Status.QUEUED);
        when(mockCreator.create()).thenReturn(mockMessage);

        try (MockedStatic<Twilio> mockedTwilio = mockStatic(Twilio.class);
             MockedStatic<Message> mockedMessage = mockStatic(Message.class)) {
            mockedMessage.when(() -> Message.creator(any(PhoneNumber.class), any(PhoneNumber.class),
                            nullable(String.class)))
                    .thenReturn(mockCreator);

            twilioProvider.send(smsData, smsSenderDTO, "carbon.super");

            DiagnosticLog diagnosticLog = captureLastDiagnosticLog();
            assertEquals(diagnosticLog.getResultStatus(), DiagnosticLog.ResultStatus.SUCCESS.name(),
                    "An accepted SMS should be recorded as a successful send.");
            assertEquals(diagnosticLog.getInput().get(Constants.InputKeys.PROVIDER_STATUS),
                    Message.Status.QUEUED.toString(),
                    "The status reported by the provider should be recorded in the log.");
        }
    }

    /**
     * Returns the diagnostic log built by the most recent triggerDiagnosticLogEvent invocation. The LoggerUtils
     * mock is scoped to the class, so invocations accumulate across tests and only the last one is relevant.
     */
    private DiagnosticLog captureLastDiagnosticLog() {

        ArgumentCaptor<DiagnosticLog.DiagnosticLogBuilder> captor =
                ArgumentCaptor.forClass(DiagnosticLog.DiagnosticLogBuilder.class);
        mockedLoggerUtils.verify(() -> LoggerUtils.triggerDiagnosticLogEvent(captor.capture()),
                Mockito.atLeastOnce());
        return captor.getValue().build();
    }

    @Test
    public void testSendLogsProviderStatusWhenApiExceptionIsThrown() {

        when(smsSenderDTO.getKey()).thenReturn("key");
        when(smsSenderDTO.getSecret()).thenReturn("secret");
        when(smsSenderDTO.getSender()).thenReturn("sender");

        SMSData smsData = new SMSData();
        smsData.setToNumber("1234567890");

        MessageCreator mockCreator = Mockito.mock(MessageCreator.class);
        when(mockCreator.create()).thenThrow(new ApiException("Authenticate", 20003, null, 401, null));

        try (MockedStatic<Twilio> mockedTwilio = mockStatic(Twilio.class);
             MockedStatic<Message> mockedMessage = mockStatic(Message.class)) {
            mockedMessage.when(() -> Message.creator(any(PhoneNumber.class), any(PhoneNumber.class),
                            nullable(String.class)))
                    .thenReturn(mockCreator);
            twilioProvider.send(smsData, smsSenderDTO, "carbon.super");
            Assert.isTrue(false, "Expected ProviderException when Twilio returns an API error");
        } catch (ProviderException e) {
            assertEquals(e.getErrorCode(), Constants.ErrorMessage.UNAUTHORIZED.getCode());
        }
    }

    @DataProvider(name = "twilioMessageErrorCodes")
    public Object[][] twilioMessageErrorCodes() {

        return new Object[][]{
                {null, Constants.ErrorMessage.MESSAGE_DELIVERY_FAILED},
                {30001, Constants.ErrorMessage.TOO_MANY_REQUESTS},
                {30002, Constants.ErrorMessage.ACCOUNT_SUSPENDED},
                {30003, Constants.ErrorMessage.UNDELIVERABLE_NUMBER},
                {30004, Constants.ErrorMessage.CARRIER_FILTERED},
                {30005, Constants.ErrorMessage.UNDELIVERABLE_NUMBER},
                {30006, Constants.ErrorMessage.UNDELIVERABLE_NUMBER},
                {30007, Constants.ErrorMessage.CARRIER_FILTERED},
                {99999, Constants.ErrorMessage.MESSAGE_DELIVERY_FAILED},
        };
    }

    @Test(dataProvider = "twilioMessageErrorCodes")
    public void testResolveTwilioMessageError(Integer twilioErrorCode, Constants.ErrorMessage expected)
            throws Exception {

        Method method = TwilioProvider.class.getDeclaredMethod("resolveTwilioMessageError", Integer.class);
        method.setAccessible(true);

        Constants.ErrorMessage result = (Constants.ErrorMessage) method.invoke(twilioProvider, twilioErrorCode);
        assertEquals(result, expected,
                "resolveTwilioMessageError(" + twilioErrorCode + ") should return " + expected);
    }

    @DataProvider(name = "twilioApiErrorCodes")
    public Object[][] twilioApiErrorCodes() {

        return new Object[][]{
                {null, Constants.ErrorMessage.SMS_SEND_FAILED},
                {400, Constants.ErrorMessage.BAD_REQUEST},
                {401, Constants.ErrorMessage.UNAUTHORIZED},
                {403, Constants.ErrorMessage.FORBIDDEN},
                {429, Constants.ErrorMessage.TOO_MANY_REQUESTS},
                {500, Constants.ErrorMessage.SERVER_ERROR},
                {503, Constants.ErrorMessage.SERVER_ERROR},
                {404, Constants.ErrorMessage.SMS_SEND_FAILED},
        };
    }

    @Test(dataProvider = "twilioApiErrorCodes")
    public void testResolveTwilioApiError(Integer httpStatus, Constants.ErrorMessage expected) throws Exception {

        Method method = TwilioProvider.class.getDeclaredMethod("resolveTwilioApiError", Integer.class);
        method.setAccessible(true);

        Constants.ErrorMessage result = (Constants.ErrorMessage) method.invoke(twilioProvider, httpStatus);
        assertEquals(result, expected,
                "resolveTwilioApiError(" + httpStatus + ") should return " + expected);
    }
}
