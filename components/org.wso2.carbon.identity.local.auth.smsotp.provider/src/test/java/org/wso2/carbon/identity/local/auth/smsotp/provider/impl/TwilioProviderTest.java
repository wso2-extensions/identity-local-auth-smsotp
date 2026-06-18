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

import io.jsonwebtoken.lang.Assert;
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

import java.lang.reflect.Method;

import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;

public class TwilioProviderTest {

    private TwilioProvider twilioProvider;

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

        twilioProvider.send(smsData, smsSenderDTO, "carbon.super");
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

        twilioProvider.send(smsData, smsSenderDTO, "carbon.super");
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
