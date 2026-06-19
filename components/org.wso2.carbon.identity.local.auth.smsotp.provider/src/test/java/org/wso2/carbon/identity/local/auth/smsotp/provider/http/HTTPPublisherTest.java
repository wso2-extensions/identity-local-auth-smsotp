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

package org.wso2.carbon.identity.local.auth.smsotp.provider.http;

import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.local.auth.smsotp.provider.constant.Constants;
import org.wso2.carbon.identity.local.auth.smsotp.provider.exception.PublisherException;
import org.wso2.carbon.identity.local.auth.smsotp.provider.model.SMSData;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;

import static org.mockito.Mockito.when;

public class HTTPPublisherTest {

    private HTTPPublisher httpPublisher;
    private static final String PUBLISHER_URL = "https://localhost:8888";

    @BeforeTest
    public void setUp() {
        httpPublisher = new HTTPPublisher();
    }

    @Test(expectedExceptions = PublisherException.class)
    public void testForInvalidURL() throws PublisherException {

        SMSData smsData = new SMSData();
        httpPublisher.publish(smsData, "file://localhost:8080");
    }

    @Test(expectedExceptions = PublisherException.class)
    public void testPublisherExceptionCase() throws PublisherException {

        SMSData smsData = new SMSData();
        httpPublisher.publish(smsData, "https://localhost:8888");
    }

    @DataProvider(name = "errorResponseCodes")
    public Object[][] errorResponseCodes() {

        return new Object[][] {
            {HttpURLConnection.HTTP_UNAUTHORIZED, Constants.ErrorMessage.UNAUTHORIZED.getCode()},
            {HttpURLConnection.HTTP_BAD_REQUEST,  Constants.ErrorMessage.BAD_REQUEST.getCode()},
            {HttpURLConnection.HTTP_FORBIDDEN,    Constants.ErrorMessage.FORBIDDEN.getCode()},
            {HttpURLConnection.HTTP_NOT_FOUND,    Constants.ErrorMessage.SERVICE_UNREACHABLE.getCode()},
            {429,                                 Constants.ErrorMessage.TOO_MANY_REQUESTS.getCode()},
            {HttpURLConnection.HTTP_INTERNAL_ERROR, Constants.ErrorMessage.SERVER_ERROR.getCode()},
            {503,                                 Constants.ErrorMessage.SERVER_ERROR.getCode()},
            {409,                                 Constants.ErrorMessage.SMS_SEND_FAILED.getCode()},
        };
    }

    @Test(dataProvider = "errorResponseCodes")
    public void testPublishThrowsCorrectErrorCodeForResponseCode(int responseCode, String expectedErrorCode)
            throws Exception {

        HttpURLConnection mockConnection = Mockito.mock(HttpURLConnection.class);
        when(mockConnection.getOutputStream()).thenReturn(new ByteArrayOutputStream());
        when(mockConnection.getResponseCode()).thenReturn(responseCode);

        Method method = HTTPPublisher.class.getDeclaredMethod(
                "publish", String.class, String.class, HttpURLConnection.class);
        method.setAccessible(true);

        try {
            method.invoke(httpPublisher, "{}", PUBLISHER_URL, mockConnection);
            Assert.fail("Expected PublisherException for HTTP " + responseCode);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            Assert.assertTrue(cause instanceof PublisherException,
                    "Expected PublisherException but got: " + cause.getClass().getName());
            Assert.assertEquals(((PublisherException) cause).getErrorCode(), expectedErrorCode,
                    "Wrong error code for HTTP " + responseCode);
        }
    }

    @Test
    public void testPublishSucceedsOnHttpOk() throws Exception {

        HttpURLConnection mockConnection = Mockito.mock(HttpURLConnection.class);
        when(mockConnection.getOutputStream()).thenReturn(new ByteArrayOutputStream());
        when(mockConnection.getResponseCode()).thenReturn(HttpURLConnection.HTTP_OK);

        Method method = HTTPPublisher.class.getDeclaredMethod(
                "publish", String.class, String.class, HttpURLConnection.class);
        method.setAccessible(true);

        method.invoke(httpPublisher, "{}", PUBLISHER_URL, mockConnection);
    }

    @Test
    public void testPublishSucceedsOnHttpAccepted() throws Exception {

        HttpURLConnection mockConnection = Mockito.mock(HttpURLConnection.class);
        when(mockConnection.getOutputStream()).thenReturn(new ByteArrayOutputStream());
        when(mockConnection.getResponseCode()).thenReturn(HttpURLConnection.HTTP_ACCEPTED);

        Method method = HTTPPublisher.class.getDeclaredMethod(
                "publish", String.class, String.class, HttpURLConnection.class);
        method.setAccessible(true);

        method.invoke(httpPublisher, "{}", PUBLISHER_URL, mockConnection);
    }
}
