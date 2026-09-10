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

import com.sun.net.httpserver.HttpServer;
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
import java.net.InetSocketAddress;
import java.util.HashMap;

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
            Assert.assertEquals(((PublisherException) cause).getProviderStatus(), String.valueOf(responseCode),
                    "The status returned by the SMS provider is not available in the exception for HTTP "
                            + responseCode);
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

        Assert.assertEquals(method.invoke(httpPublisher, "{}", PUBLISHER_URL, mockConnection),
                HttpURLConnection.HTTP_OK, "The status returned by the SMS provider is not returned to the caller.");
    }

    @Test
    public void testPublishSucceedsOnHttpAccepted() throws Exception {

        HttpURLConnection mockConnection = Mockito.mock(HttpURLConnection.class);
        when(mockConnection.getOutputStream()).thenReturn(new ByteArrayOutputStream());
        when(mockConnection.getResponseCode()).thenReturn(HttpURLConnection.HTTP_ACCEPTED);

        Method method = HTTPPublisher.class.getDeclaredMethod(
                "publish", String.class, String.class, HttpURLConnection.class);
        method.setAccessible(true);

        Assert.assertEquals(method.invoke(httpPublisher, "{}", PUBLISHER_URL, mockConnection),
                HttpURLConnection.HTTP_ACCEPTED,
                "The status returned by the SMS provider is not returned to the caller.");
    }

    @Test(expectedExceptions = PublisherException.class)
    public void testPublishAndGetResponseCodeForInvalidURL() throws PublisherException {

        SMSData smsData = new SMSData();
        httpPublisher.publishAndGetResponseCode(smsData, "file://localhost:8080");
    }

    @DataProvider(name = "endToEndResponseCodes")
    public Object[][] endToEndResponseCodes() {

        return new Object[][] {
            {HttpURLConnection.HTTP_OK},
            {HttpURLConnection.HTTP_ACCEPTED},
        };
    }

    /**
     * Publishes against a locally served endpoint so that the full publish path, including reading the status
     * returned by the SMS provider, is covered.
     */
    @Test(dataProvider = "endToEndResponseCodes")
    public void testPublishAndGetResponseCodeReturnsProviderStatus(int responseCode) throws Exception {

        HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.createContext("/sms", exchange -> {
            exchange.sendResponseHeaders(responseCode, -1);
            exchange.close();
        });
        server.start();

        try {
            SMSData smsData = new SMSData();
            smsData.setToNumber("+1234567890");
            smsData.setBody("{\"content\":\"Verification Code: 769317\"}");
            smsData.setContentType(Constants.APPLICATION_JSON);
            smsData.setHttpMethod(Constants.HTTP_POST);
            smsData.setHeaders(new HashMap<>());

            String url = "http://localhost:" + server.getAddress().getPort() + "/sms";
            Assert.assertEquals(httpPublisher.publishAndGetResponseCode(smsData, url), responseCode,
                    "The status returned by the SMS provider should be returned to the caller.");

            // The void variant delegates to the same path and must not fail for a successful response.
            httpPublisher.publish(smsData, url);
        } finally {
            server.stop(0);
        }
    }

    @Test
    public void testPublishAndGetResponseCodeThrowsForServerError() throws Exception {

        HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.createContext("/sms", exchange -> {
            exchange.sendResponseHeaders(HttpURLConnection.HTTP_INTERNAL_ERROR, -1);
            exchange.close();
        });
        server.start();

        try {
            SMSData smsData = new SMSData();
            smsData.setToNumber("+1234567890");
            smsData.setBody("{}");
            smsData.setContentType(Constants.APPLICATION_JSON);
            smsData.setHttpMethod(Constants.HTTP_POST);
            smsData.setHeaders(new HashMap<>());

            String url = "http://localhost:" + server.getAddress().getPort() + "/sms";
            try {
                httpPublisher.publishAndGetResponseCode(smsData, url);
                Assert.fail("Expected PublisherException for HTTP 500");
            } catch (PublisherException e) {
                Assert.assertEquals(e.getErrorCode(), Constants.ErrorMessage.SERVER_ERROR.getCode());
                Assert.assertEquals(e.getProviderStatus(),
                        String.valueOf(HttpURLConnection.HTTP_INTERNAL_ERROR),
                        "The status returned by the SMS provider should be carried in the exception.");
            }
        } finally {
            server.stop(0);
        }
    }
}
