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

import com.fasterxml.jackson.core.JsonProcessingException;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.local.auth.smsotp.provider.constant.Constants;
import org.wso2.carbon.identity.local.auth.smsotp.provider.exception.PublisherException;
import org.wso2.carbon.identity.local.auth.smsotp.provider.model.SMSData;
import org.wso2.carbon.identity.local.auth.smsotp.provider.util.ProviderUtil;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.wso2.carbon.identity.local.auth.smsotp.provider.constant.Constants.ErrorMessage.UNAUTHORIZED;

/**
 * This class will be used to publish the SMS to the custom SMS provider using the HTTP protocol.
 *
 * @version 1.0.0
 * @since 1.0.0
 */
public class HTTPPublisher {

    private static final Log log = LogFactory.getLog(HTTPPublisher.class);

    /**
     * This method will publish the {@link SMSData} as a JSON to the provided publisher URL.
     * @param smsData {@link SMSData} object
     */
    public void publish(SMSData smsData, String publisherURL) throws PublisherException {

        publishAndGetResponseCode(smsData, publisherURL);
    }

    /**
     * This method will publish the {@link SMSData} as a JSON to the provided publisher URL and return the HTTP
     * status code returned by the SMS provider. The status code is returned so that the response of the SMS
     * provider can be included in the logs of the SMS sending flow.
     *
     * @param smsData      {@link SMSData} object.
     * @param publisherURL URL of the SMS provider.
     * @return HTTP status code returned by the SMS provider.
     * @throws PublisherException If the SMS could not be published to the SMS provider.
     */
    @SuppressFBWarnings("URLCONNECTION_SSRF_FD")
    public int publishAndGetResponseCode(SMSData smsData, String publisherURL) throws PublisherException {

        // Validate the publisher URL for the protocol and format.
        validateURL(publisherURL);

        HttpURLConnection connection = null;
        try {
            String json = smsData.getBody();
            URL url = new URL(publisherURL);
            connection = (HttpURLConnection) url.openConnection();
            connection.setConnectTimeout(getConnectionTimeout());
            connection.setReadTimeout(getReadTimeout());

            Map<String, String> headers = smsData.getHeaders();
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                connection.setRequestProperty(entry.getKey().trim(), entry.getValue().trim());
            }

            if (StringUtils.isNotBlank(smsData.getContentType())) {
                connection.setRequestProperty(Constants.CONTENT_TYPE, smsData.getContentType());
            } else {
                connection.setRequestProperty(Constants.CONTENT_TYPE, Constants.APPLICATION_JSON);
            }

            if (StringUtils.isNotBlank(smsData.getHttpMethod())) {
                connection.setRequestMethod(smsData.getHttpMethod());
            } else {
                connection.setRequestMethod(Constants.HTTP_POST);
            }

            return publish(json, publisherURL, connection);
        } catch (JsonProcessingException e) {
            throw new PublisherException("Error while converting the SMSData object to JSON", e);
        } catch (ProtocolException e) {
            throw new PublisherException("Error while setting the request method to POST", e);
        } catch (MalformedURLException e) {
            throw new PublisherException("Error while creating the URL object", e);
        } catch (IOException e) {
            if (e instanceof SocketTimeoutException) {
                log.warn("Timeout while publishing SMS to provider: " + publisherURL + " (connectTimeout=" +
                        getConnectionTimeout() + "ms, readTimeout=" + getReadTimeout() + "ms)");
            }
            throw new PublisherException("Error while opening the connection", e);
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private int publish(String json, String publisherURL, HttpURLConnection connection)
            throws IOException, PublisherException {

        connection.setDoOutput(true);
        try (OutputStream os = connection.getOutputStream()) {
            byte[] input = json.getBytes(StandardCharsets.UTF_8);
            os.write(input, 0, input.length);
        }
        int responseCode = connection.getResponseCode();
        if (responseCode == HttpURLConnection.HTTP_OK || responseCode == HttpURLConnection.HTTP_ACCEPTED) {
            if (log.isDebugEnabled()) {
                log.debug("Successfully published the sms data to the: " + publisherURL);
                log.debug("JSON data: " + json);
            }
            return responseCode;
        }

        String providerStatus = String.valueOf(responseCode);
        if (responseCode == HttpURLConnection.HTTP_UNAUTHORIZED) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Unauthorized access while publishing the sms data to the: %s. " +
                        "Response code: %s.", publisherURL, responseCode));
            }
            throw new PublisherException(UNAUTHORIZED.getCode(), UNAUTHORIZED.getMessage(), providerStatus);
        }

        log.warn("Error occurred while publishing the sms data to the: " + publisherURL
                    + ". Response code: " + responseCode);

        if (responseCode == HttpURLConnection.HTTP_BAD_REQUEST) {
            throw new PublisherException(Constants.ErrorMessage.BAD_REQUEST.getCode(),
                    Constants.ErrorMessage.BAD_REQUEST.getMessage(), providerStatus);
        } else if (responseCode == HttpURLConnection.HTTP_FORBIDDEN) {
            throw new PublisherException(Constants.ErrorMessage.FORBIDDEN.getCode(),
                    Constants.ErrorMessage.FORBIDDEN.getMessage(), providerStatus);
        } else if (responseCode == HttpURLConnection.HTTP_NOT_FOUND) {
            throw new PublisherException(Constants.ErrorMessage.SERVICE_UNREACHABLE.getCode(),
                    Constants.ErrorMessage.SERVICE_UNREACHABLE.getMessage(), providerStatus);
        } else if (responseCode == 429) {
            throw new PublisherException(Constants.ErrorMessage.TOO_MANY_REQUESTS.getCode(),
                    Constants.ErrorMessage.TOO_MANY_REQUESTS.getMessage(), providerStatus);
        } else if (responseCode >= HttpURLConnection.HTTP_INTERNAL_ERROR) {
            throw new PublisherException(Constants.ErrorMessage.SERVER_ERROR.getCode(),
                    Constants.ErrorMessage.SERVER_ERROR.getMessage(), providerStatus);
        } else {
            throw new PublisherException(Constants.ErrorMessage.SMS_SEND_FAILED.getCode(),
                    Constants.ErrorMessage.SMS_SEND_FAILED.getMessage(), providerStatus);
        }
    }

    /**
     * This method will validate the publisher URL for the protocol and format for security purposes.
     * @param stringURL Publisher URL.
     * @throws PublisherException If URL validation failed.
     */
    private void validateURL(String stringURL) throws PublisherException {
        try {
            URL url = new URL(stringURL);
            if (!url.getProtocol().equals("http") && !url.getProtocol().equals("https")) {
                throw new PublisherException("Invalid protocol. Protocol should be either http or https.");
            }
        } catch (MalformedURLException e) {
            throw new PublisherException(Constants.ErrorMessage.INVALID_CONFIGURATION.getCode(),
                    Constants.ErrorMessage.INVALID_CONFIGURATION.getMessage(), e);
        }
    }

    private int getConnectionTimeout() {

        return ProviderUtil.parsePositiveOrDefault(
                IdentityUtil.getProperty(Constants.HTTP_URL_CONNECTION_TIMEOUT_CONFIG),
                Constants.DEFAULT_HTTP_URL_CONNECTION_TIMEOUT);
    }

    private int getReadTimeout() {

        return ProviderUtil.parsePositiveOrDefault(
                IdentityUtil.getProperty(Constants.HTTP_URL_CONNECTION_READ_TIMEOUT_CONFIG),
                Constants.DEFAULT_HTTP_URL_CONNECTION_READ_TIMEOUT);
    }
}
