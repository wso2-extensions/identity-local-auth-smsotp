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

import static org.wso2.carbon.identity.local.auth.smsotp.provider.constant.Constants.UNAUTHORIZED_ACCESS_ERROR_MSG;

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
    @SuppressFBWarnings("URLCONNECTION_SSRF_FD")
    public void publish(SMSData smsData, String publisherURL) throws PublisherException {

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

            publish(json, publisherURL, connection);
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

    private void publish(String json, String publisherURL, HttpURLConnection connection)
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
        } else if (responseCode == HttpURLConnection.HTTP_UNAUTHORIZED) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Unauthorized access while publishing the sms data to the: %s. " +
                        "Response code: %s.", publisherURL, responseCode));
            }
            throw new PublisherException(UNAUTHORIZED_ACCESS_ERROR_MSG);
        } else {
            log.warn("Error occurred while publishing the sms data to the: " + publisherURL
                    + ". Response code: " + responseCode);
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
            throw new PublisherException("", e);
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
