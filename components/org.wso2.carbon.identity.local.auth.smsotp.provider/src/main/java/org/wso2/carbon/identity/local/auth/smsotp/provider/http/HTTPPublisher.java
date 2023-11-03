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
import com.fasterxml.jackson.databind.ObjectMapper;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.local.auth.smsotp.provider.constant.Constants;
import org.wso2.carbon.identity.local.auth.smsotp.provider.exception.PublisherException;
import org.wso2.carbon.identity.local.auth.smsotp.provider.model.SMSData;
import org.wso2.carbon.identity.local.auth.smsotp.provider.model.SMSMetadata;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.nio.charset.StandardCharsets;

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
            ObjectMapper objectMapper = new ObjectMapper();
            String json = objectMapper.writeValueAsString(smsData);
            URL url = new URL(publisherURL);
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod(Constants.POST);
            connection.setRequestProperty(Constants.CONTENT_TYPE, Constants.APPLICATION_JSON);
            SMSMetadata smsMetadata = smsData.getSmsMetadata();
            if (smsMetadata.getKey() != null) {
                connection.setRequestProperty(Constants.KEY, smsMetadata.getKey());
            }
            if (smsMetadata.getSecret() != null) {
                connection.setRequestProperty(Constants.SECRET, smsMetadata.getSecret());
            }
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
            } else {
                log.warn("Error occurred while publishing the sms data to the: " + publisherURL);
            }
        } catch (JsonProcessingException e) {
            throw new PublisherException("Error while converting the SMSData object to JSON", e);
        } catch (ProtocolException e) {
            throw new PublisherException("Error while setting the request method to POST", e);
        } catch (MalformedURLException e) {
            throw new PublisherException("Error while creating the URL object", e);
        } catch (IOException e) {
            throw new PublisherException("Error while opening the connection", e);
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
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
}
