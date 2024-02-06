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

package org.wso2.carbon.identity.local.auth.smsotp.provider.model;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * This class represents the SMS data.
 *
 * @version 1.0.0
 * @since 1.0.0
 */
public class SMSData implements Serializable {

    private static final long serialVersionUID = 350777056982260622L;
    private String body;
    private String toNumber;
    private String contentType;
    private String httpMethod;
    private Map<String, String> headers = new HashMap<>();

    /**
     * Returns the body.
     *
     * @return Body.
     */
    public String getBody() {
        return body;
    }

    /**
     * Returns the content type.
     *
     * @return Content type.
     */
    public String getContentType() {
        return contentType;
    }

    /**
     * Returns the headers.
     *
     * @return Headers.
     */
    public Map<String, String> getHeaders() {
        return Collections.unmodifiableMap(headers);
    }

    /**
     * Returns the HTTP method.
     *
     * @return HTTP method.
     */
    public String getHttpMethod() {
        return httpMethod;
    }

    /**
     * Returns the to number.
     *
     * @return To number.
     */
    public String getToNumber() {
        return toNumber;
    }

    /**
     * Sets the body.
     *
     * @param body Body.
     */
    public void setBody(String body) {
        this.body = body;
    }

    /**
     * Sets the content type.
     *
     * @param contentType Content type.
     */
    public void setContentType(String contentType) {
        this.contentType = contentType;
    }

    /**
     * Sets the headers.
     *
     * @param headers Headers.
     */
    public void setHeaders(Map<String, String> headers) {
        this.headers = new HashMap<>(headers);
    }

    /**
     * Sets the HTTP method.
     *
     * @param httpMethod HTTP method.
     */
    public void setHttpMethod(String httpMethod) {
        this.httpMethod = httpMethod;
    }

    /**
     * Sets the to number.
     *
     * @param toNumber To number.
     */
    public void setToNumber(String toNumber) {
        this.toNumber = toNumber;
    }
}
