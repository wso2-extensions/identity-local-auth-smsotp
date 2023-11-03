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

/**
 * This class represents the SMS metadata.
 *
 * @version 1.0.0
 * @since 1.0.0
 */
public class SMSMetadata implements Serializable {

    private static final long serialVersionUID = 7299661568503550394L;
    private String key;
    private String secret;
    private String sender;
    private String contentType;
    private String tenantDomain;

    public SMSMetadata() {
        super();
    }

    public SMSMetadata(SMSMetadata smsMetadata) {
        this.key = smsMetadata.getKey();
        this.secret = smsMetadata.getSecret();
        this.sender = smsMetadata.getSender();
        this.contentType = smsMetadata.getContentType();
        this.tenantDomain = smsMetadata.getTenantDomain();
    }

    /**
     * Returns the key.
     *
     * @return Key.
     */
    public String getKey() {
        return key;
    }

    /**
     * Returns the secret.
     *
     * @return Secret.
     */
    public String getTenantDomain() {
        return tenantDomain;
    }

    /**
     * Sets the key.
     *
     * @param key Key.
     */
    public void setKey(String key) {
        this.key = key;
    }

    /**
     * Returns the secret.
     * @return Secret.
     */
    public String getSecret() {
        return secret;
    }

    /**
     * Sets the secret.
     *
     * @param secret Secret.
     */
    public void setSecret(String secret) {
        this.secret = secret;
    }

    /**
     * Returns the sender.
     *
     * @return Sender.
     */
    public String getSender() {
        return sender;
    }

    /**
     * Sets the sender.
     *
     * @param sender Sender.
     */
    public void setSender(String sender) {
        this.sender = sender;
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
     * Sets the content type.
     *
     * @param contentType Content type.
     */
    public void setContentType(String contentType) {
        this.contentType = contentType;
    }

    /**
     * Sets the tenant domain.
     *
     * @param tenantDomain Tenant domain.
     */
    public void setTenantDomain(String tenantDomain) {
        this.tenantDomain = tenantDomain;
    }
}
