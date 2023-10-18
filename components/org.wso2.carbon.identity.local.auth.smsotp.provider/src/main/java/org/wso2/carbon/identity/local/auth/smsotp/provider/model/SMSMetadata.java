/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com). All Rights Reserved.
 *
 * This software is the property of WSO2 LLC. and its suppliers, if any.
 * Dissemination of any information or reproduction of any material contained
 * herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
 * You may not alter or remove any copyright or other notice from copies of this content.
 *
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
