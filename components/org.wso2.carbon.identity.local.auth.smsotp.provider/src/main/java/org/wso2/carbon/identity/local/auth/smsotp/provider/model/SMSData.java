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
 * This class represents the SMS data.
 *
 * @version 1.0.0
 * @since 1.0.0
 */
public class SMSData implements Serializable {

    private static final long serialVersionUID = 350777056982260622L;
    private String toNumber;
    private String fromNumber;
    private String smsBody;
    private SMSMetadata smsMetadata;

    /**
     * Returns the from number.
     * @return From number.
     */
    public String getFromNumber() {
        return fromNumber;
    }

    /**
     * Returns the SMS metadata {@link SMSMetadata}.
     * @return SMS metadata.
     */
    public SMSMetadata getSmsMetadata() {
        return smsMetadata;
    }

    /**
     * Sets the from number.
     * @param fromNumber From number.
     */
    public void setFromNumber(String fromNumber) {
        this.fromNumber = fromNumber;
    }

    /**
     * Sets the SMS metadata {@link SMSMetadata}.
     * @param smsMetadata SMS metadata.
     */
    public void setSmsMetadata(SMSMetadata smsMetadata) {
        this.smsMetadata = smsMetadata;
    }

    /**
     * Sets the to number.
     * @param toNumber To number.
     */
    public void setToNumber(String toNumber) {
        this.toNumber = toNumber;
    }

    /**
     * Returns the to number.
     * @return To number.
     */
    public String getToNumber() {
        return toNumber;
    }

    /**
     * Sets the SMS body.
     * @param smsBody SMS body.
     */
    public void setSMSBody(String smsBody) {
        this.smsBody = smsBody;
    }

    /**
     * Returns the SMS body.
     * @return SMS body.
     */
    public String getSMSBody() {
        return smsBody;
    }
}
