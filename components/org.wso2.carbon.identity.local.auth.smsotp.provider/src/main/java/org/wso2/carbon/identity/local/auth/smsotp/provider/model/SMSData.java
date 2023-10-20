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
