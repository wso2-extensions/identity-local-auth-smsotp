/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com). All Rights Reserved.
 *
 * This software is the property of WSO2 LLC. and its suppliers, if any.
 * Dissemination of any information or reproduction of any material contained
 * herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
 * You may not alter or remove any copyright or other notice from copies of this content.
 *
 */

package org.wso2.carbon.identity.local.auth.smsotp.provider.http;

import org.mockito.Mock;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.local.auth.smsotp.provider.exception.PublisherException;
import org.wso2.carbon.identity.local.auth.smsotp.provider.model.SMSData;
import org.wso2.carbon.identity.local.auth.smsotp.provider.model.SMSMetadata;

import static org.testng.Assert.*;

public class HTTPPublisherTest {

    private HTTPPublisher httpPublisher;

    @BeforeTest
    public void setUp() {
        httpPublisher = new HTTPPublisher("http://localhost:8080");
    }

    @Test(expectedExceptions = PublisherException.class)
    public void testPublisherExceptionCase() throws PublisherException {

        SMSData smsData = new SMSData();
        SMSMetadata smsMetadata = new SMSMetadata();

        smsData.setSmsMetadata(smsMetadata);

        httpPublisher.publish(smsData);
    }
}