/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com). All Rights Reserved.
 *
 * This software is the property of WSO2 LLC. and its suppliers, if any.
 * Dissemination of any information or reproduction of any material contained
 * herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
 * You may not alter or remove any copyright or other notice from copies of this content.
 *
 */

package org.wso2.carbon.identity.local.auth.smsotp.provider.impl;

import io.jsonwebtoken.lang.Assert;
import org.mockito.Mock;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.local.auth.smsotp.provider.model.SMSData;
import org.wso2.carbon.identity.notification.sender.tenant.config.dto.SMSSenderDTO;

import static org.testng.Assert.*;

public class TwilioProviderTest {

    private TwilioProvider twilioProvider;

    @Mock
    private SMSSenderDTO smsSenderDTO;

    @Mock
    private SMSData smsData;

    @BeforeTest
    public void createNewObject() {
        twilioProvider = new TwilioProvider();
    }

    @Test
    public void testGetName() {
        String name = twilioProvider.getName();
        Assert.notNull(name);
    }

    @Test(expectedExceptions = RuntimeException.class)
    public void testInitNotInit() {
        twilioProvider.send(smsData);
    }


    @Test
    public void testInitSuccess() {
        twilioProvider.init(smsSenderDTO, "carbon.super");
        twilioProvider.send(smsData);
    }

    @Test
    public void testSend() {
        twilioProvider.init(smsSenderDTO, "carbon.super");
        twilioProvider.send(smsData);
    }
}