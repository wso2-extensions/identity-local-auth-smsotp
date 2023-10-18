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

public class VonageProviderTest {

    private VonageProvider vonageProvider;

    @Mock
    private SMSSenderDTO smsSenderDTO;

    @Mock
    private SMSData smsData;

    @BeforeTest
    public void createNewObject() {
        vonageProvider = new VonageProvider();
    }

    @Test
    public void testGetName() {
        String name = vonageProvider.getName();
        Assert.notNull(name);
    }

    @Test(expectedExceptions = RuntimeException.class)
    public void testInitNotInit() {
       vonageProvider.send(smsData);
    }


    @Test
    public void testInitSuccess() {
        vonageProvider.init(smsSenderDTO, "carbon.super");
        vonageProvider.send(smsData);
    }

    @Test
    public void testSend() {
        vonageProvider.init(smsSenderDTO, "carbon.super");
        vonageProvider.send(smsData);
    }
}