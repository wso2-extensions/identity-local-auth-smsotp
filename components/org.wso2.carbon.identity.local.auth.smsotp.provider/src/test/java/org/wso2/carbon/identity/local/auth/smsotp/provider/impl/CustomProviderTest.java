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
import org.mockito.Mockito;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.local.auth.smsotp.provider.exception.PublisherException;
import org.wso2.carbon.identity.local.auth.smsotp.provider.model.SMSData;
import org.wso2.carbon.identity.notification.sender.tenant.config.dto.SMSSenderDTO;

import static org.mockito.Mockito.when;

public class CustomProviderTest {

    private CustomProvider customProvider;

    @Mock
    private SMSSenderDTO smsSenderDTO = Mockito.mock(SMSSenderDTO.class);

    @Mock
    private SMSData smsData = Mockito.mock(SMSData.class);

    @BeforeTest
    public void createNewObject() {
        customProvider = new CustomProvider();
    }

    @Test
    public void testGetName() {
        String name = customProvider.getName();
        Assert.notNull(name);
    }

    @Test(expectedExceptions = RuntimeException.class)
    public void testInitNotInit() {
        customProvider.send(smsData);
    }


    @Test(expectedExceptions = PublisherException.class)
    public void testInitSuccess() {

        when(smsSenderDTO.getProviderURL()).thenReturn("http://localhost:8080");
        when(smsSenderDTO.getKey()).thenReturn("key");
        when(smsSenderDTO.getSecret()).thenReturn("secret");
        when(smsSenderDTO.getSender()).thenReturn("sender");
        when(smsSenderDTO.getContentType()).thenReturn("contentType");

        customProvider.init(smsSenderDTO, "carbon.super");
        customProvider.send(smsData);
    }

    @Test
    public void testSend() {
        customProvider.init(smsSenderDTO, "carbon.super");
        when(smsSenderDTO.getProviderURL()).thenReturn("http://localhost:8080");
        when(smsSenderDTO.getKey()).thenReturn("key");
        when(smsSenderDTO.getSecret()).thenReturn("secret");
        when(smsSenderDTO.getSender()).thenReturn("sender");
        when(smsSenderDTO.getContentType()).thenReturn("contentType");
        customProvider.send(smsData);
    }
}