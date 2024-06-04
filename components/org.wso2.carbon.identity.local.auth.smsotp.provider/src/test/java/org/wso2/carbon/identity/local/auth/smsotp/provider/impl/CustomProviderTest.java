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

package org.wso2.carbon.identity.local.auth.smsotp.provider.impl;

import org.mockito.Mock;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.local.auth.smsotp.provider.constant.Constants;
import org.wso2.carbon.identity.local.auth.smsotp.provider.exception.ProviderException;
import org.wso2.carbon.identity.local.auth.smsotp.provider.exception.PublisherException;
import org.wso2.carbon.identity.local.auth.smsotp.provider.model.SMSData;
import org.wso2.carbon.identity.notification.sender.tenant.config.dto.SMSSenderDTO;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.when;

public class CustomProviderTest {

    private CustomProvider customProvider;
    private Map<String, String> propertiesMap = new HashMap<>();
    private static final String TO_NUMBER = "+1234567890";

    @Mock
    private SMSSenderDTO smsSenderDTO = Mockito.mock(SMSSenderDTO.class);

    @BeforeTest
    public void init() {
        propertiesMap.put(Constants.HTTP_HEADERS, "Authorization: Basic QUNiMziOTIyNT");
        propertiesMap.put(Constants.HTTP_BODY, "Body={{body}}&To={{mobile}}");
        propertiesMap.put(Constants.HTTP_METHOD, "POST");
    }

    @BeforeTest
    public void createNewObject() {
        customProvider = new CustomProvider();
    }

    @Test
    public void testGetName() {
        String name = customProvider.getName();
        Assert.assertNotNull(name);
    }

    @Test(expectedExceptions = ProviderException.class)
    public void testInitNotInit() throws ProviderException {

        SMSData smsData = new SMSData();
        smsData.setToNumber(TO_NUMBER);

        customProvider.send(smsData, smsSenderDTO, "carbon.super");
    }

    @Test
    public void testNullTelephoneNumberTest() {

        SMSData smsData = new SMSData();
        try {
            customProvider.send(smsData, smsSenderDTO, "carbon.super");
        } catch (ProviderException e) {
            Assert.assertEquals(e.getMessage(), "To number is null or blank. Cannot send SMS");
        }
    }

    @Test
    public void testNullTemplateTest() {

        SMSData smsData = new SMSData();
        smsData.setToNumber(TO_NUMBER);
        try {
            customProvider.send(smsData, smsSenderDTO, "carbon.super");
        } catch (ProviderException e) {
            Assert.assertEquals(e.getMessage(), "Template is null or blank. Cannot send SMS");
        }
    }

    @Test(expectedExceptions = {PublisherException.class, ProviderException.class})
    public void testInitSuccess() throws ProviderException {

        when(smsSenderDTO.getProviderURL()).thenReturn("https://localhost:8888");
        when(smsSenderDTO.getKey()).thenReturn("key");
        when(smsSenderDTO.getSecret()).thenReturn("secret");
        when(smsSenderDTO.getSender()).thenReturn("sender");
        when(smsSenderDTO.getContentType()).thenReturn("contentType");

        SMSData smsData = new SMSData();
        smsData.setToNumber(TO_NUMBER);

        customProvider.send(smsData, smsSenderDTO, "carbon.super");
    }

    @Test
    public void testSend() {

        when(smsSenderDTO.getProviderURL()).thenReturn("https://localhost:8888");
        when(smsSenderDTO.getKey()).thenReturn("key");
        when(smsSenderDTO.getSecret()).thenReturn("secret");
        when(smsSenderDTO.getSender()).thenReturn("sender");
        when(smsSenderDTO.getContentType()).thenReturn("contentType");
        when(smsSenderDTO.getProperties()).thenReturn(propertiesMap);

        SMSData smsData = new SMSData();
        smsData.setToNumber(TO_NUMBER);

        try {
            customProvider.send(smsData, smsSenderDTO, "carbon.super");
        } catch (ProviderException e) {
            Assert.assertEquals(e.getMessage(), "Error occurred while publishing the SMS data to the custom provider");
        }
    }

    @Test
    public void resolveFormTemplateTest()
            throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {

        CustomProvider customProvider = new CustomProvider();
        Method method = CustomProvider.class.getDeclaredMethod(
                "resolveTemplate", String.class, String.class, String.class, String.class);
        method.setAccessible(true);

        String template = (String) method.invoke(customProvider,
                Constants.APPLICATION_FORM,
                "Body={{body}}&To={{mobile}}", TO_NUMBER, "Verification Code: 769317");
        Assert.assertEquals(template, "Body=Verification+Code%3A+769317&To=%2B1234567890");
    }

    @Test
    public void  resolveJsonTemplateTest()
            throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {

        CustomProvider customProvider = new CustomProvider();
        Method method = CustomProvider.class.getDeclaredMethod(
                "resolveTemplate", String.class, String.class, String.class, String.class);
        method.setAccessible(true);

        String template = (String) method.invoke(customProvider,
                Constants.APPLICATION_JSON,
                "{\"content\": {{body}},\"to\": {{mobile}}}", TO_NUMBER, "Verification Code: 769317");
        Assert.assertEquals(template, "{\"content\": \"Verification Code: 769317\",\"to\": \"+1234567890\"}");
    }
}
