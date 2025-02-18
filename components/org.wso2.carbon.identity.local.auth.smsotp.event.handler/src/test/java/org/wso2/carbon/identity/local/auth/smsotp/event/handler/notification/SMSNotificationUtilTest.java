/*
 * Copyright (c) 2024, WSO2 LLC. (https://www.wso2.com).
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

package org.wso2.carbon.identity.local.auth.smsotp.event.handler.notification;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.auth.otp.core.model.OTP;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.local.auth.smsotp.event.handler.notification.internal.SMSNotificationHandlerDataHolder;
import org.wso2.carbon.identity.local.auth.smsotp.event.handler.notification.internal.SMSNotificationUtil;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.user.api.Tenant;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link SMSNotificationUtil}.
 */
public class SMSNotificationUtilTest {

    @Mock
    private RealmService mockedRealmService;

    @Mock
    private TenantManager mockedTenantManager;

    @Mock
    private OrganizationManager mockedOrganizationManager;

    private MockedStatic<IdentityTenantUtil> mockedStaticIdentityTenantUtil;

    private static final String SUPER_TENANT_DOMAIN = "carbon.super";
    private static final String TEST_TENANT_DOMAIN = "test.tenant";
    private static final String TEST_ORG_NAME = "testOrg";
    private static final String TEST_ORG_UUID = "12312434";

    @BeforeClass
    public void beforeTest() {

        mockIdentityTenantUtil();
    }

    @BeforeTest
    public void setUp() {

        MockitoAnnotations.openMocks(this);
        SMSNotificationHandlerDataHolder
                .getInstance()
                .setRealmService(mockedRealmService);
        SMSNotificationHandlerDataHolder
                .getInstance()
                .setOrganizationManager(mockedOrganizationManager);
    }

    @AfterClass
    public void tearDown() {

        mockedStaticIdentityTenantUtil.close();
    }

    @DataProvider(name = "otpDataProvider")
    public Object[][] otpDataProvider() {

        return new Object[][] {
                {
                    new HashMap<String, Object>() {
                        {
                            put(SMSNotificationConstants.OTP_TOKEN_PROPERTY_NAME, new OTP("123456", 300000, 300000));
                        }
                    }, new HashMap<String, String>(), "123456", "5"
                },
                {
                    new HashMap<String, String>() {
                        {
                            put(SMSNotificationConstants.OTP_TOKEN_STRING_PROPERTY_NAME, "123456");
                        }
                    }, new HashMap<String, String>(), "123456", null
                }
        };
    }

    @DataProvider(name = "placeholderDataProvider")
    public Object[][] placeholderDataProvider() {

        String testSMSTemplate =
                "Your confirmation code is {{confirmation-code}}. It will expire in {{otp-expiry-time}} minutes.";
        return new Object[][] {
                { testSMSTemplate, new HashMap<>(), testSMSTemplate },
                { testSMSTemplate, new HashMap<String, String>() {
                        {
                            put(SMSNotificationConstants.PLACE_HOLDER_CONFIRMATION_CODE, "123456");
                            put(SMSNotificationConstants.PLACE_HOLDER_OTP_EXPIRY_TIME, "5");
                        }
                    }, "Your confirmation code is 123456. It will expire in 5 minutes."
                }
        };
    }

    @DataProvider(name = "filterPlaceholderDataProvider")
    public Object[][] filterPlaceholderDataProvider() {

        return new Object[][] {
                { new HashMap<>(), new HashMap<>() },
                {
                    new HashMap<String, String>() {
                        {
                            put(SMSNotificationConstants.PLACE_HOLDER_TENANT_DOMAIN, "tenant");
                            put(SMSNotificationConstants.PLACE_HOLDER_USER_NAME, "user");
                            put(SMSNotificationConstants.PLACE_HOLDER_USER_STORE_DOMAIN, "userstore");
                            put(SMSNotificationConstants.PLACEHOLDER_ORGANIZATION_NAME, "org");
                            put(SMSNotificationConstants.PLACE_HOLDER_APPLICATION_NAME, "app");
                            put(SMSNotificationConstants.PLACE_HOLDER_CONFIRMATION_CODE, "1234");
                            put(SMSNotificationConstants.PLACE_HOLDER_OTP_EXPIRY_TIME, "300000");
                            put("InvalidPlaceHolderName1", "value1");
                            put("InvalidPlaceHolderName2", "value2");
                        }
                    },
                    new HashMap<String, String>() {
                        {
                            put(SMSNotificationConstants.PLACE_HOLDER_TENANT_DOMAIN, "tenant");
                            put(SMSNotificationConstants.PLACE_HOLDER_USER_NAME, "user");
                            put(SMSNotificationConstants.PLACE_HOLDER_USER_STORE_DOMAIN, "userstore");
                            put(SMSNotificationConstants.PLACEHOLDER_ORGANIZATION_NAME, "org");
                            put(SMSNotificationConstants.PLACE_HOLDER_APPLICATION_NAME, "app");
                            put(SMSNotificationConstants.PLACE_HOLDER_CONFIRMATION_CODE, "1234");
                            put(SMSNotificationConstants.PLACE_HOLDER_OTP_EXPIRY_TIME, "300000");
                        }
                    }
                }
        };
    }

    @DataProvider(name = "organizationNameDataProvider")
    public Object[][] organizationNameDataProvider() {

        Tenant testTenant1 = new Tenant();
        Tenant testTenant2 = new Tenant();
        testTenant2.setAssociatedOrganizationUUID(TEST_ORG_UUID);
        return new Object[][] {
                { SUPER_TENANT_DOMAIN, SUPER_TENANT_DOMAIN, null },
                { TEST_TENANT_DOMAIN, TEST_TENANT_DOMAIN, null },
                { TEST_TENANT_DOMAIN, TEST_TENANT_DOMAIN, testTenant1 },
                { TEST_TENANT_DOMAIN, TEST_ORG_NAME, testTenant2 }
        };
    }

    @Test(dataProvider = "placeholderDataProvider")
    public void testReplacePlaceholders(String template, Map<String, String> notificationData, String expectedSMSBody) {

        String smsBody = SMSNotificationUtil.replacePlaceholders(template, notificationData);
        Assert.assertEquals(smsBody, expectedSMSBody);
    }

    @Test(dataProvider = "otpDataProvider")
    public void testResolveOTPValuesWithOTPObject(Map<String, Object> dataMap, Map<String, String> notificationData,
                                                  String confirmationCode, String expiryTime) {

        SMSNotificationUtil.resolveOTPValues(dataMap, notificationData);
        Assert.assertEquals(
                notificationData.get(SMSNotificationConstants.PLACE_HOLDER_CONFIRMATION_CODE), confirmationCode);
        Assert.assertEquals(notificationData.get(SMSNotificationConstants.PLACE_HOLDER_OTP_EXPIRY_TIME), expiryTime);
    }

    @Test(dataProvider = "filterPlaceholderDataProvider")
    public void testFilterPlaceHolderData(Map<String, String> notificationDataInput,
                                          Map<String, String> expectedOutput) {

        Map<String, String> filteredData = SMSNotificationUtil.filterPlaceHolderData(notificationDataInput);
        Assert.assertEquals(filteredData, expectedOutput);
    }

    @Test(dataProvider = "organizationNameDataProvider")
    public void  testResolveHumanReadableOrganizationName(String tenant, String expectedOrgName, Tenant testTenant)
            throws IdentityEventException, UserStoreException, OrganizationManagementException {

        when(mockedRealmService.getTenantManager()).thenReturn(mockedTenantManager);
        when(mockedTenantManager.getTenant(anyInt())).thenReturn(testTenant);
        when(mockedOrganizationManager.getOrganizationNameById(TEST_ORG_UUID)).thenReturn(TEST_ORG_NAME);
        String orgName = SMSNotificationUtil.resolveHumanReadableOrganizationName(tenant);
        Assert.assertEquals(orgName, expectedOrgName);
    }

    private void mockIdentityTenantUtil() {

        mockedStaticIdentityTenantUtil = mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(SUPER_TENANT_DOMAIN)).thenReturn(1);
        when(IdentityTenantUtil.getTenantId(TEST_TENANT_DOMAIN)).thenReturn(2);
    }
}
