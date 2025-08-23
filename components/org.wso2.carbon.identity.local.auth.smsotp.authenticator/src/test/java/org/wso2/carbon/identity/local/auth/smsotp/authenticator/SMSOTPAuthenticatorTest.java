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

package org.wso2.carbon.identity.local.auth.smsotp.authenticator;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorMessage;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorParamMetadata;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants;
import org.wso2.carbon.identity.local.auth.smsotp.authenticator.internal.AuthenticatorDataHolder;
import org.wso2.carbon.identity.local.auth.smsotp.authenticator.util.AuthenticatorUtils;

import javax.servlet.http.HttpServletRequest;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator.ENABLE_RETRY_FROM_AUTHENTICATOR;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.CODE;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.DISPLAY_USERNAME;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.RESEND;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.SMS_OTP_AUTHENTICATOR_NAME;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.USERNAME;


public class SMSOTPAuthenticatorTest {

    private SMSOTPAuthenticator smsotpAuthenticator;

    @Mock
    private AuthenticationContext context = mock(AuthenticationContext.class);

    private MockedStatic<AuthenticatorDataHolder> authenticatorDataHolder;

    @Mock
    private HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);

    @BeforeTest
    public void createNewObject() {
        smsotpAuthenticator = new SMSOTPAuthenticator();
    }

    @Test
    public void testCanHandle() {

        when(httpServletRequest.getParameter(RESEND)).thenReturn("true");
        assertTrue(smsotpAuthenticator.canHandle(httpServletRequest));
    }

    @Test
    public void testGetContextIdentifier() {

        when(httpServletRequest.getRequestedSessionId()).thenReturn("true");
        assertNotNull(smsotpAuthenticator.getContextIdentifier(httpServletRequest));
    }

    @Test
    public void testGetFriendlyName() {

        assertNotNull(smsotpAuthenticator.getFriendlyName());
    }

    @Test
    public void testGetName() {

        assertNotNull(smsotpAuthenticator.getName());
    }

    @Test(expectedExceptions = RuntimeException.class)
    public void testGetOTPLength() throws AuthenticationFailedException {

        assertEquals(smsotpAuthenticator.getOTPLength("carbon.super"), 6);
    }

    @Test
    public void testHandleOtpVerificationFail() {
        assertTrue(true, "Test case not implemented yet");
    }

    @Test
    public void testProcessAuthenticationResponse() {
        assertTrue(true, "Test case not implemented yet");
    }

    @Test
    public void testResetOtpFailedAttempts() {
        assertTrue(true, "Test case not implemented yet");
    }

    @Test
    public void testResolveScenario() {

        SMSOTPAuthenticator smsotpAuthenticator = new SMSOTPAuthenticator();
        AuthenticationContext context = mock(AuthenticationContext.class);
        HttpServletRequest request = mock(HttpServletRequest.class);

        // Test case 1: Logout request
        when(context.isLogoutRequest()).thenReturn(true);
        assertEquals(smsotpAuthenticator.resolveScenario(request, context),
                AuthenticatorConstants.AuthenticationScenarios.LOGOUT);

        // Test case 2: Initial OTP scenario
        when(context.isLogoutRequest()).thenReturn(false);
        when(context.isRetrying()).thenReturn(false);
        when(request.getParameter(CODE)).thenReturn(null);
        when(request.getParameter(RESEND)).thenReturn(String.valueOf(false));
        assertEquals(smsotpAuthenticator.resolveScenario(request, context),
                AuthenticatorConstants.AuthenticationScenarios.INITIAL_OTP);

        when(context.getCurrentAuthenticator()).thenReturn(SMS_OTP_AUTHENTICATOR_NAME);

        // Test case 3: Resend OTP scenario
        when(context.isRetrying()).thenReturn(true);
        when(request.getParameter(RESEND)).thenReturn(String.valueOf(true));
        assertEquals(smsotpAuthenticator.resolveScenario(request, context),
                AuthenticatorConstants.AuthenticationScenarios.RESEND_OTP);

        // Test case 4: Submit OTP scenario
        when(request.getParameter(RESEND)).thenReturn(String.valueOf(false));
        assertEquals(smsotpAuthenticator.resolveScenario(request, context),
                AuthenticatorConstants.AuthenticationScenarios.SUBMIT_OTP);

        // Test case 5: Submit OTP scenario with OTP code
        when(request.getParameter(CODE)).thenReturn("123456");
        when(context.getCurrentAuthenticator()).thenReturn("dummyAuthenticator");
        assertEquals(smsotpAuthenticator.resolveScenario(request, context),
                AuthenticatorConstants.AuthenticationScenarios.INITIAL_OTP);
    }

    @DataProvider
    public Object[][] retryAuthenticationData() {

        return new Object[][]{
                {Boolean.TRUE, true},
                {Boolean.FALSE, false},
                {null, true}    // Empty config map -> method returns true by default.
        };
    }

    @Test(dataProvider = "retryAuthenticationData")
    public void testRetryAuthenticationEnabled(Boolean isRetryEnabled, boolean expected) {

        AuthenticatorConfig authenticatorConfig = mock(AuthenticatorConfig.class);
        Map<String, String> params = new HashMap<>();
        if (isRetryEnabled != null) {
            params.put(ENABLE_RETRY_FROM_AUTHENTICATOR, isRetryEnabled.toString());
        }
        when(authenticatorConfig.getParameterMap()).thenReturn(params);

        FileBasedConfigurationBuilder fileBasedConfigurationBuilder = mock(FileBasedConfigurationBuilder.class);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);

        SMSOTPAuthenticator smsotpAuthenticator = new SMSOTPAuthenticator();

        try (MockedStatic<FileBasedConfigurationBuilder> mocked =
                     mockStatic(FileBasedConfigurationBuilder.class)) {

            mocked.when(FileBasedConfigurationBuilder::getInstance)
                    .thenReturn(fileBasedConfigurationBuilder);

            boolean actual = smsotpAuthenticator.retryAuthenticationEnabled();
            Assert.assertEquals(actual, expected,
                    "The retry authentication enabled value should match the expected value: " + expected);
        }
    }

    @Test
    public void testTriggerEvent() {
        assertTrue(true, "Test case not implemented yet");
    }

    @Test
    public void testGetAuthenticatorErrorPrefix() {
        assertTrue(true, "Test case not implemented yet");
    }

    @Test
    public void testGetErrorPageURL() {
        assertTrue(true, "Test case not implemented yet");
    }

    @Test
    public void testGetMaskedUserClaimValue() {
        assertTrue(true, "Test case not implemented yet");
    }

    @Test
    public void testGetOTPLoginPageURL() {
        assertTrue(true, "Test case not implemented yet");
    }

    @Test
    public void testPublishPostOTPGeneratedEvent() {
        assertTrue(true, "Test case not implemented yet");
    }

    @Test
    public void testPublishPostOTPValidatedEvent() {
        assertTrue(true, "Test case not implemented yet");
    }

    @Test(expectedExceptions = RuntimeException.class)
    public void testPublishPostOTPGeneratedEventException()
            throws AuthenticationFailedException,
            IdentityApplicationManagementException, ConfigurationManagementException {

        // Prepare mock data
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserId("testUserId");
        authenticatedUser.setUserStoreDomain("PRIMARY");
        authenticatedUser.setTenantDomain("carbon.super");

        // Mock context behavior
        when(context.getCallerSessionKey()).thenReturn("testSessionKey");
        when(context.getServiceProviderName()).thenReturn("testServiceProvider");
        when(context.getTenantDomain()).thenReturn("carbon.super");
        when(httpServletRequest.getParameter(RESEND)).thenReturn("false");

        // Mock IdentityTenantUtil static method
        try (MockedStatic<IdentityTenantUtil> identityTenantUtilMockedStatic = mockStatic(IdentityTenantUtil.class)) {
            identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);

            // Mock AuthenticatorDataHolder static method
            try (MockedStatic<AuthenticatorDataHolder> authenticatorDataHolderMockedStatic = mockStatic(AuthenticatorDataHolder.class)) {
                ApplicationManagementService applicationManagementService = mock(ApplicationManagementService.class);
                authenticatorDataHolderMockedStatic.when(AuthenticatorDataHolder::getApplicationManagementService).thenReturn(applicationManagementService);

                // Mock service provider
                ServiceProvider serviceProvider = new ServiceProvider();
                serviceProvider.setApplicationResourceId("testAppId");
                when(applicationManagementService.getServiceProvider("testServiceProvider", "carbon.super")).thenReturn(serviceProvider);

                // Mock ConfigurationManager
                ConfigurationManager configurationManager = mock(ConfigurationManager.class);
                authenticatorDataHolderMockedStatic.when(AuthenticatorDataHolder::getConfigurationManager).thenReturn(configurationManager);
                when(configurationManager.getResource(SMSOTPConstants.PUBLISHER, SMSOTPConstants.SMS_PROVIDER)).thenReturn(mock(Resource.class));

                // Execute the method under test
                smsotpAuthenticator.publishPostOTPGeneratedEvent(null, authenticatedUser, httpServletRequest, context);
            }
        }
    }

    @Test
    public void testSendOtp() {
        assertTrue(true, "Test case not implemented yet");
    }

    @Test
    public void testGetMaximumResendAttempts() {
        assertTrue(true, "Test case not implemented yet");
    }

    @Test
    public void testIsAPIBasedAuthenticationSupported() {

        boolean isAPIBasedAuthenticationSupported = smsotpAuthenticator.isAPIBasedAuthenticationSupported();
        Assert.assertTrue(isAPIBasedAuthenticationSupported);
    }

    @Test
    public void testGetAuthInitiationData() throws AuthenticationFailedException {

        Optional<AuthenticatorData> authenticatorData = smsotpAuthenticator.getAuthInitiationData(context);
        Assert.assertTrue(authenticatorData.isPresent());
        AuthenticatorData authenticatorDataObj = authenticatorData.get();

        List<AuthenticatorParamMetadata> authenticatorParamMetadataList = new ArrayList<>();
        AuthenticatorParamMetadata usernameMetadata = new AuthenticatorParamMetadata(
                USERNAME, DISPLAY_USERNAME, FrameworkConstants.AuthenticatorParamType.STRING,
                0, Boolean.FALSE, SMSOTPConstants.USERNAME_PARAM_KEY);
        authenticatorParamMetadataList.add(usernameMetadata);

        Assert.assertEquals(authenticatorDataObj.getName(), SMSOTPConstants.SMS_OTP_AUTHENTICATOR_NAME,
                "Authenticator name should match.");
        Assert.assertEquals(authenticatorDataObj.getDisplayName(), SMSOTPConstants.SMS_OTP_AUTHENTICATOR_FRIENDLY_NAME,
                "Authenticator display name should match.");
        Assert.assertEquals(authenticatorDataObj.getAuthParams().size(), authenticatorParamMetadataList.size(),
                "Size of lists should be equal.");
        Assert.assertEquals(authenticatorDataObj.getPromptType(),
                FrameworkConstants.AuthenticatorPromptType.USER_PROMPT);
        Assert.assertEquals(authenticatorDataObj.getRequiredParams().size(),
                1);
        for (int i = 0; i < authenticatorParamMetadataList.size(); i++) {
            AuthenticatorParamMetadata expectedParam = authenticatorParamMetadataList.get(i);
            AuthenticatorParamMetadata actualParam = authenticatorDataObj.getAuthParams().get(i);

            Assert.assertEquals(actualParam.getName(), expectedParam.getName(), "Parameter name should match.");
            Assert.assertEquals(actualParam.getType(), expectedParam.getType(), "Parameter type should match.");
            Assert.assertEquals(actualParam.getParamOrder(), expectedParam.getParamOrder(),
                    "Parameter order should match.");
            Assert.assertEquals(actualParam.isConfidential(), expectedParam.isConfidential(),
                    "Parameter mandatory status should match.");
        }
    }

    /**
     * Data provider for testSetMaskedMobileNumberMessage method in SMSOTPAuthenticator.
     * @return Object[][] containing current step and masked mobile configuration.
     */
    @DataProvider(name = "getCurrentStepAndMaskedMobile")
    public Object[][] getCurrentStepAndMaskedMobile() {
        return new Object[][]{
                {1, "true"},
                {2, "false"},
                {3, "true"},
                {3, null}
        };
    }

    /**
     * Test for setMaskedMobileNumberMessage method in SMSOTPAuthenticator.
     * This test checks if the masked mobile number message is set correctly in the AuthenticatorData object.
     */
    @Test   (dataProvider = "getCurrentStepAndMaskedMobile")
    public void testSetMaskedMobileNumberMessage(int currentStep, String sendMaskedMobileInAppNativeMFA) {

        //Arrange
        String maskedMobileNumber = "XXXXXX1234"; // Masked mobile number
        String message = "The code is successfully sent to the mobile number: " + maskedMobileNumber;
        Map<String, String> messageContext = new HashMap<>();
        AuthenticatorMessage authenticatorMessage = new AuthenticatorMessage(FrameworkConstants.
                AuthenticatorMessageType.INFO, "SMSOTPSent", message, messageContext);
        messageContext.put("maskedMobileNumber", maskedMobileNumber);
        context.setProperty("authenticatorMessage", authenticatorMessage);
        when(context.getProperty("authenticatorMessage")).thenReturn(authenticatorMessage);

        AuthenticatorConfig authenticatorConfig = mock(AuthenticatorConfig.class);
        Map<String, String> params = new HashMap<>();
        params.put(SMSOTPConstants.SEND_MASKED_MOBILE_IN_APPNATIVE_MFA, sendMaskedMobileInAppNativeMFA);
        when(authenticatorConfig.getParameterMap()).thenReturn(params);

        FileBasedConfigurationBuilder fileBasedConfigurationBuilder = mock(FileBasedConfigurationBuilder.class);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString()))
                .thenReturn(authenticatorConfig);

        try (MockedStatic<FileBasedConfigurationBuilder> mocked = mockStatic(FileBasedConfigurationBuilder.class)) {

            mocked.when(FileBasedConfigurationBuilder::getInstance).thenReturn(fileBasedConfigurationBuilder);

            SMSOTPAuthenticator smsotpAuthenticator = new SMSOTPAuthenticator();
            when(context.getCurrentStep()).thenReturn(currentStep);

            Optional<AuthenticatorData> authenticatorData = smsotpAuthenticator.getAuthInitiationData(context);
            AuthenticatorMessage authMsg = authenticatorData.map(data -> data.getMessage()).orElse(null);

            if (currentStep != 1) {
                // If the current step is not 1, we should set the masked mobile number message only if the
                // configuration is enabled.
                if (Boolean.parseBoolean(sendMaskedMobileInAppNativeMFA)) {
                    assertNotNull(authMsg);
                    assertEquals(authMsg.getMessage(), authenticatorMessage.getMessage(),
                            "The AuthenticatorMessage should match the expected message.");
                } else {
                    // If the configuration is disabled, the authenticatorData should not contain the masked mobile
                    // number message.
                    assertNull(authMsg,
                            "AuthenticatorMessage should be null when the configuration is disabled.");
                }
            } else {
                // Masked mobile is not returned for passwordless authentication
                assertNull(authMsg,
                        "AuthenticatorMessage should be null for passwordless authentication.");
            }
        }
    }

    @DataProvider
    public static Object[][] validateTestUseOnlyNumbersInOTP() {
        return new Object[][] {
                {"carbon.super", "true"},
                {"carbon.super", "false"},
        };
    }

    @Test(dataProvider = "validateTestUseOnlyNumbersInOTP")
    public void testUseOnlyNumbersInOTP(String tenantDomain, String useNumericChars) {
        try (MockedStatic<AuthenticatorUtils> mockedStatic = Mockito.mockStatic(AuthenticatorUtils.class)) {
            mockedStatic.when(() -> AuthenticatorUtils.getSmsAuthenticatorConfig(
                            SMSOTPConstants.ConnectorConfig.SMS_OTP_USE_NUMERIC_CHARS, tenantDomain))
                    .thenReturn(useNumericChars);

            boolean useOnlyNumbersInOTP = smsotpAuthenticator.useOnlyNumericChars(tenantDomain);
            assertEquals(useOnlyNumbersInOTP, Boolean.parseBoolean(useNumericChars));
        } catch (Exception e) {
            throw new RuntimeException(e);

        }
    }
}
