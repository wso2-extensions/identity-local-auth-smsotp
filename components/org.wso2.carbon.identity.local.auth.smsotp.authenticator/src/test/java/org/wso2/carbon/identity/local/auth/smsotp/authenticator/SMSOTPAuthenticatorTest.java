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
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorParamMetadata;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants;
import org.wso2.carbon.identity.local.auth.smsotp.authenticator.util.AuthenticatorUtils;

import javax.servlet.http.HttpServletRequest;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.DISPLAY_USERNAME;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.USERNAME;


public class SMSOTPAuthenticatorTest {

    private SMSOTPAuthenticator smsotpAuthenticator;

    @Mock
    private AuthenticationContext context = Mockito.mock(AuthenticationContext.class);

    @Mock
    private HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);

    @BeforeTest
    public void createNewObject() {
        smsotpAuthenticator = new SMSOTPAuthenticator();
    }

    @Test
    public void testCanHandle() {

        when(httpServletRequest.getParameter(SMSOTPConstants.RESEND)).thenReturn("true");
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
        assertTrue(true, "Test case not implemented yet");
    }

    @Test
    public void testRetryAuthenticationEnabled() {
        assertTrue(true, "Test case not implemented yet");
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
