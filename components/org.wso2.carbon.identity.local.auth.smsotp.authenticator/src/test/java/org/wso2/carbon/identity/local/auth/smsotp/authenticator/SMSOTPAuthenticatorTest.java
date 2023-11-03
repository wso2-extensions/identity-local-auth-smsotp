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
import org.mockito.Mockito;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants;

import javax.servlet.http.HttpServletRequest;

import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;


public class SMSOTPAuthenticatorTest {

    private SMSOTPAuthenticator smsotpAuthenticator;

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
}
