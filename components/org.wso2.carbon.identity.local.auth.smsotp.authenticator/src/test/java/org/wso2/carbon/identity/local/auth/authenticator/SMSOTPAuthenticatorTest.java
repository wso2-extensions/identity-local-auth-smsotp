/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com). All Rights Reserved.
 *
 * This software is the property of WSO2 LLC. and its suppliers, if any.
 * Dissemination of any information or reproduction of any material contained
 * herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
 * You may not alter or remove any copyright or other notice from copies of this content.
 *
 */

package org.wso2.carbon.identity.local.auth.authenticator;

import org.mockito.Mock;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.local.auth.authenticator.constant.SMSOTPConstants;

import javax.servlet.http.HttpServletRequest;

import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

public class SMSOTPAuthenticatorTest {

    private SMSOTPAuthenticator smsotpAuthenticator;

    @Mock
    private HttpServletRequest httpServletRequest;

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

    @Test
    public void testGetOTPLength() throws AuthenticationFailedException {

        assertEquals(smsotpAuthenticator.getOTPLength("carbon.super"), 6);
    }

    @Test
    public void testHandleOtpVerificationFail() {
    }

    @Test
    public void testProcessAuthenticationResponse() {
    }

    @Test
    public void testResetOtpFailedAttempts() {
    }

    @Test
    public void testResolveScenario() {
    }

    @Test
    public void testRetryAuthenticationEnabled() {
    }

    @Test
    public void testTriggerEvent() {
    }

    @Test
    public void testGetAuthenticatorErrorPrefix() {
    }

    @Test
    public void testGetErrorPageURL() {
    }

    @Test
    public void testGetMaskedUserClaimValue() {
    }

    @Test
    public void testGetOTPLoginPageURL() {
    }

    @Test
    public void testPublishPostOTPGeneratedEvent() {
    }

    @Test
    public void testPublishPostOTPValidatedEvent() {
    }

    @Test
    public void testSendOtp() {
    }

    @Test
    public void testGetMaximumResendAttempts() {
    }
}