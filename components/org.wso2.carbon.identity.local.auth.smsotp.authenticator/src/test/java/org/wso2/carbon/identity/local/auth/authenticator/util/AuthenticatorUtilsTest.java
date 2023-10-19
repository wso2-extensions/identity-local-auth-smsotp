/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com). All Rights Reserved.
 *
 * This software is the property of WSO2 LLC. and its suppliers, if any.
 * Dissemination of any information or reproduction of any material contained
 * herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
 * You may not alter or remove any copyright or other notice from copies of this content.
 *
 */

package org.wso2.carbon.identity.local.auth.authenticator.util;

import org.mockito.Mock;
import org.mockito.Mockito;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.local.auth.authenticator.exception.SMSOTPAuthenticatorServerException;

import static junit.framework.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class AuthenticatorUtilsTest {

    @Mock
    private AuthenticatedUser authenticatedUser = Mockito.mock(AuthenticatedUser.class);

    @Test(expectedExceptions = RuntimeException.class)
    public void testIsAccountLocked() throws AuthenticationFailedException {

        assertFalse(AuthenticatorUtils.isAccountLocked(authenticatedUser));
    }

    @Test(expectedExceptions = RuntimeException.class)
    public void testGetSmsAuthenticatorConfig() throws SMSOTPAuthenticatorServerException {

        AuthenticatorUtils.getSmsAuthenticatorConfig("test", "carbon.super");
    }

    @Test
    public void testGetSMSOTPLoginPageUrl() {
        assertTrue(true, "Test case not implemented yet");
    }

    @Test
    public void testGetSMSOTPErrorPageUrl() {
        assertTrue(true, "Test case not implemented yet");
    }

    @Test
    public void testHandleServerException() {
        assertTrue(true, "Test case not implemented yet");
    }

    @Test
    public void testGetMultiOptionURIQueryParam() {
        assertTrue(true, "Test case not implemented yet");
    }
}