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
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.local.auth.authenticator.exception.SMSOTPAuthenticatorServerException;

import static org.testng.Assert.*;

public class AuthenticatorUtilsTest {

    @Mock
    private AuthenticatedUser authenticatedUser;

    @Test
    public void testIsAccountLocked() throws AuthenticationFailedException {

        assertFalse(AuthenticatorUtils.isAccountLocked(authenticatedUser));
    }

    @Test
    public void testGetSmsAuthenticatorConfig() throws SMSOTPAuthenticatorServerException {

        AuthenticatorUtils.getSmsAuthenticatorConfig("test", "carbon.super");
    }

    @Test
    public void testGetSMSOTPLoginPageUrl() {
    }

    @Test
    public void testGetSMSOTPErrorPageUrl() {
    }

    @Test
    public void testHandleServerException() {
    }

    @Test
    public void testGetMultiOptionURIQueryParam() {
    }
}