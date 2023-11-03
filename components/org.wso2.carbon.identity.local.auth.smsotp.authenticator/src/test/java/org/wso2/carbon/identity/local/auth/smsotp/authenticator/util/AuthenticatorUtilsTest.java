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

package org.wso2.carbon.identity.local.auth.smsotp.authenticator.util;

import org.mockito.Mock;
import org.mockito.Mockito;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.local.auth.smsotp.authenticator.exception.SMSOTPAuthenticatorServerException;

import static org.testng.Assert.assertFalse;
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
