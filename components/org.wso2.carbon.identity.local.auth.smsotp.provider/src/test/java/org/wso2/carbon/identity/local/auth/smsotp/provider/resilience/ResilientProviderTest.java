/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
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

package org.wso2.carbon.identity.local.auth.smsotp.provider.resilience;

import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.circuitbreaker.PerTenantCircuitBreakerManager;
import org.wso2.carbon.identity.core.circuitbreaker.Policy;
import org.wso2.carbon.identity.local.auth.smsotp.provider.Provider;
import org.wso2.carbon.identity.local.auth.smsotp.provider.exception.NonBlockingProviderException;
import org.wso2.carbon.identity.local.auth.smsotp.provider.exception.ProviderException;
import org.wso2.carbon.identity.local.auth.smsotp.provider.model.SMSData;
import org.wso2.carbon.identity.notification.sender.tenant.config.dto.SMSSenderDTO;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Unit tests for {@link ResilientProvider}.
 */
public class ResilientProviderTest {

    @Test
    public void testFailFastWhenCircuitOpen() throws Exception {

        Policy policy = Policy.builder()
                .setEnabled(true)
                .setWindowSize(2)
                .setMinCallsToEvaluate(2)
                .setFailureRateThreshold(0.50D)
                .setOpenDurationMs(60000L)
                .build();
        PerTenantCircuitBreakerManager manager = new PerTenantCircuitBreakerManager(policy);
        AlwaysFailProvider delegate = new AlwaysFailProvider();
        ResilientProvider provider = new ResilientProvider(delegate, manager);

        assertProviderException(provider, "tenant-one");
        assertProviderException(provider, "tenant-one");

        provider.send(baseSmsData(), baseSenderDto(), "tenant-one");
        Assert.assertEquals(delegate.getInvocationCount(), 2);
    }

    @Test
    public void testSoftFailuresOpenCircuitWithoutThrowingEachCall() throws Exception {

        Policy policy = Policy.builder()
                .setEnabled(true)
                .setWindowSize(2)
                .setMinCallsToEvaluate(2)
                .setFailureRateThreshold(0.50D)
                .setOpenDurationMs(60000L)
                .build();
        PerTenantCircuitBreakerManager manager = new PerTenantCircuitBreakerManager(policy);
        SoftFailProvider delegate = new SoftFailProvider();
        ResilientProvider provider = new ResilientProvider(delegate, manager);

        provider.send(baseSmsData(), baseSenderDto(), "tenant-soft");
        provider.send(baseSmsData(), baseSenderDto(), "tenant-soft");

        provider.send(baseSmsData(), baseSenderDto(), "tenant-soft");
        Assert.assertEquals(delegate.getInvocationCount(), 2);
    }

    @Test(expectedExceptions = ProviderException.class,
            expectedExceptionsMessageRegExp = ".*Tenant domain is null or blank.*")
    public void testRejectsBlankTenantDomain() throws ProviderException {

        ResilientProvider provider = new ResilientProvider(new NoopProvider(), new PerTenantCircuitBreakerManager(
                Policy.builder().setEnabled(true).build()));
        provider.send(baseSmsData(), baseSenderDto(), " ");
    }

    private ProviderException assertProviderException(ResilientProvider provider, String tenantDomain)
            throws Exception {

        try {
            provider.send(baseSmsData(), baseSenderDto(), tenantDomain);
        } catch (ProviderException exception) {
            return exception;
        }
        throw new AssertionError("Expected ProviderException was not thrown");
    }

    private SMSData baseSmsData() {

        SMSData smsData = new SMSData();
        smsData.setToNumber("+11111111111");
        smsData.setBody("otp");
        return smsData;
    }

    private SMSSenderDTO baseSenderDto() {

        return new SMSSenderDTO();
    }

    private static class NoopProvider implements Provider {

        @Override
        public String getName() {

            return "NOOP";
        }

        @Override
        public void send(SMSData smsData, SMSSenderDTO smsSenderDTO, String tenantDomain) {

        }
    }

    private static class AlwaysFailProvider implements Provider {

        private final AtomicInteger invocationCount = new AtomicInteger();

        @Override
        public String getName() {

            return "FAIL_PROVIDER";
        }

        @Override
        public void send(SMSData smsData, SMSSenderDTO smsSenderDTO, String tenantDomain) throws ProviderException {

            invocationCount.incrementAndGet();
            throw new ProviderException("Simulated downstream failure");
        }

        int getInvocationCount() {

            return invocationCount.get();
        }
    }

    private static class SoftFailProvider implements Provider {

        private final AtomicInteger invocationCount = new AtomicInteger();

        @Override
        public String getName() {

            return "SOFT_FAIL_PROVIDER";
        }

        @Override
        public void send(SMSData smsData, SMSSenderDTO smsSenderDTO, String tenantDomain) throws ProviderException {

            invocationCount.incrementAndGet();
            throw new NonBlockingProviderException("Soft failure");
        }

        int getInvocationCount() {

            return invocationCount.get();
        }
    }
}
