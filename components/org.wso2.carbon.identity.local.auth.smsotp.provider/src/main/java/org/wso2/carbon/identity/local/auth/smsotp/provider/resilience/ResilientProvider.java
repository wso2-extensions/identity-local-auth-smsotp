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

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.core.circuitbreaker.Decision;
import org.wso2.carbon.identity.core.circuitbreaker.PerTenantCircuitBreakerManager;
import org.wso2.carbon.identity.core.circuitbreaker.PolicyConfiguration;
import org.wso2.carbon.identity.core.circuitbreaker.TenantKeyUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.local.auth.smsotp.provider.Provider;
import org.wso2.carbon.identity.local.auth.smsotp.provider.exception.NonBlockingProviderException;
import org.wso2.carbon.identity.local.auth.smsotp.provider.exception.ProviderException;
import org.wso2.carbon.identity.local.auth.smsotp.provider.model.SMSData;
import org.wso2.carbon.identity.notification.sender.tenant.config.dto.SMSSenderDTO;

import java.util.Objects;

/**
 * Provider decorator that enforces per-tenant breaker and bulkhead controls.
 */
public class ResilientProvider implements Provider {

    private static final String TENANT_BREAKER_PROPERTY_PREFIX = "NotificationChannel.SMS.PerTenantBreaker";
    private static final String SMS_SERVICE_KEY = "sms";
    private static final PerTenantCircuitBreakerManager DEFAULT_BREAKER_MANAGER = new PerTenantCircuitBreakerManager(
            PolicyConfiguration.fromProperties(TENANT_BREAKER_PROPERTY_PREFIX, IdentityUtil::getProperty),
            new SmsTenantBreakerObserver());

    private final Provider delegate;
    private final PerTenantCircuitBreakerManager breakerManager;

    public ResilientProvider(Provider delegate) {

        this(delegate, DEFAULT_BREAKER_MANAGER);
    }

    ResilientProvider(Provider delegate, PerTenantCircuitBreakerManager breakerManager) {

        this.delegate = Objects.requireNonNull(delegate, "delegate provider cannot be null");
        this.breakerManager = Objects.requireNonNull(breakerManager, "breakerManager cannot be null");
    }

    @Override
    public String getName() {

        return delegate.getName();
    }

    @Override
    public void send(SMSData smsData, SMSSenderDTO smsSenderDTO, String tenantDomain) throws ProviderException {

        if (StringUtils.isBlank(tenantDomain)) {
            throw new ProviderException("Tenant domain is null or blank. Cannot apply provider resilience.");
        }

        long startTimeMs = System.currentTimeMillis();
        String tenantServiceKey = TenantKeyUtil.buildTenantServiceKey(tenantDomain, SMS_SERVICE_KEY);
        boolean acquired = false;
        boolean success = false;

        if (breakerManager.isEnabled()) {
            Decision decision = breakerManager.tryAcquire(tenantServiceKey, startTimeMs);
            if (!decision.isAllowed()) {
                return;
            } else {
                acquired = true;
            }
        }

        try {
            delegate.send(smsData, smsSenderDTO, tenantDomain);
            success = true;
        } catch (ProviderException exception) {
            if (!(exception instanceof NonBlockingProviderException)) {
                throw exception;
            }
        } finally {
            if (acquired) {
                long endTimeMs = System.currentTimeMillis();
                breakerManager.onComplete(tenantServiceKey, success, endTimeMs);
                breakerManager.releaseBulkhead(tenantServiceKey, endTimeMs);
            }
        }
    }
}
