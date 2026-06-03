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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.circuitbreaker.CircuitState;
import org.wso2.carbon.identity.core.circuitbreaker.RejectReason;
import org.wso2.carbon.identity.core.circuitbreaker.TenantBreakerObserver;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.local.auth.smsotp.provider.util.ProviderUtil;

/**
 * SMS-specific observer that publishes breaker logs and diagnostics.
 */
class SmsTenantBreakerObserver implements TenantBreakerObserver {

    private static final Log LOG = LogFactory.getLog(SmsTenantBreakerObserver.class);
    private static final String ADMISSION_EVICTION_LOG_PROPERTY =
            "NotificationChannel.SMS.PerTenantBreaker.AdmissionEvictionLogsEnabled";
    private static final String ADMISSION_EVICTION_LOG_ENV =
            "SMS_OTP_TENANT_BREAKER_ADMISSION_EVICTION_LOGS_ENABLED";
    private static final boolean ADMISSION_EVICTION_LOG_ENABLED = resolveAdmissionEvictionLogEnabled();

    @Override
    public void onStateTransition(String tenantKey, CircuitState previousState, CircuitState currentState,
                                  int calls, int failures, double failureRate, double failureRateThreshold) {

        String transitionMessage = "Per-tenant circuit transition [tenantKey=" + tenantKey
                + ", from=" + previousState
                + ", to=" + currentState
                + ", calls=" + calls
                + ", failures=" + failures
                + ", failureRate=" + failureRate
                + ", failureRateThreshold=" + failureRateThreshold + "]";

        if (CircuitState.OPEN == currentState) {
            LOG.warn(transitionMessage);
        } else {
            LOG.info(transitionMessage);
        }

        ProviderUtil.triggerCircuitTransitionDiagnosticLogEvent(tenantKey, previousState.name(), currentState.name(),
                calls, failures, failureRate, failureRateThreshold);
    }

    @Override
    public void onRejection(String tenantKey, RejectReason rejectReason, CircuitState state, Integer calls,
                            Integer failures, Double failureRate, Integer inFlight) {

        StringBuilder builder = new StringBuilder("Per-tenant circuit rejection [tenantKey=")
                .append(tenantKey)
                .append(", reason=")
                .append(rejectReason);

        if (state != null) {
            builder.append(", state=").append(state)
                    .append(", calls=").append(calls)
                    .append(", failures=").append(failures)
                    .append(", failureRate=").append(failureRate)
                    .append(", inFlight=").append(inFlight);
        }
        builder.append(']');
        LOG.warn(builder.toString());

        ProviderUtil.triggerCircuitRejectionDiagnosticLogEvent(tenantKey, rejectReason.name(),
                state != null ? state.name() : null, calls, failures, failureRate, inFlight);
    }

    @Override
    public void onForcedEviction(String tenantKey) {

        if (ADMISSION_EVICTION_LOG_ENABLED && LOG.isInfoEnabled()) {
            LOG.info("Per-tenant circuit forced eviction [tenantKey=" + tenantKey
                    + ", reason=BREAKER_CACHE_SATURATED]");
        }
    }

    @Override
    public void onUncachedAdmission(String tenantKey, RejectReason reason) {

        if (ADMISSION_EVICTION_LOG_ENABLED && LOG.isInfoEnabled()) {
            LOG.info("Per-tenant circuit uncached admission [tenantKey=" + tenantKey
                    + ", reason=" + reason + "]");
        }
    }

    private static boolean resolveAdmissionEvictionLogEnabled() {

        String configuredValue = IdentityUtil.getProperty(ADMISSION_EVICTION_LOG_PROPERTY);
        if (StringUtils.isNotBlank(configuredValue)) {
            return Boolean.parseBoolean(configuredValue.trim());
        }

        String envValue = System.getenv(ADMISSION_EVICTION_LOG_ENV);
        if (StringUtils.isNotBlank(envValue)) {
            return Boolean.parseBoolean(envValue.trim());
        }

        return false;
    }
}
