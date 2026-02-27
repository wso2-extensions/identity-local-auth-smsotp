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

package org.wso2.carbon.identity.local.auth.smsotp.provider.util;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.local.auth.smsotp.provider.constant.Constants;
import org.wso2.carbon.utils.DiagnosticLog;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils.isDiagnosticLogsEnabled;

/**
 * This class represents the provider utility.
 *
 * @version 1.0.0
 * @since 1.0.0
 */
public class ProviderUtil {

    private static final Log LOG = LogFactory.getLog(ProviderUtil.class);
    private static final AtomicBoolean DIAGNOSTIC_LOG_FALLBACK_LOGGED = new AtomicBoolean(false);

    /**
     * Hash the given telephone number using SHA-256 to print in logs. This is to avoid printing the telephone
     * number as a PII.
     * @param telephoneNumber Telephone number to be hashed.
     * @return Hashed telephone number.
     */
    public static String hashTelephoneNumber(String telephoneNumber) {

        try {
            final MessageDigest digest = MessageDigest.getInstance("SHA3-256");
            final byte[] hash = digest.digest(telephoneNumber.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                hexString.append(String.format("%02X", b));
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException ex) {
            LOG.error("Error while hashing the telephone number.", ex);
            return "---";
        }
    }

    /**
     * Parse a positive integer value, or return the given default when blank/invalid/non-positive.
     *
     * @param value        String to parse.
     * @param defaultValue Default value to return on failure.
     * @return Parsed positive int, or defaultValue.
     */
    public static int parsePositiveOrDefault(String value, int defaultValue) {

        if (StringUtils.isBlank(value)) {
            return defaultValue;
        }
        try {
            int parsed = Integer.parseInt(value.trim());
            return parsed > 0 ? parsed : defaultValue;
        } catch (NumberFormatException exception) {
            return defaultValue;
        }
    }

    /**
     * Trigger Diagnostic Log Event.
     *
     * @param resultMessage Result message.
     * @param resultStatus  Result status.
     * @param provider      SMS provider name.
     * @param mobile        Mobile number.
     */
    public static void triggerDiagnosticLogEvent(String resultMessage, String mobile, String provider,
                                                 DiagnosticLog.ResultStatus resultStatus) {

        if (!isDiagnosticLogsEnabled()) {
            return;
        }
        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                Constants.SMS_OTP_SERVICE, Constants.ActionIDs.SEND_SMS);
        diagnosticLogBuilder
                .resultMessage(resultMessage)
                .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                .configParam("provider", provider)
                .resultStatus(resultStatus)
                .inputParam(LogConstants.InputKeys.SUBJECT,
                        LoggerUtils.isLogMaskingEnable ? LoggerUtils.getMaskedContent(mobile) : mobile);
        LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
    }

    /**
     * Trigger Diagnostic Log Event for per-tenant breaker state transitions.
     *
     * @param tenantKey            Tenant key.
     * @param fromState            Previous state.
     * @param toState              Current state.
     * @param calls                Number of calls in window.
     * @param failures             Number of failures in window.
     * @param failureRate          Current failure rate.
     * @param failureRateThreshold Configured failure rate threshold.
     */
    public static void triggerCircuitTransitionDiagnosticLogEvent(String tenantKey, String fromState, String toState,
                                                                  int calls, int failures, double failureRate,
                                                                  double failureRateThreshold) {

        if (!isDiagnosticLogsEnabled()) {
            return;
        }
        DiagnosticLog.ResultStatus resultStatus =
                "OPEN".equals(toState) ? DiagnosticLog.ResultStatus.FAILED : DiagnosticLog.ResultStatus.SUCCESS;
        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                Constants.SMS_OTP_SERVICE, Constants.ActionIDs.CIRCUIT_BREAKER_STATE_TRANSITION);
        diagnosticLogBuilder
                .resultMessage("Per-tenant breaker state transitioned.")
                .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                .resultStatus(resultStatus)
                .inputParam("tenantKey", tenantKey)
                .inputParam("fromState", fromState)
                .inputParam("toState", toState)
                .inputParam("calls", String.valueOf(calls))
                .inputParam("failures", String.valueOf(failures))
                .inputParam("failureRate", String.valueOf(failureRate))
                .inputParam("failureRateThreshold", String.valueOf(failureRateThreshold));
        LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
    }

    /**
     * Trigger Diagnostic Log Event for per-tenant breaker rejections.
     *
     * @param tenantKey       Tenant key.
     * @param rejectReason    Rejection reason.
     * @param state           Current state. Null if unavailable.
     * @param calls           Number of calls in window. Null if unavailable.
     * @param failures        Number of failures in window. Null if unavailable.
     * @param failureRate     Current failure rate. Null if unavailable.
     * @param inFlight        In-flight count. Null if unavailable.
     */
    public static void triggerCircuitRejectionDiagnosticLogEvent(String tenantKey, String rejectReason,
                                                                 String state, Integer calls, Integer failures,
                                                                 Double failureRate, Integer inFlight) {

        if (!isDiagnosticLogsEnabled()) {
            return;
        }
        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                Constants.SMS_OTP_SERVICE, Constants.ActionIDs.CIRCUIT_BREAKER_REJECTION);
        diagnosticLogBuilder
                .resultMessage("Per-tenant breaker request rejected.")
                .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                .resultStatus(DiagnosticLog.ResultStatus.FAILED)
                .inputParam("tenantKey", tenantKey)
                .inputParam("rejectReason", rejectReason);
        if (state != null) {
            diagnosticLogBuilder.inputParam("state", state);
        }
        if (calls != null) {
            diagnosticLogBuilder.inputParam("calls", String.valueOf(calls));
        }
        if (failures != null) {
            diagnosticLogBuilder.inputParam("failures", String.valueOf(failures));
        }
        if (failureRate != null) {
            diagnosticLogBuilder.inputParam("failureRate", String.valueOf(failureRate));
        }
        if (inFlight != null) {
            diagnosticLogBuilder.inputParam("inFlight", String.valueOf(inFlight));
        }
        LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
    }
}
