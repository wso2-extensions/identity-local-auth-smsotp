/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.local.auth.smsotp.authenticator;

import org.wso2.carbon.identity.auth.otp.core.AbstractOTPExecutor;
import org.wso2.carbon.identity.auth.otp.core.constant.OTPExecutorConstants;
import org.wso2.carbon.identity.auth.otp.core.model.OTP;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineException;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineServerException;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.governance.service.notification.NotificationChannels;
import org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants;
import org.wso2.carbon.identity.local.auth.smsotp.authenticator.util.SMSOTPExecutorUtils;
import org.wso2.carbon.utils.DiagnosticLog;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.PASSWORD_RESET_TEMPLATE;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.SMS_OTP_VERIFICATION_TEMPLATE;

/**
 * SMS OTP executor class.
 */
public class SMSOTPExecutor extends AbstractOTPExecutor {

    private static final String PASSWORD_RECOVERY = "PASSWORD_RECOVERY";
    private static final String REGISTRATION = "REGISTRATION";
    private static final String ASK_PASSWORD = "ASK_PASSWORD";

    @Override
    public String getName() {

        return "SMSOTPExecutor";
    }

    @Override
    public List<String> getInitiationData() {

        List<String> initiationData = new ArrayList<>();
        initiationData.add(SMSOTPConstants.Claims.MOBILE_CLAIM);
        return initiationData;
    }

    @Override
    public ExecutorResponse rollback(FlowExecutionContext flowExecutionContext) throws FlowEngineException {

        return null;
    }

    @Override
    protected Event getSendOTPEvent(OTPExecutorConstants.OTPScenarios scenario, OTP otp,
                                    FlowExecutionContext flowExecutionContext) throws FlowEngineServerException {

        Map<String, Object> metaProperties = new HashMap<>();
        String smsTemplate = resolveOTPTemplate(flowExecutionContext);
        String mobile = String.valueOf(flowExecutionContext.getFlowUser()
                .getClaim(SMSOTPConstants.Claims.MOBILE_CLAIM));

        metaProperties.put(IdentityEventConstants.EventProperty.NOTIFICATION_CHANNEL,
                NotificationChannels.SMS_CHANNEL.getChannelType());
        metaProperties.put(SMSOTPConstants.ATTRIBUTE_SMS_SENT_TO, mobile);
        metaProperties.put(SMSOTPConstants.OTP_TOKEN, otp);
        metaProperties.put(SMSOTPConstants.ConnectorConfig.OTP_EXPIRY_TIME, String.valueOf(
                SMSOTPExecutorUtils.getOTPValidityPeriod(flowExecutionContext.getTenantDomain()) / 60000));
        metaProperties.put(SMSOTPConstants.TEMPLATE_TYPE, smsTemplate);
        metaProperties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, flowExecutionContext.getTenantDomain());

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    getDiagnosticLogComponentId(), SMSOTPConstants.LogConstants.ActionIDs.SEND_SMS_OTP);
            diagnosticLogBuilder.resultMessage("SMS OTP sent successfully.")
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .inputParam(LogConstants.InputKeys.SUBJECT, LoggerUtils.isLogMaskingEnable ?
                            LoggerUtils.getMaskedContent(mobile) : mobile)
                    .inputParam("scenario", scenario.name());
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }

        return new Event(SMSOTPConstants.EVENT_TRIGGER_NAME, metaProperties);
    }

    @Override
    protected void handleClaimUpdate(FlowExecutionContext flowExecutionContext, ExecutorResponse executorResponse) {

        String mobileNumber = (String) flowExecutionContext.getFlowUser()
                .getClaim(SMSOTPConstants.Claims.MOBILE_CLAIM);
        Map<String, Object> updatedClaims = new HashMap<>();
        updatedClaims.put(SMSOTPConstants.Claims.VERIFIED_MOBILE_NUMBERS_CLAIM, mobileNumber);
        executorResponse.setUpdatedUserClaims(updatedClaims);
    }

    @Override
    protected String getDiagnosticLogComponentId() {

        return SMSOTPConstants.LogConstants.SMS_OTP_SERVICE;
    }

    @Override
    protected int getOTPLength(String tenantDomain) throws FlowEngineException {

        return SMSOTPExecutorUtils.getOTPLength(tenantDomain);
    }

    @Override
    protected String getOTPCharset(String tenantDomain) throws FlowEngineException {

        return SMSOTPExecutorUtils.getOTPCharset(tenantDomain);
    }

    @Override
    protected int getMaxRetryCount(FlowExecutionContext flowExecutionContext) {

        return 3;
    }

    @Override
    protected long getOTPValidityPeriod(String tenantDomain) throws FlowEngineException {

        return SMSOTPExecutorUtils.getOTPValidityPeriod(tenantDomain);
    }

    @Override
    protected int getMaxResendCount(FlowExecutionContext flowExecutionContext) {

        return 3;
    }

    @Override
    protected String getPostOTPGeneratedEventName() {

        return IdentityEventConstants.Event.POST_GENERATE_SMS_OTP;
    }

    @Override
    protected String getPostOTPValidatedEventName() {

        return IdentityEventConstants.Event.POST_VALIDATE_SMS_OTP;
    }

    private String resolveOTPTemplate(FlowExecutionContext flowExecutionContext) {

        switch (flowExecutionContext.getFlowType()) {
            case REGISTRATION:
                return SMS_OTP_VERIFICATION_TEMPLATE;
            case PASSWORD_RECOVERY:
            case ASK_PASSWORD:
                return PASSWORD_RESET_TEMPLATE;
            default:
                return null;
        }
    }
}
