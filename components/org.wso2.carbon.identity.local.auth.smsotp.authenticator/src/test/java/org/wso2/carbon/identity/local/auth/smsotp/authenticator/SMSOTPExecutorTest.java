package org.wso2.carbon.identity.local.auth.smsotp.authenticator;

import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.auth.otp.core.constant.OTPExecutorConstants;
import org.wso2.carbon.identity.auth.otp.core.model.OTP;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants;
import org.wso2.carbon.identity.local.auth.smsotp.authenticator.util.SMSOTPExecutorUtils;
import org.wso2.carbon.identity.user.registration.engine.exception.RegistrationEngineException;
import org.wso2.carbon.identity.user.registration.engine.exception.RegistrationEngineServerException;
import org.wso2.carbon.identity.user.registration.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.user.registration.engine.model.RegistrationContext;

import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.mockStatic;

public class SMSOTPExecutorTest {

    private static final String CARBON_SUPER = "carbon.super";
    private static final SMSOTPExecutor smsotpExecutor = new SMSOTPExecutor();

    private static RegistrationContext registrationContext;
    private static MockedStatic<SMSOTPExecutorUtils> mockedSMSOTPExecutorUtils;
    private static MockedStatic<LoggerUtils> mockedLoggerUtils;

    @BeforeClass
    public void setUp() {

        registrationContext = new RegistrationContext();
        registrationContext.setTenantDomain(CARBON_SUPER);
        mockedSMSOTPExecutorUtils = mockStatic(SMSOTPExecutorUtils.class);
        mockedLoggerUtils = mockStatic(LoggerUtils.class);
    }

    @AfterClass
    public void tearDown() {

        if (mockedSMSOTPExecutorUtils != null) {
            mockedSMSOTPExecutorUtils.close();
        }
        if (mockedLoggerUtils != null) {
            mockedLoggerUtils.close();
        }
    }

    @Test
    public void testGetName() {

        Assert.assertEquals(smsotpExecutor.getName(), "SMSOTPExecutor");
    }

    @Test
    public void testGetInitiationData() {

        List<String> initiationData = smsotpExecutor.getInitiationData();
        Assert.assertNotNull(initiationData);
        Assert.assertEquals(initiationData.size(), 1);
        Assert.assertEquals(initiationData.get(0), SMSOTPConstants.Claims.MOBILE_CLAIM);
    }

    @Test
    public void testGetSendOTPEvent() throws RegistrationEngineServerException {

        OTP otp = new OTP("123456", 30000, 600000);
        registrationContext.getRegisteringUser().addClaim(SMSOTPConstants.Claims.MOBILE_CLAIM, "1234567890");

        mockedSMSOTPExecutorUtils.when(() -> SMSOTPExecutorUtils.getOTPValidityPeriod(CARBON_SUPER)).thenReturn(600000L);

        Event event = smsotpExecutor.getSendOTPEvent(OTPExecutorConstants.OTPScenarios.INITIAL_OTP, otp, registrationContext);

        Assert.assertEquals(event.getEventName(), SMSOTPConstants.EVENT_TRIGGER_NAME);
        Assert.assertEquals(event.getEventProperties().get(SMSOTPConstants.OTP_TOKEN), otp);
        Assert.assertEquals(event.getEventProperties().get(SMSOTPConstants.ATTRIBUTE_SMS_SENT_TO), "1234567890");
        Assert.assertEquals(event.getEventProperties().get(SMSOTPConstants.TEMPLATE_TYPE), SMSOTPConstants.EVENT_NAME);
        Assert.assertEquals(event.getEventProperties().get(SMSOTPConstants.ConnectorConfig.OTP_EXPIRY_TIME), "10");
    }

    @Test
    public void testHandleClaimUpdate_ReplaceExisting() {

        registrationContext.getRegisteringUser().addClaim(SMSOTPConstants.Claims.MOBILE_CLAIM, "1234567890");
        ExecutorResponse executorResponse = new ExecutorResponse();

        smsotpExecutor.handleClaimUpdate(registrationContext, executorResponse);

        Map<String, Object> updatedClaims = executorResponse.getUpdatedUserClaims();
        Assert.assertNotNull(updatedClaims);
        Assert.assertEquals(updatedClaims.get(SMSOTPConstants.Claims.VERIFIED_MOBILE_NUMBERS_CLAIM), "1234567890");
    }


    @Test
    public void testGetDiagnosticLogComponentId() {

        Assert.assertEquals(smsotpExecutor.getDiagnosticLogComponentId(), SMSOTPConstants.LogConstants.SMS_OTP_SERVICE);
    }

    @Test
    public void testGetOTPLength() throws RegistrationEngineException {

        mockedSMSOTPExecutorUtils.when(() -> SMSOTPExecutorUtils.getOTPLength(CARBON_SUPER)).thenReturn(6);
        Assert.assertEquals(smsotpExecutor.getOTPLength(CARBON_SUPER), 6);
    }

    @Test
    public void testGetOTPCharset() throws RegistrationEngineException {

        mockedSMSOTPExecutorUtils.when(() -> SMSOTPExecutorUtils.getOTPCharset(CARBON_SUPER)).thenReturn("123456");
        Assert.assertEquals(smsotpExecutor.getOTPCharset(CARBON_SUPER), "123456");
    }

    @Test
    public void testGetMaxRetryCount() {

        Assert.assertEquals(smsotpExecutor.getMaxRetryCount(registrationContext), 3);
    }

    @Test
    public void testGetOTPValidityPeriod() throws RegistrationEngineException {

        mockedSMSOTPExecutorUtils.when(() -> SMSOTPExecutorUtils.getOTPValidityPeriod(CARBON_SUPER)).thenReturn(600000L);
        Assert.assertEquals(smsotpExecutor.getOTPValidityPeriod(CARBON_SUPER), 600000L);
    }

    @Test
    public void testGetMaxResendCount() {

        Assert.assertEquals(smsotpExecutor.getMaxResendCount(registrationContext), 3);
    }

    @Test
    public void testGetPostOTPGeneratedEventName() {

        Assert.assertEquals(smsotpExecutor.getPostOTPGeneratedEventName(), "POST_GENERATE_SMS_OTP");
    }

    @Test
    public void testGetPostOTPValidatedEventName() {

        Assert.assertEquals(smsotpExecutor.getPostOTPValidatedEventName(), "POST_VALIDATE_SMS_OTP");
    }

    // Negative Tests for Exception Scenarios
    @Test(expectedExceptions = RegistrationEngineServerException.class)
    public void testGetOTPLength_Exception() throws RegistrationEngineException {

        mockedSMSOTPExecutorUtils.when(() -> SMSOTPExecutorUtils.getOTPLength(CARBON_SUPER))
                .thenThrow(new RegistrationEngineServerException("Error getting SMS OTP authenticator config"));
        smsotpExecutor.getOTPLength(CARBON_SUPER);
    }

    @Test(expectedExceptions = RegistrationEngineServerException.class)
    public void testGetOTPCharset_Exception() throws RegistrationEngineException {

        mockedSMSOTPExecutorUtils.when(() -> SMSOTPExecutorUtils.getOTPCharset(CARBON_SUPER))
                .thenThrow(new RegistrationEngineServerException("Error getting SMS OTP authenticator config"));
        smsotpExecutor.getOTPCharset(CARBON_SUPER);
    }

    @Test(expectedExceptions = RegistrationEngineServerException.class)
    public void testGetOTPValidityPeriod_Exception() throws RegistrationEngineException {

        mockedSMSOTPExecutorUtils.when(() -> SMSOTPExecutorUtils.getOTPValidityPeriod(CARBON_SUPER))
                .thenThrow(new RegistrationEngineServerException("Error getting SMS OTP authenticator config"));
        smsotpExecutor.getOTPValidityPeriod(CARBON_SUPER);
    }
}
