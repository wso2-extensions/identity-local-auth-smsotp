/*
 * Copyright (c) 2025-2026, WSO2 LLC. (https://www.wso2.com).
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

import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.local.auth.smsotp.provider.constant.Constants;
import org.wso2.carbon.utils.DiagnosticLog;

import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;

public class ProviderUtilTest {

    private static final String MOBILE = "+1234567890";
    private static final String PROVIDER = "Twilio";

    private MockedStatic<LoggerUtils> mockedLoggerUtils;

    @BeforeMethod
    public void setUp() {

        mockedLoggerUtils = mockStatic(LoggerUtils.class);
    }

    @AfterMethod
    public void tearDown() {

        if (mockedLoggerUtils != null) {
            mockedLoggerUtils.close();
        }
    }

    @DataProvider(name = "parsePositiveOrDefaultData")
    public Object[][] parsePositiveOrDefaultData() {
        return new Object[][]{
                {null, 5, 5},
                {"", 7, 7},
                {"   \t  ", 9, 9},
                {"abc", 3, 3},
                {"0", 11, 11},
                {"-5", 13, 13},
                {"10", 1, 10},
                {"  42  ", 2, 42},
                {"+7", 4, 7}
        };
    }

    @Test(dataProvider = "parsePositiveOrDefaultData")
    public void testParsePositiveOrDefault(String value, int defaultValue, int expected) {

        int result = ProviderUtil.parsePositiveOrDefault(value, defaultValue);
        Assert.assertEquals(result, expected);
    }

    @Test
    public void testTriggerDiagnosticLogEventIncludesProviderStatus() {

        mockedLoggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);

        ProviderUtil.triggerDiagnosticLogEvent("SMS was accepted by the SMS provider.", MOBILE, PROVIDER, "202",
                DiagnosticLog.ResultStatus.SUCCESS);

        DiagnosticLog.DiagnosticLogBuilder builder = captureTriggeredLogBuilder();
        DiagnosticLog diagnosticLog = builder.build();
        Assert.assertEquals(diagnosticLog.getResultStatus(), DiagnosticLog.ResultStatus.SUCCESS.name());
        Assert.assertEquals(diagnosticLog.getInput().get(Constants.InputKeys.PROVIDER_STATUS), "202",
                "The status returned by the SMS provider should be logged as a separate input parameter.");
    }

    @Test
    public void testTriggerDiagnosticLogEventOmitsBlankProviderStatus() {

        mockedLoggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);

        // The four argument variant is used where the provider does not report a status.
        ProviderUtil.triggerDiagnosticLogEvent("Error occurred while sending SMS.", MOBILE, PROVIDER,
                DiagnosticLog.ResultStatus.FAILED);

        DiagnosticLog.DiagnosticLogBuilder builder = captureTriggeredLogBuilder();
        DiagnosticLog diagnosticLog = builder.build();
        Assert.assertEquals(diagnosticLog.getResultStatus(), DiagnosticLog.ResultStatus.FAILED.name());
        Map<String, Object> input = diagnosticLog.getInput();
        Assert.assertTrue(input == null || !input.containsKey(Constants.InputKeys.PROVIDER_STATUS),
                "A blank provider status should not be added as an input parameter.");
    }

    @Test
    public void testTriggerDiagnosticLogEventSkippedWhenDiagnosticLogsDisabled() {

        mockedLoggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(false);

        ProviderUtil.triggerDiagnosticLogEvent("SMS was accepted by the SMS provider.", MOBILE, PROVIDER, "200",
                DiagnosticLog.ResultStatus.SUCCESS);

        mockedLoggerUtils.verify(() -> LoggerUtils.triggerDiagnosticLogEvent(
                any(DiagnosticLog.DiagnosticLogBuilder.class)), never());
    }

    private DiagnosticLog.DiagnosticLogBuilder captureTriggeredLogBuilder() {

        ArgumentCaptor<DiagnosticLog.DiagnosticLogBuilder> captor =
                ArgumentCaptor.forClass(DiagnosticLog.DiagnosticLogBuilder.class);
        mockedLoggerUtils.verify(() -> LoggerUtils.triggerDiagnosticLogEvent(captor.capture()));
        return captor.getValue();
    }
}
