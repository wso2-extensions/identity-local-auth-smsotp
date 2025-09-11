/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
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

import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class ProviderUtilTest {

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
}
