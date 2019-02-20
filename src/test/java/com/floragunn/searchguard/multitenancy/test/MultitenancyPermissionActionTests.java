/*
 * Copyright 2015-2018 floragunn GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.floragunn.searchguard.multitenancy.test;

import org.apache.http.HttpStatus;
import org.apache.http.message.BasicHeader;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import com.floragunn.searchguard.test.DynamicSgConfig;
import com.floragunn.searchguard.test.SingleClusterTest;
import com.floragunn.searchguard.test.helper.cluster.ClusterConfiguration;
import com.floragunn.searchguard.test.helper.rest.RestHelper;
import com.floragunn.searchguard.test.helper.rest.RestHelper.HttpResponse;

public class MultitenancyPermissionActionTests extends SingleClusterTest {

    @Override
    protected String getResourceFolder() {
        return "multitenancy";
    }

    @Test
    public void test() throws Exception {
        Settings settings = Settings.builder().build();

        setup(Settings.EMPTY, new DynamicSgConfig(), settings, true, ClusterConfiguration.DEFAULT);

        RestHelper rh = nonSslRestHelper();

        HttpResponse response = rh.executeGetRequest(
                "_searchguard/permission?permissions=kibana:ui:navLinks/x,kibana:ui:navLinks/y,kibana:foo/foo,kibana:foo/bar,searchguard:tenant/write,searchguard:tenant/read",
                new BasicHeader("sgtenant", "vesting_stats"), encodeBasicHeader("hr_employee", "hr_employee"));

        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().matches(".*\"kibana:ui:navLinks/x\":\\s*true.*"));
        Assert.assertTrue(response.getBody().matches(".*\"kibana:ui:navLinks/y\":\\s*true.*"));
        Assert.assertTrue(response.getBody().matches(".*\"kibana:foo/foo\":\\s*false.*"));
        Assert.assertTrue(response.getBody().matches(".*\"kibana:foo/bar\":\\s*true.*"));
        Assert.assertTrue(response.getBody().matches(".*\"searchguard:tenant/write\":\\s*true.*"));
        Assert.assertTrue(response.getBody().matches(".*\"searchguard:tenant/read\":\\s*false.*"));

        response = rh.executeGetRequest(
                "_searchguard/permission?permissions=kibana:ui:navLinks/x,kibana:ui:navLinks/y,kibana:foo/foo,kibana:foo/bar,searchguard:tenant/write,searchguard:tenant/read",
                new BasicHeader("sgtenant", "vesting_stats"), encodeBasicHeader("hr_trainee", "hr_trainee"));

        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().matches(".*\"kibana:foo/foo\":\\s*false.*"));
        Assert.assertTrue(response.getBody().matches(".*\"kibana:foo/bar\":\\s*false.*"));
        Assert.assertTrue(response.getBody().matches(".*\"searchguard:tenant/write\":\\s*false.*"));
        Assert.assertTrue(response.getBody().matches(".*\"searchguard:tenant/read\":\\s*true.*"));

        response = rh.executeGetRequest(
                "_searchguard/permission?permissions=kibana:ui:navLinks/x,kibana:ui:navLinks/y,kibana:foo/foo,kibana:foo/bar,searchguard:tenant/write,searchguard:tenant/read",
                new BasicHeader("sgtenant", "human_resources"), encodeBasicHeader("hr_employee", "hr_employee"));

        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().matches(".*\"searchguard:tenant/write\":\\s*true.*"));
        Assert.assertTrue(response.getBody().matches(".*\"searchguard:tenant/read\":\\s*false.*"));
        Assert.assertTrue(response.getBody().matches(".*\"kibana:ui:navLinks/x\":\\s*true.*"));
        Assert.assertTrue(response.getBody().matches(".*\"kibana:foo/foo\":\\s*false.*"));
        Assert.assertTrue(response.getBody().matches(".*\"kibana:foo/bar\":\\s*false.*"));

        response = rh.executeGetRequest(
                "_searchguard/permission?permissions=kibana:ui:navLinks/x,kibana:ui:navLinks/y,kibana:foo/foo,kibana:foo/bar,searchguard:tenant/write,searchguard:tenant/read",
                new BasicHeader("sgtenant", "human_resources"), encodeBasicHeader("hr_trainee", "hr_trainee"));

        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().matches(".*\"searchguard:tenant/write\":\\s*false.*"));
        Assert.assertTrue(response.getBody().matches(".*\"searchguard:tenant/read\":\\s*true.*"));
        Assert.assertTrue(response.getBody().matches(".*\"kibana:foo/foo\":\\s*false.*"));
        Assert.assertTrue(response.getBody().matches(".*\"kibana:foo/bar\":\\s*false.*"));
    }

}
