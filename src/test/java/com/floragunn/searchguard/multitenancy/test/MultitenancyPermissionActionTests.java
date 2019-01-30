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
                "_searchguard/permission?permissions=kibana:saved_objects/x/read,kibana:saved_objects/x/write,kibana:foo/foo,kibana:foo/bar",
                new BasicHeader("sgtenant", "vesting_stats"), encodeBasicHeader("hr_employee", "hr_employee"));

        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().matches(".*\"kibana:saved_objects/x/read\":\\s*true.*"));
        Assert.assertTrue(response.getBody().matches(".*\"kibana:saved_objects/x/write\":\\s*true.*"));
        Assert.assertTrue(response.getBody().matches(".*\"kibana:foo/foo\":\\s*false.*"));
        Assert.assertTrue(response.getBody().matches(".*\"kibana:foo/bar\":\\s*true.*"));

        response = rh.executeGetRequest(
                "_searchguard/permission?permissions=kibana:saved_objects/x/read,kibana:saved_objects/x/write,kibana:foo/foo,kibana:foo/bar",
                new BasicHeader("sgtenant", "vesting_stats"), encodeBasicHeader("hr_trainee", "hr_trainee"));

        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().matches(".*\"kibana:saved_objects/x/read\":\\s*true.*"));
        Assert.assertTrue(response.getBody().matches(".*\"kibana:saved_objects/x/write\":\\s*false.*"));
        Assert.assertTrue(response.getBody().matches(".*\"kibana:foo/foo\":\\s*false.*"));
        Assert.assertTrue(response.getBody().matches(".*\"kibana:foo/bar\":\\s*false.*"));

        response = rh.executeGetRequest(
                "_searchguard/permission?permissions=kibana:saved_objects/x/read,kibana:saved_objects/x/write,kibana:foo/foo,kibana:foo/bar",
                new BasicHeader("sgtenant", "human_resources"), encodeBasicHeader("hr_employee", "hr_employee"));

        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().matches(".*\"kibana:saved_objects/x/read\":\\s*true.*"));
        Assert.assertTrue(response.getBody().matches(".*\"kibana:saved_objects/x/write\":\\s*true.*"));
        Assert.assertTrue(response.getBody().matches(".*\"kibana:foo/foo\":\\s*false.*"));
        Assert.assertTrue(response.getBody().matches(".*\"kibana:foo/bar\":\\s*false.*"));
        
        response = rh.executeGetRequest(
                "_searchguard/permission?permissions=kibana:saved_objects/x/read,kibana:saved_objects/x/write,kibana:foo/foo,kibana:foo/bar",
                new BasicHeader("sgtenant", "human_resources"), encodeBasicHeader("hr_trainee", "hr_trainee"));

        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().matches(".*\"kibana:saved_objects/x/read\":\\s*true.*"));
        Assert.assertTrue(response.getBody().matches(".*\"kibana:saved_objects/x/write\":\\s*false.*"));
        Assert.assertTrue(response.getBody().matches(".*\"kibana:foo/foo\":\\s*false.*"));
        Assert.assertTrue(response.getBody().matches(".*\"kibana:foo/bar\":\\s*false.*"));
    }

}
