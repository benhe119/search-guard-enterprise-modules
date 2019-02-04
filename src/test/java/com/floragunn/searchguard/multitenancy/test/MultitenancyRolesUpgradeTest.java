package com.floragunn.searchguard.multitenancy.test;

import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.floragunn.searchguard.DefaultObjectMapper;
import com.floragunn.searchguard.dlic.rest.api.AbstractRestApiUnitTest;
import com.floragunn.searchguard.test.helper.rest.RestHelper.HttpResponse;

public class MultitenancyRolesUpgradeTest extends AbstractRestApiUnitTest {

    @Override
    protected String getResourceFolder() {
        return "multitenancy";
    }
    

	@Test
	public void testUpgradeConfigFormat() throws Exception {

		setup();

		rh.keystore = "restapi/kirk-keystore.jks";
		rh.sendHTTPClientCertificate = true;
		
		HttpResponse response = rh.executePostRequest("/_searchguard/api/roles/", "{\"action\": \"formatUpgrade\"}",  new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

		response = rh.executeGetRequest("/_searchguard/api/roles/", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		
		JsonNode responseJson = DefaultObjectMapper.objectMapper.readTree(response.getBody());

		Assert.assertEquals("kibana:saved_objects/*/*", responseJson.get("sg_human_resources").get("tenants").get("human_resources").get("applications").get(0).asText());
		Assert.assertEquals("kibana:saved_objects/*/read", responseJson.get("sg_human_resources").get("tenants").get("business_intelligence").get("applications").get(0).asText());

	}
}