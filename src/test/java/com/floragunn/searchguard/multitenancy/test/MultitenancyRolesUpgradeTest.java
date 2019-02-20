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

import java.util.Arrays;
import java.util.HashSet;

import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.floragunn.searchguard.dlic.rest.api.AbstractRestApiUnitTest;
import com.floragunn.searchguard.test.helper.rest.RestHelper.HttpResponse;

public class MultitenancyRolesUpgradeTest extends AbstractRestApiUnitTest {

    @Override
    protected String getResourceFolder() {
        return "multitenancy";
    }

    @Test
    public void testRolesUpgrade() throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();

        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendHTTPClientCertificate = true;

        HttpResponse response = rh.executePostRequest("/_searchguard/kibanainfo", "{\"action\": \"formatUpgrade\"}", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeGetRequest("/_searchguard/api/roles/", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        JsonNode responseJson = objectMapper.readTree(response.getBody());

        final HashSet<String> permissions = new HashSet<>();
        responseJson.at("/sg_human_resources/tenants/human_resources/applications").elements().forEachRemaining(n -> permissions.add(n.asText()));

        Assert.assertEquals(new HashSet<>(Arrays.asList("searchguard:tenant/write", "kibana:ui:navLinks/*")), permissions);

        permissions.clear();
        responseJson.at("/sg_human_resources/tenants/business_intelligence/applications").elements()
                .forEachRemaining(n -> permissions.add(n.asText()));

        Assert.assertEquals(new HashSet<>(Arrays.asList("searchguard:tenant/read", "kibana:ui:navLinks/*")), permissions);

    }
}
