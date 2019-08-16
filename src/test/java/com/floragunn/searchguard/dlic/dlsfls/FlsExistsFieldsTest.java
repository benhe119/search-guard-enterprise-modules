/*
 * Copyright 2016-2017 by floragunn GmbH - All rights reserved
 * 
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed here is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * 
 * This software is free of charge for non-commercial and academic use. 
 * For commercial use in a production environment you have to obtain a license 
 * from https://floragunn.com
 * 
 */

package com.floragunn.searchguard.dlic.dlsfls;

import java.io.IOException;

import org.apache.http.HttpStatus;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.xcontent.XContentType;
import org.junit.Assert;
import org.junit.Test;

import com.floragunn.searchguard.test.helper.file.FileHelper;
import com.floragunn.searchguard.test.helper.rest.RestHelper.HttpResponse;

public class FlsExistsFieldsTest extends AbstractDlsFlsTest {

    protected void populate(TransportClient tc) {

        tc.index(new IndexRequest("searchguard").type("sg").id("config").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("config",
                FileHelper.readYamlContent("dlsfls/sg_config.yml"))).actionGet();
        tc.index(new IndexRequest("searchguard").type("sg").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("internalusers").source("internalusers",
                FileHelper.readYamlContent("dlsfls/sg_internal_users.yml"))).actionGet();
        tc.index(new IndexRequest("searchguard").type("sg").id("roles").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("roles",
                FileHelper.readYamlContent("dlsfls/sg_roles.yml"))).actionGet();
        tc.index(new IndexRequest("searchguard").type("sg").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("rolesmapping").source("rolesmapping",
                FileHelper.readYamlContent("dlsfls/sg_roles_mapping.yml"))).actionGet();
        tc.index(new IndexRequest("searchguard").type("sg").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("actiongroups").source("actiongroups",
                FileHelper.readYamlContent("dlsfls/sg_action_groups.yml"))).actionGet();

        tc.admin().indices().create(new CreateIndexRequest("data").mapping("doc", 
                "@timestamp", "type=date", 
                "host", "type=text,norms=false",
                "response", "type=text,norms=false",
                "non-existing", "type=text,norms=false"
                ))
                .actionGet();

        for (int i = 0; i < 1; i++) {
            String doc = "{\"host\" : \"myhost"+i+"\",\n" + 
                    "        \"@timestamp\" : \"2018-01-18T09:03:25.877Z\",\n" + 
                    "        \"response\": \"404\"}";
            tc.index(new IndexRequest("data").type("doc").id("a-normal-" + i).setRefreshPolicy(RefreshPolicy.IMMEDIATE).source(doc,
                    XContentType.JSON)).actionGet();
        }

        for (int i = 0; i < 1; i++) {
            String doc = "{" + 
                    "        \"@timestamp\" : \"2017-01-18T09:03:25.877Z\",\n" + 
                    "        \"response\": \"200\"}";
            tc.index(new IndexRequest("data").type("doc").id("b-missing1-" + i).setRefreshPolicy(RefreshPolicy.IMMEDIATE).source(doc,
                    XContentType.JSON)).actionGet();
        }
        
        for (int i = 0; i < 1; i++) {
            String doc = "{\"host\" : \"myhost"+i+"\",\n" + 
                    "        \"@timestamp\" : \"2018-01-18T09:03:25.877Z\",\n" + 
                    "         \"non-existing\": \"xxx\","+
                    "        \"response\": \"403\"}";
            tc.index(new IndexRequest("data").type("doc").id("c-missing2-" + i).setRefreshPolicy(RefreshPolicy.IMMEDIATE).source(doc,
                    XContentType.JSON)).actionGet();
        }

    }

    @Test
    public void testExistsField() throws Exception {
        setup();

        String query = "{\n" + 
                "  \"query\": {\n" + 
                "    \"bool\": {\n" + 
                
                "      \"must_not\": \n" + 
                "      {\n" + 
                "          \"exists\": {\n" + 
                "            \"field\": \"non-existing\"\n" + 
                "            \n" + 
                "          }\n" + 
                "      },\n" + 
                
                "      \"must\": [\n" + 
                "        {\n" + 
                "          \"exists\": {\n" + 
                "            \"field\": \"@timestamp\"\n" + 
                "          }\n" + 
                "        },\n" + 
                "        {\n" + 
                "          \"exists\": {\n" + 
                "            \"field\": \"host\"\n" + 
                "          }\n" + 
                "        }\n" + 
                "      ]\n" + 
                "    }\n" + 
                "  }\n" + 
                "}";

        HttpResponse res;
        Assert.assertEquals(HttpStatus.SC_OK,
                (res = rh.executePostRequest("/data/_search?pretty", query, encodeBasicHeader("admin", "admin"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("\"total\" : 1,\n    \"max_"));
        Assert.assertTrue(res.getBody().contains("a-normal-0"));
        Assert.assertTrue(res.getBody().contains("response"));
        Assert.assertTrue(res.getBody().contains("404"));

        //only see's - timestamp and host field
        //therefore non-existing does not exist so we expect c-missing2-0 to be returned
        Assert.assertEquals(HttpStatus.SC_OK,
                (res = rh.executePostRequest("/data/_search?pretty", query, encodeBasicHeader("fls_exists", "password"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("\"total\" : 2,\n    \"max_"));
        Assert.assertTrue(res.getBody().contains("a-normal-0"));
        Assert.assertTrue(res.getBody().contains("c-missing2-0"));
        Assert.assertFalse(res.getBody().contains("response"));
    }
}