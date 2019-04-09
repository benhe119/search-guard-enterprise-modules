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

import org.apache.http.HttpStatus;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentType;
import org.junit.Assert;
import org.junit.Test;

import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.test.helper.file.FileHelper;
import com.floragunn.searchguard.test.helper.rest.RestHelper.HttpResponse;

public class DlsDateMathTest extends AbstractDlsFlsTest{


    @Override
    protected void populate(TransportClient tc) {

        tc.index(new IndexRequest("searchguard").type("sg").id("config").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("config", FileHelper.readYamlContent("dlsfls/sg_config.yml"))).actionGet();
        tc.index(new IndexRequest("searchguard").type("sg").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("internalusers")
                .source("internalusers", FileHelper.readYamlContent("dlsfls/sg_internal_users.yml"))).actionGet();
        tc.index(new IndexRequest("searchguard").type("sg").id("roles").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("roles", FileHelper.readYamlContent("dlsfls/sg_roles.yml"))).actionGet();
        tc.index(new IndexRequest("searchguard").type("sg").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("rolesmapping")
                .source("rolesmapping", FileHelper.readYamlContent("dlsfls/sg_roles_mapping.yml"))).actionGet();
        tc.index(new IndexRequest("searchguard").type("sg").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("actiongroups")
                .source("actiongroups", FileHelper.readYamlContent("dlsfls/sg_action_groups.yml"))).actionGet();

        tc.index(new IndexRequest("logstash").type("_doc").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"@timestamp\": \"2019/04/02\"}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest("logstash").type("_doc").id("2").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"@timestamp\": \"2019/04/03\"}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest("logstash").type("_doc").id("3").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"@timestamp\": \"2019/04/04\"}", XContentType.JSON)).actionGet();
    }

    
    @Test
    public void testDlsDateMathQuery() throws Exception {
        final Settings settings = Settings.builder()/*.put(ConfigConstants.SEARCHGUARD_UNSUPPORTED_ALLOW_NOW_IN_DLS,true)*/.build();
        setup(settings);

        HttpResponse res;

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/logstash/_search?pretty", encodeBasicHeader("date_math", "password"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("\"total\" : 1,\n    \"max_score"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
        
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/logstash/_search?pretty", encodeBasicHeader("admin", "admin"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("\"total\" : 3,\n    \"max_score"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
    }
    
    @Test
    public void testDlsDateMathQueryNotAllowed() throws Exception {
        setup();

        HttpResponse res;

        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, (res = rh.executeGetRequest("/logstash/_search?pretty", encodeBasicHeader("date_math", "password"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("'now' is not allowed in DLS queries"));
        Assert.assertTrue(res.getBody().contains("error"));
        
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/logstash/_search?pretty", encodeBasicHeader("admin", "admin"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("\"total\" : 3,\n    \"max_score"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
    }
}