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
import org.elasticsearch.common.xcontent.XContentType;
import org.junit.Assert;
import org.junit.Test;

import com.floragunn.searchguard.test.helper.file.FileHelper;
import com.floragunn.searchguard.test.helper.rest.RestHelper.HttpResponse;

public class DlsPropsReplaceTest extends AbstractDlsFlsTest{


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

        tc.index(new IndexRequest("prop1").type("_doc").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"prop_replace\": \"yes\", \"amount\": 1010}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest("prop1").type("_doc").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"prop_replace\": \"no\", \"amount\": 2020}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest("prop2").type("_doc").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"role\": \"prole1\", \"amount\": 3030}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest("prop2").type("_doc").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"role\": \"prole2\", \"amount\": 4040}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest("prop2").type("_doc").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"role\": \"prole3\", \"amount\": 5050}", XContentType.JSON)).actionGet();

    }


    @Test
    public void testDlsProps() throws Exception {

        setup();

        HttpResponse res;

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/prop1,prop2/_search?pretty&size=100", encodeBasicHeader("admin", "admin"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("\"total\" : 5,\n    \"max_"));

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/prop1,prop2/_search?pretty&size=100", encodeBasicHeader("prop_replace", "password"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("\"total\" : 3,\n    \"max_"));
    }
}