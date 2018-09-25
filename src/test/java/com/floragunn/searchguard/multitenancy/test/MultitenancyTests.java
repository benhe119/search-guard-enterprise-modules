/*
 * Copyright 2017 by floragunn GmbH - All rights reserved
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

package com.floragunn.searchguard.multitenancy.test;

import java.util.HashMap;
import java.util.Map;

import org.apache.http.HttpStatus;
import org.apache.http.message.BasicHeader;
import org.elasticsearch.action.admin.indices.alias.Alias;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentType;
import org.junit.Assert;
import org.junit.Test;

import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.support.WildcardMatcher;
import com.floragunn.searchguard.test.DynamicSgConfig;
import com.floragunn.searchguard.test.SingleClusterTest;
import com.floragunn.searchguard.test.helper.file.FileHelper;
import com.floragunn.searchguard.test.helper.rest.RestHelper;
import com.floragunn.searchguard.test.helper.rest.RestHelper.HttpResponse;

public class MultitenancyTests extends SingleClusterTest {

    @Override
    protected String getResourceFolder() {
        return "multitenancy";
    }
    
    @Test
    public void testMt() throws Exception {
        final Settings settings = Settings.builder()
                .build();
        setup(settings);
        final RestHelper rh = nonSslRestHelper();

        HttpResponse res;
        String body = "{\"buildNum\": 15460, \"defaultIndex\": \"humanresources\", \"tenant\": \"human_resources\"}";
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (res = rh.executePutRequest(".kibana/config/5.6.0?pretty",body, new BasicHeader("sgtenant", "blafasel"), encodeBasicHeader("hr_employee", "hr_employee"))).getStatusCode());
        
        body = "{\"buildNum\": 15460, \"defaultIndex\": \"humanresources\", \"tenant\": \"human_resources\"}";
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (res = rh.executePutRequest(".kibana/config/5.6.0?pretty",body, new BasicHeader("sgtenant", "business_intelligence"), encodeBasicHeader("hr_employee", "hr_employee"))).getStatusCode());

        body = "{\"buildNum\": 15460, \"defaultIndex\": \"humanresources\", \"tenant\": \"human_resources\"}";
        Assert.assertEquals(HttpStatus.SC_CREATED, (res = rh.executePutRequest(".kibana/config/5.6.0?pretty",body, new BasicHeader("sgtenant", "human_resources"), encodeBasicHeader("hr_employee", "hr_employee"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(WildcardMatcher.match("*.kibana_*_humanresources*", res.getBody()));
        
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest(".kibana/config/5.6.0?pretty",new BasicHeader("sgtenant", "human_resources"), encodeBasicHeader("hr_employee", "hr_employee"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(WildcardMatcher.match("*human_resources*", res.getBody()));
        
    }
    
    @Test
    public void testKibanaAlias() throws Exception {
        final Settings settings = Settings.builder()
                .build();
        setup(settings);
        
        try (TransportClient tc = getInternalTransportClient()) {
            String body = "{\"buildNum\": 15460, \"defaultIndex\": \"humanresources\", \"tenant\": \"human_resources\"}";
            Map indexSettings = new HashMap();
            indexSettings.put("number_of_shards", 1);
            indexSettings.put("number_of_replicas", 0);
            tc.admin().indices().create(new CreateIndexRequest(".kibana-6")
                .alias(new Alias(".kibana"))
                .settings(indexSettings))
                .actionGet();

            tc.index(new IndexRequest(".kibana-6").type("doc").id("6.2.2").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source(body, XContentType.JSON)).actionGet();
        }

        final RestHelper rh = nonSslRestHelper();

        HttpResponse res;        
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest(".kibana-6/doc/6.2.2?pretty", encodeBasicHeader("kibanaro", "kibanaro"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest(".kibana/doc/6.2.2?pretty", encodeBasicHeader("kibanaro", "kibanaro"))).getStatusCode());
        System.out.println(res.getBody());
        
    }
    
    @Test
    public void testITT1635() throws Exception {
        final Settings settings = Settings.builder()
                .put(ConfigConstants.SEARCHGUARD_ROLES_MAPPING_RESOLUTION, "BOTH")
                .build();
        setup(Settings.EMPTY, new DynamicSgConfig().setSgRoles("sg_roles_itt1635.yml"), settings);
        
        try (TransportClient tc = getInternalTransportClient(this.clusterInfo, Settings.EMPTY)) {
                        
            tc.index(new IndexRequest("esb-prod-1").type("doc").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("esb-prod-2").type("doc").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":2}", XContentType.JSON)).actionGet();            
            tc.index(new IndexRequest("esb-prod-3").type("doc").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":3}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("esb-prod-4").type("doc").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":4}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("esb-prod-5").type("doc").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":5}", XContentType.JSON)).actionGet();

            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("esb-prod-1","esb-prod-2","esb-prod-3","esb-prod-4","esb-prod-5").alias("esb-prod-all"))).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("esb-prod-1").alias("esb-alias-1"))).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("esb-prod-2").alias("esb-alias-2"))).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("esb-prod-3").alias("esb-alias-3"))).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("esb-prod-4").alias("esb-alias-4"))).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("esb-prod-5").alias("esb-alias-5"))).actionGet();

        }
        
        final RestHelper rh = nonSslRestHelper();

        System.out.println("###1");
        HttpResponse res = rh.executeGetRequest("/esb-prod-*/_search?pretty", encodeBasicHeader("itt1635", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());  
        System.out.println("###2");
        res = rh.executeGetRequest("/esb-alias-*/_search?pretty", encodeBasicHeader("itt1635", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        System.out.println("###3");
        res = rh.executeGetRequest("/esb-prod-all/_search?pretty", encodeBasicHeader("itt1635", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
    }


}
