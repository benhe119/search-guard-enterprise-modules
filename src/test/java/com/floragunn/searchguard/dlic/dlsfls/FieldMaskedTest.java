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

import com.floragunn.searchguard.crypto.CryptoManagerFactory;
import com.floragunn.searchguard.test.helper.rest.RestHelper.HttpResponse;

public class FieldMaskedTest extends AbstractDlsFlsTest{
    
    @Override
    protected void populateData(TransportClient tc) {


        
        tc.index(new IndexRequest("deals").type("deals").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"customer\": {\"name\":\"cust1\"}, \"ip_source\": \"100.100.1.1\",\"ip_dest\": \"123.123.1.1\",\"amount\": 10}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest("deals").type("deals").id("2").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"customer\": {\"name\":\"cust2\"}, \"ip_source\": \"100.100.2.2\",\"ip_dest\": \"123.123.2.2\",\"amount\": 20}", XContentType.JSON)).actionGet();

        
        for (int i=0; i<30;i++) {
            tc.index(new IndexRequest("deals").type("deals").id("a"+i).setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                    .source("{\"customer\": {\"name\":\"cust1\"}, \"ip_source\": \"200.100.1.1\",\"ip_dest\": \"123.123.1.1\",\"amount\": 10}", XContentType.JSON)).actionGet();
        }
        
     }
    
    @Test
    public void testMaskedAggregations() throws Exception {

        setup();


        String query = "{"+
            "\"query\" : {"+
                 "\"match_all\": {}"+
            "},"+
            "\"aggs\" : {"+
                "\"ips\" : { \"terms\" : { \"field\" : \"ip_source.keyword\" } }"+
            "}"+
        "}";

        HttpResponse res;
        //Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePostRequest("/deals/_search?pretty&size=0", query, encodeBasicHeader("admin", "admin"))).getStatusCode());
        //Assert.assertTrue(res.getBody().contains("100.100"));

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePostRequest("/deals/_search?pretty&size=0", query, encodeBasicHeader("user_masked", "user_masked"))).getStatusCode());
        Assert.assertFalse(res.getBody().contains("100.100"));

    }
    
    @Test
    public void testMaskedAggregationsRace() throws Exception {

        setup();


        String query = "{"+
            "\"aggs\" : {"+
                "\"ips\" : { \"terms\" : { \"field\" : \"ip_source.keyword\", \"size\": 1002, \"show_term_doc_count_error\": true } }"+
            "}"+
        "}";


        
            HttpResponse res;
            Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePostRequest("/deals/_search?pretty&size=0", query, encodeBasicHeader("admin", "admin"))).getStatusCode());
            Assert.assertTrue(res.getBody().contains("100.100"));
            Assert.assertTrue(res.getBody().contains("200.100"));
            Assert.assertTrue(res.getBody().contains("\"doc_count\" : 30"));
            Assert.assertTrue(res.getBody().contains("\"doc_count\" : 1"));
            Assert.assertFalse(res.getBody().contains("e1623afebfa505884e249a478640ec98094d19a72ac7a89dd0097e28955bb5ae"));
            Assert.assertFalse(res.getBody().contains("26a8671e57fefc13504f8c61ced67ac98338261ace1e5bf462038b2f2caae16e"));
            Assert.assertFalse(res.getBody().contains("87873bdb698e5f0f60e0b02b76dad1ec11b2787c628edbc95b7ff0e82274b140"));
            Assert.assertFalse(res.getBody().contains("53a3509dbc166721b3c09cf05c69c0d2e30c6ac165bc0d6e7cadbe8843a6dde5"));
            Assert.assertFalse(res.getBody().contains("506838dfb7c22bedd476383c5df965d8fccce9984be15398018be109a79ef974"));
            Assert.assertFalse(res.getBody().contains("b68b32cc3237d36ac16df479beea274971988022bdcc5ddb87a842aa2103b10f"));
    
            Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePostRequest("/deals/_search?pretty&size=0", query, encodeBasicHeader("user_masked", "user_masked"))).getStatusCode());
            Assert.assertTrue(res.getBody().contains("\"doc_count\" : 30"));
            Assert.assertTrue(res.getBody().contains("\"doc_count\" : 1"));
            Assert.assertFalse(res.getBody().contains("100.100"));
            Assert.assertFalse(res.getBody().contains("200.100"));           
            
            if(CryptoManagerFactory.isFipsEnabled()) {
                Assert.assertTrue(res.getBody().contains("53a3509dbc166721b3c09cf05c69c0d2e30c6ac165bc0d6e7cadbe8843a6dde5"));
                Assert.assertTrue(res.getBody().contains("506838dfb7c22bedd476383c5df965d8fccce9984be15398018be109a79ef974"));
                Assert.assertTrue(res.getBody().contains("b68b32cc3237d36ac16df479beea274971988022bdcc5ddb87a842aa2103b10f"));
            } else {
                Assert.assertTrue(res.getBody().contains("e1623afebfa505884e249a478640ec98094d19a72ac7a89dd0097e28955bb5ae"));
                Assert.assertTrue(res.getBody().contains("26a8671e57fefc13504f8c61ced67ac98338261ace1e5bf462038b2f2caae16e"));
                Assert.assertTrue(res.getBody().contains("87873bdb698e5f0f60e0b02b76dad1ec11b2787c628edbc95b7ff0e82274b140"));
            }
        
        for (int i = 0; i < 10; i++) {
            Assert.assertEquals(HttpStatus.SC_OK,
                    (res = rh.executePostRequest("/deals/_search?pretty&size=0", query, encodeBasicHeader("admin", "admin"))).getStatusCode());
            Assert.assertTrue(res.getBody().contains("100.100"));
            Assert.assertTrue(res.getBody().contains("200.100"));
            Assert.assertTrue(res.getBody().contains("\"doc_count\" : 30"));
            Assert.assertTrue(res.getBody().contains("\"doc_count\" : 1"));
            Assert.assertFalse(res.getBody().contains("e1623afebfa505884e249a478640ec98094d19a72ac7a89dd0097e28955bb5ae"));
            Assert.assertFalse(res.getBody().contains("26a8671e57fefc13504f8c61ced67ac98338261ace1e5bf462038b2f2caae16e"));
            Assert.assertFalse(res.getBody().contains("87873bdb698e5f0f60e0b02b76dad1ec11b2787c628edbc95b7ff0e82274b140"));
            Assert.assertFalse(res.getBody().contains("53a3509dbc166721b3c09cf05c69c0d2e30c6ac165bc0d6e7cadbe8843a6dde5"));
            Assert.assertFalse(res.getBody().contains("506838dfb7c22bedd476383c5df965d8fccce9984be15398018be109a79ef974"));
            Assert.assertFalse(res.getBody().contains("b68b32cc3237d36ac16df479beea274971988022bdcc5ddb87a842aa2103b10f"));
        }

    }
    
    @Test
    public void testMaskedSearch() throws Exception {
        
        setup();

        HttpResponse res;

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/deals/_search?pretty&size=100", encodeBasicHeader("admin", "admin"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("\"value\" : 32,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
        Assert.assertTrue(res.getBody().contains("cust1"));
        Assert.assertTrue(res.getBody().contains("cust2"));
        Assert.assertTrue(res.getBody().contains("100.100.1.1"));
        Assert.assertTrue(res.getBody().contains("100.100.2.2"));
        Assert.assertFalse(res.getBody().contains("87873bdb698e5f0f60e0b02b76dad1ec11b2787c628edbc95b7ff0e82274b140"));
        Assert.assertFalse(res.getBody().contains("53a3509dbc166721b3c09cf05c69c0d2e30c6ac165bc0d6e7cadbe8843a6dde5"));
        
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/deals/_search?pretty&size=100", encodeBasicHeader("user_masked", "user_masked"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("\"value\" : 32,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
        Assert.assertTrue(res.getBody().contains("cust1"));
        Assert.assertTrue(res.getBody().contains("cust2"));
        Assert.assertFalse(res.getBody().contains("100.100.1.1"));
        Assert.assertFalse(res.getBody().contains("100.100.2.2"));
        
        if(CryptoManagerFactory.isFipsEnabled()) {
          Assert.assertTrue(res.getBody().contains("53a3509dbc166721b3c09cf05c69c0d2e30c6ac165bc0d6e7cadbe8843a6dde5"));
          Assert.assertFalse(res.getBody().contains("87873bdb698e5f0f60e0b02b76dad1ec11b2787c628edbc95b7ff0e82274b140"));
        } else {
          Assert.assertTrue(res.getBody().contains("87873bdb698e5f0f60e0b02b76dad1ec11b2787c628edbc95b7ff0e82274b140"));
          Assert.assertFalse(res.getBody().contains("53a3509dbc166721b3c09cf05c69c0d2e30c6ac165bc0d6e7cadbe8843a6dde5"));

        }

    }
    
    @Test
    public void testMaskedGet() throws Exception {
        
        setup();

        HttpResponse res;

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/deals/deals/0?pretty", encodeBasicHeader("admin", "admin"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("\"found\" : true"));
        Assert.assertTrue(res.getBody().contains("cust1"));
        Assert.assertFalse(res.getBody().contains("cust2"));
        Assert.assertTrue(res.getBody().contains("100.100.1.1"));
        Assert.assertFalse(res.getBody().contains("100.100.2.2"));
        Assert.assertFalse(res.getBody().contains("87873bdb698e5f0f60e0b02b76dad1ec11b2787c628edbc95b7ff0e82274b140"));
        Assert.assertFalse(res.getBody().contains("b68b32cc3237d36ac16df479beea274971988022bdcc5ddb87a842aa2103b10f"));
        
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/deals/deals/0?pretty", encodeBasicHeader("user_masked", "user_masked"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("\"found\" : true"));
        Assert.assertTrue(res.getBody().contains("cust1"));
        Assert.assertFalse(res.getBody().contains("cust2"));
        Assert.assertFalse(res.getBody().contains("100.100.1.1"));
        Assert.assertFalse(res.getBody().contains("100.100.2.2"));
        if(CryptoManagerFactory.isFipsEnabled()) {
            Assert.assertTrue(res.getBody().contains("b68b32cc3237d36ac16df479beea274971988022bdcc5ddb87a842aa2103b10f"));
            Assert.assertFalse(res.getBody().contains("87873bdb698e5f0f60e0b02b76dad1ec11b2787c628edbc95b7ff0e82274b140"));
          } else {
            Assert.assertTrue(res.getBody().contains("87873bdb698e5f0f60e0b02b76dad1ec11b2787c628edbc95b7ff0e82274b140"));
            Assert.assertFalse(res.getBody().contains("b68b32cc3237d36ac16df479beea274971988022bdcc5ddb87a842aa2103b10f"));
          }
    }
    

}