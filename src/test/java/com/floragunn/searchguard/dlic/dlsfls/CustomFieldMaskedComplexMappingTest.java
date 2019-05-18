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

import java.nio.charset.StandardCharsets;

import org.apache.http.HttpStatus;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.xcontent.XContentType;
import org.junit.Assert;
import org.junit.Test;

import com.floragunn.searchguard.crypto.CryptoManagerFactory;
import com.floragunn.searchguard.test.helper.file.FileHelper;
import com.floragunn.searchguard.test.helper.rest.RestHelper.HttpResponse;

public class CustomFieldMaskedComplexMappingTest extends AbstractDlsFlsTest{

    @Override
    protected void populateData(TransportClient tc) {



        try {
            tc.admin().indices().create(new CreateIndexRequest("logs").mapping("_doc", FileHelper.loadFile("dlsfls/masked_field_mapping.json"), XContentType.JSON)).actionGet();


            byte[] data = FileHelper.loadFile("dlsfls/logs_bulk_data.json").getBytes(StandardCharsets.UTF_8);
            BulkRequest br = new BulkRequest().add(data, 0, data.length, XContentType.JSON).setRefreshPolicy(RefreshPolicy.IMMEDIATE);
            if(tc.bulk(br).actionGet().hasFailures()) {
                Assert.fail("bulk import failed");
            }
            Thread.sleep(1000);

        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail(e.toString());
        }

    }

    @Test
    public void testComplexMappingAggregationsRace() throws Exception {

        setup();


        String query = "{"+
                "\"aggs\" : {"+
                "\"ips\" : { \"terms\" : { \"field\" : \"machine.os.keyword\", \"size\": 1002, \"show_term_doc_count_error\": true } }"+
                "}"+
                "}";



        HttpResponse res;
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePostRequest("/logs/_search?pretty&size=0", query, encodeBasicHeader("admin", "admin"))).getStatusCode());
        System.out.println(res.getBody());

        Assert.assertTrue(res.getBody().contains("win 8"));
        Assert.assertTrue(res.getBody().contains("win xp"));
        Assert.assertTrue(res.getBody().contains("ios"));
        Assert.assertTrue(res.getBody().contains("osx"));
        Assert.assertTrue(res.getBody().contains("win 7"));

        Assert.assertTrue(res.getBody().contains("\"doc_count\" : 11"));
        Assert.assertTrue(res.getBody().contains("\"doc_count\" : 9"));
        Assert.assertTrue(res.getBody().contains("\"doc_count\" : 7"));
        Assert.assertTrue(res.getBody().contains("\"doc_count\" : 6"));

        Assert.assertFalse(res.getBody().contains("047f2c11be727"));
        Assert.assertFalse(res.getBody().contains("4dce2825bb66e"));
        Assert.assertFalse(res.getBody().contains("f47ed84663640"));
        Assert.assertFalse(res.getBody().contains("88783587fef7"));
        Assert.assertFalse(res.getBody().contains("c1f04335d9f41"));

        for(int i=0;i<10;i++) {
            Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePostRequest("/logs/_search?pretty&size=0", query, encodeBasicHeader("user_masked_nowc1", "user_masked_nowc1"))).getStatusCode());
            System.out.println(res.getBody());
        }

        
        
        for(int i=0;i<10;i++) {
        
            Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePostRequest("/logs/_search?pretty&size=0", query, encodeBasicHeader("user_masked_nowc", "user_masked_nowc"))).getStatusCode());
            System.out.println(res.getBody());
    
            Assert.assertFalse(res.getBody().contains("\"aaa"));
            
            Assert.assertTrue(res.getBody().contains("047f2c11be727"));
            Assert.assertTrue(res.getBody().contains("4dce2825bb66e"));
            Assert.assertTrue(res.getBody().contains("f47ed84663640"));
            Assert.assertTrue(res.getBody().contains("88783587fef7"));
            Assert.assertTrue(res.getBody().contains("c1f04335d9f41"));
    
            Assert.assertTrue(res.getBody().contains("\"doc_count\" : 11"));
            Assert.assertTrue(res.getBody().contains("\"doc_count\" : 9"));
            Assert.assertTrue(res.getBody().contains("\"doc_count\" : 7"));
            Assert.assertTrue(res.getBody().contains("\"doc_count\" : 6"));
    
            Assert.assertFalse(res.getBody().contains("win 8"));
            Assert.assertFalse(res.getBody().contains("win xp"));
            Assert.assertFalse(res.getBody().contains("ios"));
            Assert.assertFalse(res.getBody().contains("osx"));
            Assert.assertFalse(res.getBody().contains("win 7"));
            
            
            
            Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePostRequest("/logs/_search?pretty&size=0", query, encodeBasicHeader("admin", "admin"))).getStatusCode());

        
        
        }
        
        




        for(int i=0;i<10;i++) {
            Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePostRequest("/logs/_search?pretty&size=0", query, encodeBasicHeader("admin", "admin"))).getStatusCode());
            Assert.assertTrue(res.getBody().contains("win 8"));
            Assert.assertTrue(res.getBody().contains("win xp"));
            Assert.assertTrue(res.getBody().contains("ios"));
            Assert.assertTrue(res.getBody().contains("osx"));
            Assert.assertTrue(res.getBody().contains("win 7"));

            Assert.assertTrue(res.getBody().contains("\"doc_count\" : 11"));
            Assert.assertTrue(res.getBody().contains("\"doc_count\" : 9"));
            Assert.assertTrue(res.getBody().contains("\"doc_count\" : 7"));
            Assert.assertTrue(res.getBody().contains("\"doc_count\" : 6"));

            Assert.assertFalse(res.getBody().contains("047f2c11be727"));
            Assert.assertFalse(res.getBody().contains("4dce2825bb66e"));
            Assert.assertFalse(res.getBody().contains("f47ed84663640"));
            Assert.assertFalse(res.getBody().contains("88783587fef7"));
            Assert.assertFalse(res.getBody().contains("c1f04335d9f41"));
        }

    }

    @Test
    public void testComplexMappingSearch() throws Exception {

        setup();

        HttpResponse res;

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/logs/_search?pretty&size=100", encodeBasicHeader("admin", "admin"))).getStatusCode());
        Assert.assertFalse(res.getBody().contains("88783587fef740690c4fa39476fb86314d034fa3370e1a1fa186f6d9d4644a18ad85063c1e3161f8929f7ca019bb8740611eaf337709113901e7c3a6b59f4166"));
        Assert.assertFalse(res.getBody().contains("e90a2fdf7b1939ec06e294321fd7d23e1a70d8fc080a3f85d0f3bf08c205b53"));
        Assert.assertFalse(res.getBody().contains("*.*.*.*"));
        Assert.assertFalse(res.getBody().contains("430a65d4b9c51de7192e048b2639db0de5c56f1901afccc2a01ef97f6a769a38"));
        Assert.assertFalse(res.getBody().contains("7f48bb3636edf546a75968ca7cd0bdfe63e9ce7af04ef7cb642931fa15d2d7a3"));
        Assert.assertFalse(res.getBody().contains("https://www.static.co/downloads/beats/metricbeat"));
        Assert.assertFalse(res.getBody().contains("eb551beb79792f3366b3623495bb0d9acf85055e63d4f48ade024289f9aa782fc7bd215b6ed3452d3d3ff3eccd8a7f5e8f55b8d0ef245c7ccbf8b747e0be9807"));
        Assert.assertFalse(res.getBody().contains("XXX.XXX.XXX.XXX"));
        Assert.assertFalse(res.getBody().contains("ANONYMIZED_BROWSER"));
        Assert.assertFalse(res.getBody().contains("69ce5643cf2abe2dec163330161e669"));
        Assert.assertFalse(res.getBody().contains("0b50856e97a54df444ff8f7c73c67fc3109aa234"));
        Assert.assertTrue(res.getBody().contains("win xp"));
        Assert.assertTrue(res.getBody().contains("\"timestamp\" : \"2018-07-22T20:45:16.163Z"));

        for(int i=0;i<10;i++) {
            
            if(CryptoManagerFactory.isFipsEnabled()) {
                //MD5 not alowed
                Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, (res = rh.executeGetRequest("/logs/_search?pretty&size=100", encodeBasicHeader("user_masked_nowc", "user_masked_nowc"))).getStatusCode());
            } else {
                Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/logs/_search?pretty&size=100", encodeBasicHeader("user_masked_nowc", "user_masked_nowc"))).getStatusCode());
                Assert.assertTrue(res.getBody().contains("88783587fef740690c4fa39476fb86314d034fa3370e1a1fa186f6d9d4644a18ad85063c1e3161f8929f7ca019bb8740611eaf337709113901e7c3a6b59f4166"));
                Assert.assertTrue(res.getBody().contains("e90a2fdf7b1939ec06e294321fd7d23e1a70d8fc080a3f85d0f3bf08c205b53"));
                Assert.assertTrue(res.getBody().contains("*.*.*.*"));
                Assert.assertTrue(res.getBody().contains("430a65d4b9c51de7192e048b2639db0de5c56f1901afccc2a01ef97f6a769a38"));
                Assert.assertTrue(res.getBody().contains("7f48bb3636edf546a75968ca7cd0bdfe63e9ce7af04ef7cb642931fa15d2d7a3"));
                Assert.assertTrue(res.getBody().contains("https://www.static.co/downloads/beats/metricbeat"));
                Assert.assertTrue(res.getBody().contains("eb551beb79792f3366b3623495bb0d9acf85055e63d4f48ade024289f9aa782fc7bd215b6ed3452d3d3ff3eccd8a7f5e8f55b8d0ef245c7ccbf8b747e0be9807"));
                Assert.assertTrue(res.getBody().contains("XXX.XXX.XXX.XXX"));
                Assert.assertTrue(res.getBody().contains("ANONYMIZED_BROWSER"));
                Assert.assertTrue(res.getBody().contains("69ce5643cf2abe2dec163330161e669"));
                Assert.assertTrue(res.getBody().contains("0b50856e97a54df444ff8f7c73c67fc3109aa234"));
                Assert.assertFalse(res.getBody().contains("win xp"));
                Assert.assertFalse(res.getBody().contains("\"timestamp\" : \"2018-07-22T20:45:16.163Z"));
            }
        }
        
        for(int i=0;i<10;i++) {
            Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/logs/_search?pretty&size=100", encodeBasicHeader("user_masked_nowc_fips", "user_masked_nowc"))).getStatusCode());
            Assert.assertTrue(res.getBody().contains("88783587fef740690c4fa39476fb86314d034fa3370e1a1fa186f6d9d4644a18ad85063c1e3161f8929f7ca019bb8740611eaf337709113901e7c3a6b59f4166"));
            Assert.assertTrue(res.getBody().contains("770653e72d7ee8ffe16f7a93ef7bf2e62f6ab2c990c8c5b2fc1334ee5307c3d72bb90830b3ddf79bf4d926dc60201dbb3556d3cdc5b616173d1a0b9217accd55"));
            Assert.assertTrue(res.getBody().contains("*.*.*.*"));
            Assert.assertTrue(res.getBody().contains("https://www.static.co/downloads/beats/metricbeat"));
            Assert.assertTrue(res.getBody().contains("eb551beb79792f3366b3623495bb0d9acf85055e63d4f48ade024289f9aa782fc7bd215b6ed3452d3d3ff3eccd8a7f5e8f55b8d0ef245c7ccbf8b747e0be9807"));
            Assert.assertTrue(res.getBody().contains("XXX.XXX.XXX.XXX"));
            Assert.assertTrue(res.getBody().contains("ANONYMIZED_BROWSER"));
            Assert.assertFalse(res.getBody().contains("win xp"));
            Assert.assertFalse(res.getBody().contains("nytimes"));
            Assert.assertFalse(res.getBody().contains("\"timestamp\" : \"2018-07-22T20:45:16.163Z"));
        }
        
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/logs/_search?pretty&size=100", encodeBasicHeader("admin", "admin"))).getStatusCode());
        Assert.assertFalse(res.getBody().contains("770653e72d7ee8ffe16f7a93ef7bf2e62f6ab2c990c8c5b2fc1334ee5307c3d72bb90830b3ddf79bf4d926dc60201dbb3556d3cdc5b616173d1a0b9217accd55"));
        Assert.assertFalse(res.getBody().contains("88783587fef740690c4fa39476fb86314d034fa3370e1a1fa186f6d9d4644a18ad85063c1e3161f8929f7ca019bb8740611eaf337709113901e7c3a6b59f4166"));
        Assert.assertFalse(res.getBody().contains("e90a2fdf7b1939ec06e294321fd7d23e1a70d8fc080a3f85d0f3bf08c205b53"));
        Assert.assertFalse(res.getBody().contains("*.*.*.*"));
        Assert.assertFalse(res.getBody().contains("430a65d4b9c51de7192e048b2639db0de5c56f1901afccc2a01ef97f6a769a38"));
        Assert.assertFalse(res.getBody().contains("7f48bb3636edf546a75968ca7cd0bdfe63e9ce7af04ef7cb642931fa15d2d7a3"));
        Assert.assertFalse(res.getBody().contains("https://www.static.co/downloads/beats/metricbeat"));
        Assert.assertFalse(res.getBody().contains("eb551beb79792f3366b3623495bb0d9acf85055e63d4f48ade024289f9aa782fc7bd215b6ed3452d3d3ff3eccd8a7f5e8f55b8d0ef245c7ccbf8b747e0be9807"));
        Assert.assertFalse(res.getBody().contains("XXX.XXX.XXX.XXX"));
        Assert.assertFalse(res.getBody().contains("ANONYMIZED_BROWSER"));
        Assert.assertFalse(res.getBody().contains("69ce5643cf2abe2dec163330161e669"));
        Assert.assertFalse(res.getBody().contains("0b50856e97a54df444ff8f7c73c67fc3109aa234"));
        Assert.assertTrue(res.getBody().contains("win xp"));
        Assert.assertTrue(res.getBody().contains("\"timestamp\" : \"2018-07-22T20:45:16.163Z"));
    }
}