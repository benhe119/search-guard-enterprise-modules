package com.floragunn.dlic.auth.dnfof;

import org.apache.http.HttpStatus;
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
import com.floragunn.searchguard.test.DynamicSgConfig;
import com.floragunn.searchguard.test.SingleClusterTest;
import com.floragunn.searchguard.test.helper.rest.RestHelper;
import com.floragunn.searchguard.test.helper.rest.RestHelper.HttpResponse;

public class DnfofTest extends SingleClusterTest {
    
    @Override
    protected String getResourceFolder() {
        return "dnfof";
    }

    @Test
    public void testDeleteByQueryDnfof() throws Exception {

        setup(Settings.EMPTY, new DynamicSgConfig().setSgConfig("sg_config_dnfof.yml"), Settings.EMPTY);

        try (TransportClient tc = getInternalTransportClient()) {                    
            for(int i=0; i<3; i++) {
                tc.index(new IndexRequest("vulcangov").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();        
            }
        }

        RestHelper rh = nonSslRestHelper();
        HttpResponse res;
        Assert.assertEquals(HttpStatus.SC_OK, (res=rh.executePostRequest("/vulcango*/_delete_by_query?refresh=true&wait_for_completion=true&pretty=true", "{\"query\" : {\"match_all\" : {}}}", encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("\"deleted\" : 3"));

    }
    
    @Test
    public void testDnfofMinRole3() throws Exception {

        final Settings settings = Settings.builder()
                .put(ConfigConstants.SEARCHGUARD_ROLES_MAPPING_RESOLUTION, "BACKENDROLES_ONLY")
                .build();

        setup(Settings.EMPTY, new DynamicSgConfig().setSgConfig("sg_config_dnfof.yml"), settings);
        final RestHelper rh = nonSslRestHelper();

        try (TransportClient tc = getInternalTransportClient()) {
            tc.index(new IndexRequest("findex_1").type("doc").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":\"findex1\"}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("findex_2").type("doc").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":\"findex2\"}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("findex_3").type("doc").id("2").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":\"findex3\"}", XContentType.JSON)).actionGet();
        }
        
        HttpResponse resc;
        Assert.assertEquals(HttpStatus.SC_OK, (resc=rh.executeGetRequest("_search?pretty", encodeBasicHeader("user_f", "user_f"))).getStatusCode());
        System.out.println(resc.getBody());
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("findex1"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("findex2"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("findex3"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("exception"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("permission"));
    }
    
    @Test
    public void testDnfofMinRole2() throws Exception {

        final Settings settings = Settings.builder()
                .put(ConfigConstants.SEARCHGUARD_ROLES_MAPPING_RESOLUTION, "BOTH")
                .build();

        setup(Settings.EMPTY, new DynamicSgConfig().setSgConfig("sg_config_dnfof.yml"), settings);
        final RestHelper rh = nonSslRestHelper();

        try (TransportClient tc = getInternalTransportClient()) {
            tc.index(new IndexRequest("findex_1").type("doc").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":\"findex1\"}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("findex_2").type("doc").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":\"findex2\"}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("findex_3").type("doc").id("2").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":\"findex3\"}", XContentType.JSON)).actionGet();
        }
        
        HttpResponse resc;
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("_search?pretty", encodeBasicHeader("user_f1", "user_f"))).getStatusCode());
        System.out.println(resc.getBody());
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("findex1"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("findex2"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("findex3"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("no permissions"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("security_exception"));
    }
    
    @Test
    public void testDnfofMinRole() throws Exception {

        final Settings settings = Settings.builder()
                .put(ConfigConstants.SEARCHGUARD_ROLES_MAPPING_RESOLUTION, "BOTH")
                .build();

        setup(Settings.EMPTY, new DynamicSgConfig().setSgConfig("sg_config_dnfof.yml"), settings);
        final RestHelper rh = nonSslRestHelper();

        try (TransportClient tc = getInternalTransportClient()) {
            tc.index(new IndexRequest("findex_1").type("doc").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":\"findex1\"}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("findex_2").type("doc").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":\"findex2\"}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("findex_3").type("doc").id("2").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":\"findex3\"}", XContentType.JSON)).actionGet();
        }
        
        HttpResponse resc;
        Assert.assertEquals(HttpStatus.SC_OK, (resc=rh.executeGetRequest("_search?pretty", encodeBasicHeader("user_f", "user_f"))).getStatusCode());
        System.out.println(resc.getBody());
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("findex1"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("findex2"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("findex3"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("exception"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("permission"));
    }
    
    @Test
    public void testDnfof() throws Exception {

        final Settings settings = Settings.builder()
                .put(ConfigConstants.SEARCHGUARD_ROLES_MAPPING_RESOLUTION, "BOTH")
                .build();

        setup(Settings.EMPTY, new DynamicSgConfig().setSgConfig("sg_config_dnfof.yml"), settings);
        final RestHelper rh = nonSslRestHelper();

        try (TransportClient tc = getInternalTransportClient()) {
            tc.admin().indices().create(new CreateIndexRequest("copysf")).actionGet();

            tc.index(new IndexRequest("indexa").type("doc").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":\"indexa\"}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("indexb").type("doc").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":\"indexb\"}", XContentType.JSON)).actionGet();


            tc.index(new IndexRequest("vulcangov").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("starfleet").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("starfleet_academy").type("students").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("starfleet_library").type("public").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("klingonempire").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("public").type("legends").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();

            tc.index(new IndexRequest("spock").type("type01").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("kirk").type("type01").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("role01_role02").type("type01").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();

            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("starfleet","starfleet_academy","starfleet_library").alias("sf"))).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("klingonempire","vulcangov").alias("nonsf"))).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("public").alias("unrestricted"))).actionGet();

        }

        HttpResponse resc;
        Assert.assertEquals(HttpStatus.SC_OK, (resc=rh.executeGetRequest("indexa,indexb/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("indexa"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("indexb"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("exception"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("permission"));

        Assert.assertEquals(HttpStatus.SC_OK, (resc=rh.executeGetRequest("indexa,indexb/_search?pretty", encodeBasicHeader("user_b", "user_b"))).getStatusCode());
        System.out.println(resc.getBody());
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("indexa"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("indexb"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("exception"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("permission"));

        String msearchBody =
                "{\"index\":\"indexa\", \"type\":\"doc\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator()+
                "{\"index\":\"indexb\", \"type\":\"doc\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator()+
                "{\"index\":\"index*\", \"type\":\"doc\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator();
        System.out.println("#### msearch");
        resc = rh.executePostRequest("_msearch?pretty", msearchBody, encodeBasicHeader("user_a", "user_a"));
        Assert.assertEquals(200, resc.getStatusCode());
        System.out.println(resc.getBody());
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("indexa"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("indexb"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("exception"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("permission"));
        Assert.assertEquals(3, resc.getBody().split("\"status\" : 200").length);
        Assert.assertEquals(2, resc.getBody().split("\"status\" : 403").length);

        resc = rh.executePostRequest("_msearch?pretty", msearchBody, encodeBasicHeader("user_b", "user_b"));
        Assert.assertEquals(200, resc.getStatusCode());
        System.out.println(resc.getBody());
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("indexa"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("indexb"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("exception"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("permission"));
        Assert.assertEquals(3, resc.getBody().split("\"status\" : 200").length);
        Assert.assertEquals(2, resc.getBody().split("\"status\" : 403").length);

        String mgetBody = "{"+
                "\"docs\" : ["+
                "{"+
                "\"_index\" : \"indexa\","+
                "\"_type\" : \"doc\","+
                "\"_id\" : \"0\""+
                " },"+
                " {"+
                "\"_index\" : \"indexb\","+
                " \"_type\" : \"doc\","+
                " \"_id\" : \"0\""+
                "}"+
                "]"+
                "}";

        System.out.println("#### mget");
        resc = rh.executePostRequest("_mget?pretty",  mgetBody, encodeBasicHeader("user_b", "user_b"));
        Assert.assertEquals(200, resc.getStatusCode());
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("\"content\" : \"indexa\""));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("\"content\" : \"indexb\""));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("exception"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("permission"));

        Assert.assertEquals(HttpStatus.SC_OK, (resc=rh.executeGetRequest("_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("indexa"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("indexb"));

        Assert.assertEquals(HttpStatus.SC_OK, (resc=rh.executeGetRequest("index*/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("indexa"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("indexb"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("exception"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("permission"));

        Assert.assertEquals(HttpStatus.SC_OK, (resc=rh.executeGetRequest("indexa/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());

        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("indexb/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());

        Assert.assertEquals(HttpStatus.SC_OK, (resc=rh.executeGetRequest("*/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());

        Assert.assertEquals(HttpStatus.SC_OK, (resc=rh.executeGetRequest("_all/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());

        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("notexists/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());

        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, (resc=rh.executeGetRequest("indexanbh,indexabb*/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());

        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("starfleet/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());

        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("starfleet/_search?pretty", encodeBasicHeader("worf", "worf"))).getStatusCode());
        System.out.println(resc.getBody());

        System.out.println("#### _all/_mapping/field/*");
        Assert.assertEquals(HttpStatus.SC_OK, (resc=rh.executeGetRequest("_all/_mapping/field/*", encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        System.out.println(resc.getBody());
    }
    
    @Test
    public void testNoDnfof() throws Exception {

        final Settings settings = Settings.builder()
                .put(ConfigConstants.SEARCHGUARD_ROLES_MAPPING_RESOLUTION, "BOTH")
                .build();

        setup(Settings.EMPTY, new DynamicSgConfig(), settings);
        final RestHelper rh = nonSslRestHelper();

        try (TransportClient tc = getInternalTransportClient()) {
            tc.admin().indices().create(new CreateIndexRequest("copysf")).actionGet();

            tc.index(new IndexRequest("indexa").type("doc").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":\"indexa\"}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("indexb").type("doc").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":\"indexb\"}", XContentType.JSON)).actionGet();


            tc.index(new IndexRequest("vulcangov").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("starfleet").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("starfleet_academy").type("students").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("starfleet_library").type("public").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("klingonempire").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("public").type("legends").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();

            tc.index(new IndexRequest("spock").type("type01").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("kirk").type("type01").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("role01_role02").type("type01").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();

            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("starfleet","starfleet_academy","starfleet_library").alias("sf"))).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("klingonempire","vulcangov").alias("nonsf"))).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("public").alias("unrestricted"))).actionGet();

        }

        HttpResponse resc;
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("indexa,indexb/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());

        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("indexa,indexb/_search?pretty", encodeBasicHeader("user_b", "user_b"))).getStatusCode());
        System.out.println(resc.getBody());

        String msearchBody =
                "{\"index\":\"indexa\", \"type\":\"doc\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator()+
                "{\"index\":\"indexb\", \"type\":\"doc\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator();
        System.out.println("#### msearch a");
        resc = rh.executePostRequest("_msearch?pretty", msearchBody, encodeBasicHeader("user_a", "user_a"));
        Assert.assertEquals(200, resc.getStatusCode());
        System.out.println(resc.getBody());
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("indexa"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("indexb"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("exception"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("permission"));

        System.out.println("#### msearch b");
        resc = rh.executePostRequest("_msearch?pretty", msearchBody, encodeBasicHeader("user_b", "user_b"));
        Assert.assertEquals(200, resc.getStatusCode());
        System.out.println(resc.getBody());
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("indexa"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("indexb"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("exception"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("permission"));

        msearchBody =
                "{\"index\":\"indexc\", \"type\":\"doc\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator()+
                "{\"index\":\"indexd\", \"type\":\"doc\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator();

        System.out.println("#### msearch b2");
        resc = rh.executePostRequest("_msearch?pretty", msearchBody, encodeBasicHeader("user_b", "user_b"));
        System.out.println(resc.getBody());
        Assert.assertEquals(200, resc.getStatusCode());
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("indexc"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("indexd"));

        String mgetBody = "{"+
                "\"docs\" : ["+
                "{"+
                "\"_index\" : \"indexa\","+
                "\"_type\" : \"doc\","+
                "\"_id\" : \"0\""+
                " },"+
                " {"+
                "\"_index\" : \"indexb\","+
                " \"_type\" : \"doc\","+
                " \"_id\" : \"0\""+
                "}"+
                "]"+
                "}";

        resc = rh.executePostRequest("_mget?pretty",  mgetBody, encodeBasicHeader("user_b", "user_b"));
        Assert.assertEquals(200, resc.getStatusCode());
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("\"content\" : \"indexa\""));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("indexb"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("exception"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("permission"));

        mgetBody = "{"+
                "\"docs\" : ["+
                "{"+
                "\"_index\" : \"indexx\","+
                "\"_type\" : \"doc\","+
                "\"_id\" : \"0\""+
                " },"+
                " {"+
                "\"_index\" : \"indexy\","+
                " \"_type\" : \"doc\","+
                " \"_id\" : \"0\""+
                "}"+
                "]"+
                "}";

        resc = rh.executePostRequest("_mget?pretty",  mgetBody, encodeBasicHeader("user_b", "user_b"));
        Assert.assertEquals(200, resc.getStatusCode());
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("exception"));
        int count = resc.getBody().split("root_cause").length;
        Assert.assertEquals(3, count);

        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());

        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("index*/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());


        Assert.assertEquals(HttpStatus.SC_OK, (resc=rh.executeGetRequest("indexa/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());

        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("indexb/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());

        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("*/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());

        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("_all/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());

        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("notexists/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());

        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, (resc=rh.executeGetRequest("indexanbh,indexabb*/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());

        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("starfleet/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());

        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("starfleet/_search?pretty", encodeBasicHeader("worf", "worf"))).getStatusCode());
        System.out.println(resc.getBody());

        System.out.println("#### _all/_mapping/field/*");
        Assert.assertEquals(HttpStatus.SC_OK, (resc=rh.executeGetRequest("_all/_mapping/field/*", encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        System.out.println(resc.getBody());
        System.out.println("#### _mapping/field/*");
        Assert.assertEquals(HttpStatus.SC_OK, (resc=rh.executeGetRequest("_mapping/field/*", encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        System.out.println(resc.getBody());
        System.out.println("#### */_mapping/field/*");
        Assert.assertEquals(HttpStatus.SC_OK, (resc=rh.executeGetRequest("*/_mapping/field/*", encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        System.out.println(resc.getBody());
    }

    
}
