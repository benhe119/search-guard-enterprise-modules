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

package com.floragunn.searchguard.dlic.rest.support;

import java.io.IOException;
import java.util.Map;

import org.elasticsearch.ElasticsearchParseException;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.common.xcontent.json.JsonXContent;

public class Utils {
    
    public static Map<String, Object> convertJsonToxToStructuredMap(ToXContent jsonContent) {
        Map<String, Object> map = null;
        try {
            final BytesReference bytes = XContentHelper.toXContent(jsonContent, XContentType.JSON, false);
            map = XContentHelper.convertToMap(bytes, false, XContentType.JSON).v2();
        } catch (IOException e1) {
            throw ExceptionsHelper.convertToElastic(e1);
        }
        
        return map;
    }
    
    public static Map<String, Object> convertJsonToxToStructuredMap(String jsonContent) {
        try (XContentParser parser = XContentType.JSON.xContent().createParser(NamedXContentRegistry.EMPTY, jsonContent)) {
            return parser.map();
        } catch (IOException e1) {
            throw ExceptionsHelper.convertToElastic(e1);
        }
    }
    
    public static BytesReference convertStructuredMapToBytes(Map<String, Object> structuredMap) {
        try {
            return JsonXContent.contentBuilder().map(structuredMap).bytes();
        } catch (IOException e) {
            throw new ElasticsearchParseException("Failed to convert map", e);
        }
    }
    
    public static String convertStructuredMapToJson(Map<String, Object> structuredMap) {
        try {
            return XContentHelper.convertToJson(convertStructuredMapToBytes(structuredMap), false, XContentType.JSON);
        } catch (IOException e) {
            throw new ElasticsearchParseException("Failed to convert map", e);
        }
    }
    
}
