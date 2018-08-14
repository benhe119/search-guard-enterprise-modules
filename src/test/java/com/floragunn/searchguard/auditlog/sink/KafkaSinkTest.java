/*
 * Copyright 2016-2018 by floragunn GmbH - All rights reserved
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

package com.floragunn.searchguard.auditlog.sink;

import java.util.Arrays;
import java.util.Properties;

import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.yaml.YamlXContent;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;
import org.springframework.kafka.test.rule.KafkaEmbedded;

import scala.util.Random;

import com.floragunn.searchguard.auditlog.AbstractAuditlogiUnitTest;
import com.floragunn.searchguard.auditlog.helper.MockAuditMessageFactory;
import com.floragunn.searchguard.auditlog.impl.AuditMessage.Category;
import com.floragunn.searchguard.test.helper.file.FileHelper;

public class KafkaSinkTest extends AbstractAuditlogiUnitTest {
	
	@ClassRule
	public static KafkaEmbedded embeddedKafka = new KafkaEmbedded(1, true, 1, "compliance");
	
	@Test
	public void testKafka() throws Exception {
	    String configYml = FileHelper.loadFile("auditlog/endpoints/sink/configuration_kafka.yml");
	    configYml = configYml.replace("_RPLC_BOOTSTRAP_SERVERS_",embeddedKafka.getBrokersAsString());
		Settings.Builder settingsBuilder = Settings.builder().loadFromSource(configYml, YamlXContent.yamlXContent.type());
		try(KafkaConsumer<Long, String> consumer = createConsumer()) {
		    consumer.subscribe(Arrays.asList("compliance"));
	        
	        Settings settings = settingsBuilder.put("path.home", ".").build();      
	        SinkProvider provider = new SinkProvider(settings, null, null, null);
	        AuditLogSink sink = provider.getDefaultSink();
	        Assert.assertEquals(KafkaSink.class, sink.getClass());
	        boolean success = sink.doStore(MockAuditMessageFactory.validAuditMessage(Category.MISSING_PRIVILEGES));
	        Assert.assertTrue(success);
	        Thread.sleep(1000);
	        sink.close();
	        ConsumerRecords<Long, String> records = consumer.poll(1000);
	        Assert.assertEquals(1, records.count());
		}
		
	}

	private KafkaConsumer<Long, String> createConsumer() {
		Properties props = new Properties();
		props.put("bootstrap.servers", embeddedKafka.getBrokersAsString());
		props.put("auto.offset.reset", "earliest");
		props.put("group.id", "mygroup"+System.currentTimeMillis()+"_"+new Random().nextDouble());
		props.put("key.deserializer", "org.apache.kafka.common.serialization.LongDeserializer");
		props.put("value.deserializer", "org.apache.kafka.common.serialization.StringDeserializer");
		return new KafkaConsumer<>(props);
	}
}
