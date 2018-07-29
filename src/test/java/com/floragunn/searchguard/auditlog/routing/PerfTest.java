package com.floragunn.searchguard.auditlog.routing;

import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import com.floragunn.searchguard.auditlog.AbstractAuditlogiUnitTest;
import com.floragunn.searchguard.auditlog.helper.LoggingSink;
import com.floragunn.searchguard.auditlog.helper.MockAuditMessageFactory;
import com.floragunn.searchguard.auditlog.impl.AuditMessage;
import com.floragunn.searchguard.auditlog.impl.AuditMessage.Category;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.test.helper.file.FileHelper;



public class PerfTest extends AbstractAuditlogiUnitTest {

	@Test
	@Ignore(value="jvm crash on cci")
	public void testPerf() throws Exception {
		Settings.Builder settingsBuilder = Settings.builder().loadFromPath(FileHelper.getAbsoluteFilePathFromClassPath("auditlog/endpoints/routing/perftest.yml"));

		Settings settings = settingsBuilder.put("path.home", ".")
				.put(ConfigConstants.SEARCHGUARD_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE")
				.put("searchguard.audit.threadpool.size", 0)
				.build();

		AuditMessageRouter router = createMessageRouterComplianceEnabled(settings);
		int limit = 150000;
		while(limit > 0) {
			AuditMessage msg = MockAuditMessageFactory.validAuditMessage(Category.MISSING_PRIVILEGES);
			router.route(msg);
			limit--;
		}
		LoggingSink loggingSink = (LoggingSink)router.defaultSink.getFallbackSink();
		int currentSize = loggingSink.messages.size();
		Assert.assertTrue(currentSize > 0);
	}

}
