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

package com.floragunn.searchguard.dlic.rest.validation;

import java.util.Map;
import java.util.regex.Pattern;

import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.compress.NotXContentException;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.rest.RestRequest.Method;

import com.floragunn.searchguard.support.ConfigConstants;

public class InternalUsersValidator extends AbstractConfigurationValidator {

	public InternalUsersValidator(final Method method, BytesReference ref, final Settings esSettings) {
		super(method, ref, esSettings);
		this.payloadMandatory = true;
		allowedKeys.put("hash", DataType.STRING);
		allowedKeys.put("password", DataType.STRING);
		allowedKeys.put("roles", DataType.ARRAY);
		allowedKeys.put("attributes", DataType.OBJECT);
	}

	@Override
	public boolean validateSettings() {
		if(!super.validateSettings()) {
			return false;
		}
		
		try {
			final String regex = this.esSettings.get(ConfigConstants.SEARCHGUARD_RESTAPI_PASSWORD_VALIDATION_REGEX, null);
			final Map<String, Object> contentAsMap = XContentHelper.convertToMap(this.content, false, XContentType.JSON).v2();
			if(regex != null && contentAsMap.containsKey("password")) {
				final String password = (String) contentAsMap.get("password");

				if(!regex.isEmpty() && !Pattern.compile("^"+regex+"$").matcher(password).matches()) {
					this.errorType = ErrorType.INVALID_PASSWORD;
					return false;
				}
			}
		} catch (NotXContentException e) {
			return true;
		}

		return true;
	}
}
