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

import java.util.List;

import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestRequest;

import com.floragunn.searchguard.configuration.MaskedField;
import com.floragunn.searchguard.dlic.rest.validation.AbstractConfigurationValidator.DataType;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.ReadContext;

public class RolesValidator extends AbstractConfigurationValidator {

	public RolesValidator(final RestRequest request, final BytesReference ref, final Settings esSettings, Object... param) {
		super(request, ref, esSettings, param);
		this.payloadMandatory = true;
		allowedKeys.put("indices", DataType.OBJECT);
		allowedKeys.put("cluster", DataType.ARRAY);
		allowedKeys.put("tenants", DataType.OBJECT);
		allowedKeys.put("description", DataType.STRING);
		
		mandatoryOrKeys.add("indices");
		mandatoryOrKeys.add("cluster");
	}

    @Override
    public boolean validateSettings() {

        if (!super.validateSettings()) {
            return false;
        }
        
        boolean valid=true;

        if (this.content != null && this.content.length() > 0) {

            final ReadContext ctx = JsonPath.parse(this.content.utf8ToString());
            final List<String> maskedFields = ctx.read("$.._masked_fields_[*]");

            if (maskedFields != null) {
                
                for (String mf : maskedFields) {
                    if (!validateMaskedFieldSyntax(mf)) {
                        valid = false;
                    }
                }
            }
        }
        
        if(!valid) {
           this.errorType = ErrorType.WRONG_DATATYPE;
        }

        return valid;
    }

    private boolean validateMaskedFieldSyntax(String mf) {
        try {
            new MaskedField(mf, new byte[] {1,2,3,4,5,1,2,3,4,5,1,2,3,4,5,6}).isValid();
        } catch (Exception e) {
            wrongDatatypes.put("Masked field not valid: "+mf, e.getMessage());
            return false;
        }
        return true;
    }
}
