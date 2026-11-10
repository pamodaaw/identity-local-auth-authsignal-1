/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.local.auth.authsignal.connector;

import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.ConnectorConfig;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.Defaults;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * Governance connector that holds the Authsignal configuration of each tenant.
 */
public class AuthsignalConnectorConfig implements IdentityConnectorConfig {

    public static final String[] PROPERTY_NAMES = {ConnectorConfig.SECRET_KEY, ConnectorConfig.REGION,
            ConnectorConfig.ACTION_CODE, ConnectorConfig.PASSKEY_ENROLLED_CLAIM};

    @Override
    public String getName() {

        return ConnectorConfig.NAME;
    }

    @Override
    public String getFriendlyName() {

        return ConnectorConfig.FRIENDLY_NAME;
    }

    @Override
    public String getCategory() {

        return ConnectorConfig.CATEGORY;
    }

    @Override
    public String getSubCategory() {

        return ConnectorConfig.SUB_CATEGORY;
    }

    @Override
    public int getOrder() {

        return ConnectorConfig.ORDER;
    }

    @Override
    public Map<String, String> getPropertyNameMapping() {

        Map<String, String> nameMapping = new HashMap<>();
        nameMapping.put(ConnectorConfig.SECRET_KEY, "Secret key");
        nameMapping.put(ConnectorConfig.REGION, "Region");
        nameMapping.put(ConnectorConfig.ACTION_CODE, "Action code");
        nameMapping.put(ConnectorConfig.PASSKEY_ENROLLED_CLAIM, "Passkey enrolled claim");
        return nameMapping;
    }

    @Override
    public Map<String, String> getPropertyDescriptionMapping() {

        Map<String, String> descriptionMapping = new HashMap<>();
        descriptionMapping.put(ConnectorConfig.SECRET_KEY,
                "Server API secret key of the Authsignal tenant");
        descriptionMapping.put(ConnectorConfig.REGION,
                "Region of the Authsignal tenant: us, eu, au, ca or uk");
        descriptionMapping.put(ConnectorConfig.ACTION_CODE,
                "Default action code of the Authsignal flow. A flow node or the adaptive authentication script "
                        + "can override it");
        descriptionMapping.put(ConnectorConfig.PASSKEY_ENROLLED_CLAIM,
                "URI of the local claim set to true or false based on whether the user has a passkey on Authsignal."
                        + " Leave empty to not update any claim");
        return descriptionMapping;
    }

    @Override
    public String[] getPropertyNames() {

        return PROPERTY_NAMES.clone();
    }

    @Override
    public Properties getDefaultPropertyValues(String tenantDomain) throws IdentityGovernanceException {

        Properties properties = new Properties();
        properties.put(ConnectorConfig.SECRET_KEY, "");
        properties.put(ConnectorConfig.REGION, Defaults.REGION);
        properties.put(ConnectorConfig.ACTION_CODE, Defaults.ACTION_CODE);
        properties.put(ConnectorConfig.PASSKEY_ENROLLED_CLAIM, "");
        return properties;
    }

    @Override
    public Map<String, String> getDefaultPropertyValues(String[] propertyNames, String tenantDomain)
            throws IdentityGovernanceException {

        return null;
    }

    @Override
    public List<String> getConfidentialPropertyValues(String tenantDomain) {

        return Collections.singletonList(ConnectorConfig.SECRET_KEY);
    }
}
