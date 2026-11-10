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

package org.wso2.carbon.identity.local.auth.authsignal.model;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.ConnectorConfig;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.Defaults;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.Region;

import java.util.Collections;
import java.util.Locale;
import java.util.Map;

/**
 * Authsignal configuration of a tenant.
 */
public class AuthsignalConfig {

    private final String secretKey;
    private final String region;
    private final String actionCode;
    private final String passkeyEnrolledClaim;

    /**
     * @param tenantProperties Governance connector properties of the tenant, keyed by
     *                         {@link ConnectorConfig} property names.
     */
    public AuthsignalConfig(Map<String, String> tenantProperties) {

        Map<String, String> tenant = tenantProperties != null ? tenantProperties : Collections.emptyMap();

        this.secretKey = StringUtils.trimToNull(tenant.get(ConnectorConfig.SECRET_KEY));
        this.region = getString(tenant, ConnectorConfig.REGION, Defaults.REGION).toLowerCase(Locale.ROOT);
        this.actionCode = getString(tenant, ConnectorConfig.ACTION_CODE, Defaults.ACTION_CODE);
        this.passkeyEnrolledClaim =
                StringUtils.trimToNull(tenant.get(ConnectorConfig.PASSKEY_ENROLLED_CLAIM));
    }

    public String getSecretKey() {

        return secretKey;
    }

    public String getRegion() {

        return region;
    }

    /**
     * Get the Server API base URL of the tenant's region.
     *
     * @return The URL of the tenant's region, or {@code null} if the region is not supported.
     */
    public String getApiBaseUrl() {

        return Region.API_BASE_URLS.get(region);
    }

    /**
     * @return Default action code of the Authsignal flow.
     */
    public String getActionCode() {

        return actionCode;
    }

    /**
     * @return URI of the claim that records whether the user has a passkey, or null if not set.
     */
    public String getPasskeyEnrolledClaim() {

        return passkeyEnrolledClaim;
    }

    private static String getString(Map<String, String> params, String key, String defaultValue) {

        String value = StringUtils.trimToNull(params.get(key));
        return value != null ? value : defaultValue;
    }
}
