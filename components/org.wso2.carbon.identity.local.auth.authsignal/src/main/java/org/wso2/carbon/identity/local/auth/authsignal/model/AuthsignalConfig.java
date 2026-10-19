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
import org.wso2.carbon.identity.local.auth.authsignal.connector.AuthsignalConnectorConfig;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.Defaults;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.Region;

import java.util.Collections;
import java.util.Locale;
import java.util.Map;

/**
 * Authsignal configuration of a tenant, built from the tenant's governance connector properties. There is no
 * server-wide (deployment.toml) configuration.
 */
public class AuthsignalConfig {

    private final String secretKey;
    private final String region;
    private final String userIdentifier;
    private final String signInFlowRef;
    private final String registrationFlowRef;
    private final String recoveryFlowRef;
    private final boolean syncContactDetails;
    private final boolean deleteUsers;
    private final String passkeyEnrolledClaim;

    /**
     * @param tenantProperties Governance connector properties of the tenant, keyed by
     *                         {@link AuthsignalConnectorConfig} property names.
     */
    public AuthsignalConfig(Map<String, String> tenantProperties) {

        Map<String, String> tenant = tenantProperties != null ? tenantProperties : Collections.emptyMap();

        this.secretKey = StringUtils.trimToNull(tenant.get(AuthsignalConnectorConfig.SECRET_KEY));
        this.region = getString(tenant, AuthsignalConnectorConfig.REGION, Defaults.REGION).toLowerCase(Locale.ROOT);
        this.userIdentifier = getString(tenant, AuthsignalConnectorConfig.USER_IDENTIFIER, Defaults.USER_IDENTIFIER);
        this.signInFlowRef = getString(tenant, AuthsignalConnectorConfig.SIGN_IN_FLOW_REF,
                Defaults.SIGN_IN_FLOW_REF);
        this.registrationFlowRef = getString(tenant, AuthsignalConnectorConfig.REGISTRATION_FLOW_REF,
                Defaults.REGISTRATION_FLOW_REF);
        this.recoveryFlowRef = getString(tenant, AuthsignalConnectorConfig.RECOVERY_FLOW_REF,
                Defaults.RECOVERY_FLOW_REF);
        this.syncContactDetails = getBoolean(tenant, AuthsignalConnectorConfig.SYNC_CONTACT_DETAILS,
                Defaults.SYNC_CONTACT_DETAILS);
        this.deleteUsers = getBoolean(tenant, AuthsignalConnectorConfig.DELETE_USERS, Defaults.DELETE_USERS);
        this.passkeyEnrolledClaim =
                StringUtils.trimToNull(tenant.get(AuthsignalConnectorConfig.PASSKEY_ENROLLED_CLAIM));
    }

    public String getSecretKey() {

        return secretKey;
    }

    public String getRegion() {

        return region;
    }

    /**
     * Resolve the Server API base URL from the tenant's region. Tenants cannot supply an arbitrary URL, so the server
     * only ever calls Authsignal's own hosts with the tenant's secret key and user data.
     *
     * @return The URL of the tenant's region, or {@code null} if the region is not supported.
     */
    public String getApiBaseUrl() {

        return Region.API_BASE_URLS.get(region);
    }

    public String getUserIdentifier() {

        return userIdentifier;
    }

    /**
     * @return Action code of the Authsignal flow used at sign-in.
     */
    public String getSignInFlowRef() {

        return signInFlowRef;
    }

    /**
     * @return Action code of the Authsignal flow used in registration flows.
     */
    public String getRegistrationFlowRef() {

        return registrationFlowRef;
    }

    /**
     * @return Action code of the Authsignal flow used in password recovery flows.
     */
    public String getRecoveryFlowRef() {

        return recoveryFlowRef;
    }

    /**
     * @return Whether the user's email address and mobile number are updated on Authsignal when they change and are
     * verified in WSO2.
     */
    public boolean isSyncContactDetails() {

        return syncContactDetails;
    }

    /**
     * @return Whether the user and their authenticators are deleted on Authsignal when the user is deleted in WSO2.
     */
    public boolean isDeleteUsers() {

        return deleteUsers;
    }

    /**
     * @return URI of the local claim set to whether the user has a passkey on Authsignal, or null if no claim is
     * updated.
     */
    public String getPasskeyEnrolledClaim() {

        return passkeyEnrolledClaim;
    }

    /**
     * @return Timeout for each Authsignal API call. Fixed rather than tenant configurable, so that a tenant cannot hold
     * server threads for long periods.
     */
    public int getRequestTimeoutMillis() {

        return Defaults.REQUEST_TIMEOUT_MILLIS;
    }

    private static String getString(Map<String, String> params, String key, String defaultValue) {

        String value = StringUtils.trimToNull(params.get(key));
        return value != null ? value : defaultValue;
    }

    private static boolean getBoolean(Map<String, String> params, String key, boolean defaultValue) {

        String value = StringUtils.trimToNull(params.get(key));
        return value != null ? Boolean.parseBoolean(value) : defaultValue;
    }
}
