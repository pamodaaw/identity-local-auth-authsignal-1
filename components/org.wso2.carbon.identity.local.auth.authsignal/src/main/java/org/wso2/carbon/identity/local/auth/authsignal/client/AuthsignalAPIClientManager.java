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

package org.wso2.carbon.identity.local.auth.authsignal.client;

import org.wso2.carbon.identity.external.api.client.api.exception.APIClientConfigException;
import org.wso2.carbon.identity.external.api.client.api.model.APIClientConfig;
import org.wso2.carbon.identity.external.api.client.api.service.AbstractAPIClientManager;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.Defaults;

/**
 * Shared external API client used for all Authsignal Server API calls.
 * The underlying HTTP client holds a connection pool, so one instance is reused across tenants and requests
 * for the lifetime of the server.
 */
public class AuthsignalAPIClientManager extends AbstractAPIClientManager {

    private static volatile AuthsignalAPIClientManager instance;

    private AuthsignalAPIClientManager(APIClientConfig apiClientConfig) {

        super(apiClientConfig);
    }

    /**
     * Get the shared client, creating it on first use. Pool size, max connections per route and the retry count
     * come from the ExternalAPIClient settings of the server.
     *
     * @return Shared Authsignal API client manager.
     * @throws APIClientConfigException If the client configuration is not valid.
     */
    public static AuthsignalAPIClientManager getInstance() throws APIClientConfigException {

        if (instance == null) {
            synchronized (AuthsignalAPIClientManager.class) {
                if (instance == null) {
                    APIClientConfig apiClientConfig = new APIClientConfig.Builder()
                            .httpConnectionTimeoutInMillis(Defaults.REQUEST_TIMEOUT_MILLIS)
                            .httpConnectionRequestTimeoutInMillis(Defaults.REQUEST_TIMEOUT_MILLIS)
                            .httpReadTimeoutInMillis(Defaults.REQUEST_TIMEOUT_MILLIS)
                            .build();
                    instance = new AuthsignalAPIClientManager(apiClientConfig);
                }
            }
        }
        return instance;
    }
}
