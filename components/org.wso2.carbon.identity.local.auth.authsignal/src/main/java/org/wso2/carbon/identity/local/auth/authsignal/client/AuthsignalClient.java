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

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHeaders;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.wso2.carbon.identity.external.api.client.api.exception.APIClientException;
import org.wso2.carbon.identity.external.api.client.api.model.APIAuthentication;
import org.wso2.carbon.identity.external.api.client.api.model.APIInvocationConfig;
import org.wso2.carbon.identity.external.api.client.api.model.APIRequestContext;
import org.wso2.carbon.identity.external.api.client.api.model.APIResponse;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.ErrorMessages;
import org.wso2.carbon.identity.local.auth.authsignal.exception.AuthsignalConnectionException;
import org.wso2.carbon.identity.local.auth.authsignal.model.AuthsignalConfig;
import org.wso2.carbon.identity.local.auth.authsignal.model.AuthsignalRequest;
import org.wso2.carbon.identity.local.auth.authsignal.model.AuthsignalResponse;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Minimal client for the Authsignal Server API, built on the external API client of the identity framework,
 * which retries calls that fail without a response.
 * See https://docs.authsignal.com/api-reference/server-api/overview
 */
public class AuthsignalClient {

    private static final Log LOG = LogFactory.getLog(AuthsignalClient.class);
    private static final Gson GSON = new Gson();

    // Server API endpoints, relative to the region's base URL.
    private static final String START_FLOW_ENDPOINT = "/flows";
    private static final String VERIFY_FLOW_ENDPOINT = "/flows/verify";
    private static final String IDENTIFY_USER_ENDPOINT = "/identify";

    // Request body property names defined by the Server API.
    private static final String ACTION_CODE = "actionCode";
    private static final String CHALLENGE_TOKEN = "challengeToken";
    private static final String USER_ID = "userId";
    private static final String CHALLENGE_ID = "challengeId";

    private final String baseUrl;
    private final String authorizationHeader;

    /**
     * Create a client for the Authsignal tenant of a configuration.
     *
     * @param config Tenant configuration.
     * @throws AuthsignalConnectionException If the secret key or region is not valid.
     */
    public AuthsignalClient(AuthsignalConfig config) throws AuthsignalConnectionException {

        this(getApiBaseUrl(config), config.getSecretKey());
    }

    /**
     * Create a client for a Server API base URL.
     *
     * @param baseUrl   Server API base URL, such as https://api.authsignal.com/v1.
     * @param secretKey Secret key of the Authsignal tenant.
     */
    public AuthsignalClient(String baseUrl, String secretKey) {

        this.baseUrl = StringUtils.removeEnd(baseUrl.trim(), "/");
        this.authorizationHeader = "Basic " + Base64.getEncoder()
                .encodeToString((secretKey + ":").getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Start a flow.
     *
     * @param request Start flow request.
     * @return Start flow response with the challenge URL and challenge ID.
     * @throws AuthsignalConnectionException If the API call fails.
     */
    public AuthsignalResponse startFlow(AuthsignalRequest request) throws AuthsignalConnectionException {

        return sendPostRequest(START_FLOW_ENDPOINT, GSON.toJson(request), AuthsignalResponse.class);
    }

    /**
     * Verify the result of a flow.
     *
     * @param actionCode     Action code the flow was started with.
     * @param challengeToken Token Authsignal added to the redirect URL.
     * @return Verify flow response.
     * @throws AuthsignalConnectionException If the API call fails.
     */
    public AuthsignalResponse verifyFlow(String actionCode, String challengeToken)
            throws AuthsignalConnectionException {

        JsonObject body = new JsonObject();
        body.addProperty(ACTION_CODE, actionCode);
        body.addProperty(CHALLENGE_TOKEN, challengeToken);
        return sendPostRequest(VERIFY_FLOW_ENDPOINT, body.toString(), AuthsignalResponse.class);
    }

    /**
     * Link a flow that was started without a user ID to the user.
     *
     * @param userId      Authsignal user ID of the user.
     * @param challengeId Challenge ID returned when the flow started.
     * @return Response holding the user's verified authenticators.
     * @throws AuthsignalConnectionException If the API call fails.
     */
    public AuthsignalResponse identifyUser(String userId, String challengeId) throws AuthsignalConnectionException {

        JsonObject body = new JsonObject();
        body.addProperty(USER_ID, userId);
        body.addProperty(CHALLENGE_ID, challengeId);
        return sendPostRequest(IDENTIFY_USER_ENDPOINT, body.toString(), AuthsignalResponse.class);
    }

    /**
     * Get the Server API base URL of a configuration, checking that the secret key is set and the region is
     * supported.
     */
    private static String getApiBaseUrl(AuthsignalConfig config) throws AuthsignalConnectionException {

        if (StringUtils.isBlank(config.getSecretKey())) {
            throw new AuthsignalConnectionException(ErrorMessages.ERROR_CODE_SECRET_KEY_NOT_CONFIGURED,
                    ErrorMessages.ERROR_CODE_SECRET_KEY_NOT_CONFIGURED.getMessage());
        }
        String apiBaseUrl = config.getApiBaseUrl();
        if (apiBaseUrl == null) {
            throw new AuthsignalConnectionException(ErrorMessages.ERROR_CODE_INVALID_REGION,
                    String.format(ErrorMessages.ERROR_CODE_INVALID_REGION.getMessage(), config.getRegion()));
        }
        return apiBaseUrl;
    }

    private <T> T sendPostRequest(String path, String jsonBody, Class<T> responseType)
            throws AuthsignalConnectionException {

        APIResponse httpResponse;
        try {
            httpResponse = AuthsignalAPIClientManager.getInstance()
                    .callAPI(buildRequest(path, jsonBody), new APIInvocationConfig());
        } catch (APIClientException e) {
            throw new AuthsignalConnectionException("Error while calling the Authsignal API. " + e.getDescription(), e);
        } catch (IllegalArgumentException e) {
            throw new AuthsignalConnectionException("Invalid Authsignal API URL: " + baseUrl, e);
        }

        int status = httpResponse.getStatusCode();
        if (status < 200 || status >= 300) {
            // The response body is not logged, as it may contain personal data.
            if (LOG.isDebugEnabled()) {
                LOG.debug("Authsignal API " + path + " returned HTTP " + status + ".");
            }
            throw new AuthsignalConnectionException("Authsignal API returned HTTP " + status + ".", status);
        }
        try {
            T result = GSON.fromJson(httpResponse.getResponseBody(), responseType);
            if (result == null) {
                throw new AuthsignalConnectionException("Empty response received from the Authsignal API.", status);
            }
            return result;
        } catch (JsonParseException e) {
            throw new AuthsignalConnectionException("Invalid response received from the Authsignal API.", e);
        }
    }

    private APIRequestContext buildRequest(String path, String jsonBody) throws APIClientException {

        Map<String, String> headers = new HashMap<>();
        // The secret key goes in a header of its own, as framework basic auth rejects an empty password.
        headers.put(HttpHeaders.AUTHORIZATION, authorizationHeader);
        headers.put(HttpHeaders.ACCEPT, ContentType.APPLICATION_JSON.getMimeType());
        return new APIRequestContext.Builder()
                .httpMethod(APIRequestContext.HttpMethod.POST)
                .apiAuthentication(new APIAuthentication.Builder()
                        .authType(APIAuthentication.AuthType.NONE)
                        .build())
                .endpointUrl(baseUrl + path)
                .headers(headers)
                .payload(new StringEntity(jsonBody, ContentType.APPLICATION_JSON))
                .build();
    }
}
