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
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.ErrorMessages;
import org.wso2.carbon.identity.local.auth.authsignal.exception.AuthsignalClientException;
import org.wso2.carbon.identity.local.auth.authsignal.model.AuthsignalConfig;
import org.wso2.carbon.identity.local.auth.authsignal.model.FlowResponse;
import org.wso2.carbon.identity.local.auth.authsignal.model.StartFlowRequest;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;

/**
 * Minimal client for the Authsignal Server API.
 * See https://docs.authsignal.com/api-reference/server-api/overview
 */
public class AuthsignalClient {

    private static final Log LOG = LogFactory.getLog(AuthsignalClient.class);
    private static final Gson GSON = new Gson();
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
    // Shared across instances; java.net.http.HttpClient is thread safe and pools connections.
    private static final HttpClient DEFAULT_HTTP_CLIENT = HttpClient.newBuilder()
            .connectTimeout(CONNECT_TIMEOUT)
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    private final HttpClient httpClient;
    private final String baseUrl;
    private final String authorizationHeader;
    private final Duration requestTimeout;

    public AuthsignalClient(String baseUrl, String secretKey, int requestTimeoutMillis) {

        this(DEFAULT_HTTP_CLIENT, baseUrl, secretKey, requestTimeoutMillis);
    }

    AuthsignalClient(HttpClient httpClient, String baseUrl, String secretKey, int requestTimeoutMillis) {

        this.httpClient = httpClient;
        this.baseUrl = StringUtils.removeEnd(baseUrl.trim(), "/");
        // Authsignal uses HTTP basic auth with the secret key as the username and an empty password.
        this.authorizationHeader = "Basic " + Base64.getEncoder()
                .encodeToString((secretKey + ":").getBytes(StandardCharsets.UTF_8));
        this.requestTimeout = Duration.ofMillis(requestTimeoutMillis);
    }

    /**
     * Create a client for the Authsignal tenant of a configuration.
     *
     * @param config Tenant configuration.
     * @return Client calling the Server API of the tenant's region.
     * @throws AuthsignalClientException If the secret key is not configured or the region is not supported, with the
     *                                   matching error code.
     */
    public static AuthsignalClient forConfig(AuthsignalConfig config) throws AuthsignalClientException {

        if (StringUtils.isBlank(config.getSecretKey())) {
            throw new AuthsignalClientException(ErrorMessages.ERROR_CODE_SECRET_KEY_NOT_CONFIGURED,
                    ErrorMessages.ERROR_CODE_SECRET_KEY_NOT_CONFIGURED.getMessage());
        }
        String apiBaseUrl = config.getApiBaseUrl();
        if (apiBaseUrl == null) {
            throw new AuthsignalClientException(ErrorMessages.ERROR_CODE_INVALID_REGION,
                    String.format(ErrorMessages.ERROR_CODE_INVALID_REGION.getMessage(), config.getRegion()));
        }
        return new AuthsignalClient(apiBaseUrl, config.getSecretKey(), config.getRequestTimeoutMillis());
    }

    /**
     * Start a flow. The user completes it in the pre-built UI at the returned challenge URL.
     *
     * @param request Start flow request.
     * @return Start flow response with the challenge URL and challenge ID.
     * @throws AuthsignalClientException If the API call fails.
     */
    public FlowResponse startFlow(StartFlowRequest request) throws AuthsignalClientException {

        return post("/flows", GSON.toJson(request), FlowResponse.class);
    }

    /**
     * Verify the result of a flow using the token Authsignal appended to the redirect URL.
     *
     * @param actionCode     Action code the flow was started with. Authsignal rejects a mismatch.
     * @param challengeToken Token received on the redirect, not the one returned when the flow started.
     * @return Verify flow response.
     * @throws AuthsignalClientException If the API call fails.
     */
    public FlowResponse verifyFlow(String actionCode, String challengeToken) throws AuthsignalClientException {

        JsonObject body = new JsonObject();
        body.addProperty("actionCode", actionCode);
        body.addProperty("challengeToken", challengeToken);
        return post("/flows/verify", body.toString(), FlowResponse.class);
    }

    /**
     * Link a completed flow that was started without a user ID to the user. Everything enrolled in the flow moves to
     * the given user ID.
     *
     * @param userId      Authsignal user ID of the user.
     * @param challengeId Challenge ID returned when the flow started.
     * @return Response holding the user's verified authenticators.
     * @throws AuthsignalClientException If the API call fails.
     */
    public FlowResponse identifyUser(String userId, String challengeId) throws AuthsignalClientException {

        JsonObject body = new JsonObject();
        body.addProperty("userId", userId);
        body.addProperty("challengeId", challengeId);
        return post("/identify", body.toString(), FlowResponse.class);
    }

    /**
     * Update the email address and / or phone number of a user as already verified. Authsignal moves the user's email
     * OTP / magic link and SMS authenticators to the new values only when they are marked as verified.
     *
     * @param userId      Authsignal user ID.
     * @param email       The verified email address, or null to leave it unchanged.
     * @param phoneNumber The verified phone number in E.164 format, or null to leave it unchanged.
     * @throws AuthsignalClientException If the API call fails.
     */
    public void updateVerifiedContactDetails(String userId, String email, String phoneNumber)
            throws AuthsignalClientException {

        JsonObject body = new JsonObject();
        if (email != null) {
            body.addProperty("email", email);
            body.addProperty("emailVerified", true);
        }
        if (phoneNumber != null) {
            body.addProperty("phoneNumber", phoneNumber);
            body.addProperty("phoneNumberVerified", true);
        }
        send("PATCH", "/users/" + encodePathSegment(userId), body.toString(), JsonObject.class);
    }

    /**
     * Delete a user along with their authenticators.
     *
     * @param userId Authsignal user ID.
     * @throws AuthsignalClientException If the API call fails, with status 404 if the user does not exist.
     */
    public void deleteUser(String userId) throws AuthsignalClientException {

        send("DELETE", "/users/" + encodePathSegment(userId), null, null);
    }

    private <T> T post(String path, String jsonBody, Class<T> responseType) throws AuthsignalClientException {

        return send("POST", path, jsonBody, responseType);
    }

    private <T> T send(String method, String path, String jsonBody, Class<T> responseType)
            throws AuthsignalClientException {

        HttpRequest httpRequest;
        try {
            HttpRequest.Builder builder = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + path))
                    .timeout(requestTimeout)
                    .header("Authorization", authorizationHeader)
                    .header("Accept", "application/json");
            if (jsonBody != null) {
                builder.header("Content-Type", "application/json")
                        .method(method, HttpRequest.BodyPublishers.ofString(jsonBody, StandardCharsets.UTF_8));
            } else {
                builder.method(method, HttpRequest.BodyPublishers.noBody());
            }
            httpRequest = builder.build();
        } catch (IllegalArgumentException e) {
            throw new AuthsignalClientException("Invalid Authsignal API URL: " + baseUrl, e);
        }

        HttpResponse<String> httpResponse;
        try {
            httpResponse = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AuthsignalClientException("Interrupted while calling the Authsignal API.", e);
        } catch (IOException e) {
            throw new AuthsignalClientException("Error while calling the Authsignal API.", e);
        }

        int status = httpResponse.statusCode();
        if (status < 200 || status >= 300) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Authsignal API " + path.replaceAll("/users/[^/]+", "/users/***") + " returned HTTP "
                        + status + ": " + httpResponse.body());
            }
            throw new AuthsignalClientException("Authsignal API returned HTTP " + status + ".", status);
        }
        if (responseType == null) {
            // The caller does not use the response body.
            return null;
        }

        try {
            T result = GSON.fromJson(httpResponse.body(), responseType);
            if (result == null) {
                throw new AuthsignalClientException("Empty response received from the Authsignal API.", status);
            }
            return result;
        } catch (JsonParseException e) {
            throw new AuthsignalClientException("Invalid response received from the Authsignal API.", e);
        }
    }

    private static String encodePathSegment(String value) {

        // URLEncoder does form encoding; spaces must be %20 inside a path segment.
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
