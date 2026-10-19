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

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpServer;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.local.auth.authsignal.exception.AuthsignalClientException;
import org.wso2.carbon.identity.local.auth.authsignal.model.FlowResponse;
import org.wso2.carbon.identity.local.auth.authsignal.model.StartFlowRequest;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicReference;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;

/**
 * Tests for {@link AuthsignalClient} against a local stub of the Authsignal Server API.
 */
public class AuthsignalClientTest {

    private static final String SECRET = "test-secret";

    private HttpServer server;
    private String baseUrl;
    private final AtomicReference<String> lastPath = new AtomicReference<>();
    private final AtomicReference<String> lastMethod = new AtomicReference<>();
    private final AtomicReference<String> lastAuthorization = new AtomicReference<>();
    private final AtomicReference<String> lastBody = new AtomicReference<>();
    private volatile int responseStatus;
    private volatile String responseBody;

    @BeforeMethod
    public void setUp() throws IOException {

        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            lastPath.set(exchange.getRequestURI().getRawPath());
            lastMethod.set(exchange.getRequestMethod());
            lastAuthorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
            lastBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] bytes = responseBody.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(responseStatus, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        });
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort() + "/v1/";
    }

    @AfterMethod
    public void tearDown() {

        server.stop(0);
    }

    @Test
    public void testStartFlowForExistingUser() throws Exception {

        responseStatus = 200;
        responseBody = "{\"challengeUrl\":\"https://signin.authsignal.com/abc\",\"challengeId\":\"ch-1\","
                + "\"challengeToken\":\"start-tok\",\"action\":{\"state\":\"CHALLENGE_REQUIRED\","
                + "\"completedSteps\":[]}}";

        FlowResponse response = new AuthsignalClient(baseUrl, SECRET, 5000).startFlow(
                new StartFlowRequest("sign-in").setUserId("u1")
                        .setRedirectUrl("https://is/commonauth?sessionDataKey=k")
                        .setIpAddress("203.0.113.10"));

        assertEquals(response.getChallengeUrl(), "https://signin.authsignal.com/abc");
        assertEquals(response.getChallengeId(), "ch-1");
        assertEquals(response.getChallengeToken(), "start-tok");
        assertEquals(response.getState(), "CHALLENGE_REQUIRED");
        assertEquals(lastMethod.get(), "POST");
        assertEquals(lastPath.get(), "/v1/flows");
        assertEquals(lastAuthorization.get(), "Basic " + Base64.getEncoder()
                .encodeToString((SECRET + ":").getBytes(StandardCharsets.UTF_8)));

        JsonObject body = JsonParser.parseString(lastBody.get()).getAsJsonObject();
        assertEquals(body.get("actionCode").getAsString(), "sign-in");
        assertEquals(body.getAsJsonObject("user").get("userId").getAsString(), "u1");
        assertEquals(body.getAsJsonObject("user").size(), 1, "Authsignal takes one user identifier only");
        assertEquals(body.get("redirectUrl").getAsString(), "https://is/commonauth?sessionDataKey=k");
        assertEquals(body.getAsJsonObject("attributes").get("ipAddress").getAsString(), "203.0.113.10");
        assertFalse(body.has("hints"), "Null fields must be omitted");
    }

    @Test
    public void testStartFlowForNewUser() throws Exception {

        responseStatus = 200;
        responseBody = "{\"challengeUrl\":\"https://signin.authsignal.com/abc\",\"challengeId\":\"ch-1\"}";

        new AuthsignalClient(baseUrl, SECRET, 5000).startFlow(new StartFlowRequest("sign-up")
                .setUserEmail("jane@example.com").setHintPhoneNumber("+15550100"));

        JsonObject body = JsonParser.parseString(lastBody.get()).getAsJsonObject();
        assertEquals(body.getAsJsonObject("user").get("email").getAsString(), "jane@example.com");
        assertFalse(body.getAsJsonObject("user").has("userId"));
        assertEquals(body.getAsJsonObject("hints").get("phoneNumber").getAsString(), "+15550100");
        assertFalse(body.getAsJsonObject("hints").has("email"));
    }

    @Test
    public void testVerifyFlow() throws Exception {

        responseStatus = 200;
        responseBody = "{\"action\":{\"state\":\"CHALLENGE_SUCCEEDED\",\"completedSteps\":[{\"stepType\":"
                + "\"VERIFICATION_REQUIRED\",\"verificationMethod\":\"EMAIL_OTP\",\"userAuthenticatorId\":\"a1\"}]},"
                + "\"user\":{\"userId\":\"u1\",\"authenticators\":[{\"userAuthenticatorId\":\"a1\","
                + "\"verificationMethod\":\"EMAIL_OTP\",\"email\":\"jane@example.com\"},"
                + "{\"userAuthenticatorId\":\"a2\",\"verificationMethod\":\"SMS\",\"phoneNumber\":\"+15550100\"},"
                + "{\"userAuthenticatorId\":\"a3\",\"verificationMethod\":\"PASSKEY\"}]}}";

        FlowResponse response = new AuthsignalClient(baseUrl, SECRET, 5000).verifyFlow("sign-in", "tok");

        assertEquals(response.getState(), "CHALLENGE_SUCCEEDED");
        assertEquals(response.getAction().getCompletedSteps().get(0).getStepType(), "VERIFICATION_REQUIRED");
        assertEquals(response.getUser().getUserId(), "u1");
        assertEquals(response.getUser().getVerifiedEmail(), "jane@example.com");
        assertEquals(response.getUser().getVerifiedPhoneNumber(), "+15550100");
        assertEquals(lastPath.get(), "/v1/flows/verify");
        JsonObject body = JsonParser.parseString(lastBody.get()).getAsJsonObject();
        assertEquals(body.get("actionCode").getAsString(), "sign-in");
        assertEquals(body.get("challengeToken").getAsString(), "tok");
    }

    @Test
    public void testIdentifyUser() throws Exception {

        responseStatus = 200;
        responseBody = "{\"user\":{\"userId\":\"u1\",\"authenticators\":[]}}";

        FlowResponse response = new AuthsignalClient(baseUrl, SECRET, 5000).identifyUser("u1", "ch-1");

        assertEquals(response.getUser().getUserId(), "u1");
        assertEquals(lastPath.get(), "/v1/identify");
        JsonObject body = JsonParser.parseString(lastBody.get()).getAsJsonObject();
        assertEquals(body.get("userId").getAsString(), "u1");
        assertEquals(body.get("challengeId").getAsString(), "ch-1");
    }

    @Test
    public void testUpdateVerifiedContactDetails() throws Exception {

        responseStatus = 200;
        responseBody = "{\"userId\":\"u 1/x\"}";

        new AuthsignalClient(baseUrl, SECRET, 5000).updateVerifiedContactDetails("u 1/x", "jane@example.com",
                "+15550100");

        assertEquals(lastMethod.get(), "PATCH");
        assertEquals(lastPath.get(), "/v1/users/u%201%2Fx");
        JsonObject body = JsonParser.parseString(lastBody.get()).getAsJsonObject();
        assertEquals(body.get("email").getAsString(), "jane@example.com");
        assertTrue(body.get("emailVerified").getAsBoolean());
        assertEquals(body.get("phoneNumber").getAsString(), "+15550100");
        assertTrue(body.get("phoneNumberVerified").getAsBoolean());
    }

    @Test
    public void testUpdateVerifiedEmailOnly() throws Exception {

        responseStatus = 200;
        responseBody = "{\"userId\":\"u1\"}";

        new AuthsignalClient(baseUrl, SECRET, 5000).updateVerifiedContactDetails("u1", "jane@example.com", null);

        JsonObject body = JsonParser.parseString(lastBody.get()).getAsJsonObject();
        assertEquals(body.get("email").getAsString(), "jane@example.com");
        assertTrue(body.get("emailVerified").getAsBoolean());
        assertFalse(body.has("phoneNumber"));
        assertFalse(body.has("phoneNumberVerified"));
    }

    @Test
    public void testDeleteUser() throws Exception {

        responseStatus = 200;
        responseBody = "{\"success\":true}";

        new AuthsignalClient(baseUrl, SECRET, 5000).deleteUser("u 1/x");

        assertEquals(lastMethod.get(), "DELETE");
        assertEquals(lastPath.get(), "/v1/users/u%201%2Fx");
    }

    @Test
    public void testDeleteUserWithEmptyResponse() throws Exception {

        responseStatus = 200;
        responseBody = "";

        new AuthsignalClient(baseUrl, SECRET, 5000).deleteUser("u1");

        assertEquals(lastMethod.get(), "DELETE");
    }

    @Test
    public void testDeleteUnknownUser() {

        responseStatus = 404;
        responseBody = "{\"error\":\"not_found\"}";

        AuthsignalClientException e = expectThrows(AuthsignalClientException.class,
                () -> new AuthsignalClient(baseUrl, SECRET, 5000).deleteUser("u1"));
        assertEquals(e.getStatusCode(), 404);
    }

    @Test
    public void testErrorStatus() {

        responseStatus = 401;
        responseBody = "{\"error\":\"unauthorized\"}";

        AuthsignalClientException e = expectThrows(AuthsignalClientException.class,
                () -> new AuthsignalClient(baseUrl, SECRET, 5000).verifyFlow("sign-in", "tok"));
        assertEquals(e.getStatusCode(), 401);
    }

    @Test
    public void testMalformedResponse() {

        responseStatus = 200;
        responseBody = "not json";

        expectThrows(AuthsignalClientException.class,
                () -> new AuthsignalClient(baseUrl, SECRET, 5000).verifyFlow("sign-in", "tok"));
    }
}
