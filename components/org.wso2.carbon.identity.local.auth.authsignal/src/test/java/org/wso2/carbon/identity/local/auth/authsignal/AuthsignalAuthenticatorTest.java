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

package org.wso2.carbon.identity.local.auth.authsignal;

import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ApplicationConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.local.auth.authsignal.client.AuthsignalClient;
import org.wso2.carbon.identity.local.auth.authsignal.connector.AuthsignalConnectorConfig;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants;
import org.wso2.carbon.identity.local.auth.authsignal.internal.AuthsignalAuthenticatorDataHolder;
import org.wso2.carbon.identity.local.auth.authsignal.model.AuthsignalConfig;
import org.wso2.carbon.identity.local.auth.authsignal.model.FlowResponse;
import org.wso2.carbon.identity.local.auth.authsignal.model.StartFlowRequest;
import org.wso2.carbon.identity.local.auth.authsignal.util.ClaimUpdateRecorder;
import org.wso2.carbon.user.api.UserStoreException;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;

/**
 * Tests for {@link AuthsignalAuthenticator}.
 */
public class AuthsignalAuthenticatorTest {

    private static final String USER_ID = "8f1c1c0e-3a3b-4d3a-9a51-111111111111";
    private static final String CALLBACK_URL = "https://localhost:9443/commonauth?sessionDataKey=ctx-1";
    private static final String CHALLENGE_URL = "https://signin.authsignal.com/challenge";
    private static final String PASSKEY_CLAIM = "http://wso2.org/claims/authsignalPasskeyEnrolled";

    private AuthsignalClient client;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private AuthenticationContext context;
    private AuthenticatedUser user;
    private Map<String, String> parameters;
    private Map<String, String> serverParameters;
    private IdentityGovernanceService governanceService;
    private TestableAuthenticator authenticator;
    private MockedStatic<IdentityUtil> identityUtil;
    private ClaimUpdateRecorder claimUpdates;

    @BeforeMethod
    public void setUp() {

        client = mock(AuthsignalClient.class);
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);

        user = new AuthenticatedUser();
        user.setUserName("alice");
        user.setUserStoreDomain("PRIMARY");
        user.setTenantDomain("carbon.super");
        user.setUserId(USER_ID);
        user.setAuthenticatedSubjectIdentifier("alice");

        StepConfig step1 = new StepConfig();
        step1.setSubjectAttributeStep(true);
        step1.setAuthenticatedUser(user);
        Map<Integer, StepConfig> stepMap = new HashMap<>();
        stepMap.put(1, step1);
        SequenceConfig sequenceConfig = new SequenceConfig();
        sequenceConfig.setStepMap(stepMap);
        sequenceConfig.setApplicationConfig(new ApplicationConfig(new ServiceProvider(), "carbon.super"));

        context = new AuthenticationContext();
        context.setContextIdentifier("ctx-1");
        context.setTenantDomain("carbon.super");
        context.setSequenceConfig(sequenceConfig);
        // Initialized by the framework at runtime; used when publishing failed step attempts.
        context.initializeAnalyticsData();

        parameters = new HashMap<>();
        parameters.put(AuthsignalConnectorConfig.SECRET_KEY, "secret");
        parameters.put(AuthsignalConnectorConfig.PASSKEY_ENROLLED_CLAIM, PASSKEY_CLAIM);

        serverParameters = new HashMap<>();
        // Tenant-wise configuration is served by the identity governance service.
        governanceService = mock(IdentityGovernanceService.class);
        try {
            when(governanceService.getConfiguration(any(String[].class), eq("carbon.super"))).thenAnswer(
                    invocation -> parameters.entrySet().stream().map(entry -> {
                        Property property = new Property();
                        property.setName(entry.getKey());
                        property.setValue(entry.getValue());
                        return property;
                    }).toArray(Property[]::new));
        } catch (IdentityGovernanceException e) {
            throw new IllegalStateException(e);
        }
        AuthsignalAuthenticatorDataHolder.setIdentityGovernanceService(governanceService);

        claimUpdates = ClaimUpdateRecorder.start();
        authenticator = new TestableAuthenticator();
        identityUtil = mockStatic(IdentityUtil.class);
        identityUtil.when(() -> IdentityUtil.getClientIpAddress(any())).thenReturn("203.0.113.10");
    }

    @AfterMethod
    public void tearDown() {

        identityUtil.close();
        claimUpdates.close();
        AuthsignalAuthenticatorDataHolder.setIdentityGovernanceService(null);
    }

    @Test
    public void testCanHandle() {

        assertFalse(authenticator.canHandle(request));
        when(request.getParameter("challenge_token")).thenReturn("tok");
        assertTrue(authenticator.canHandle(request));
    }

    @Test
    public void testTags() {

        assertEquals(authenticator.getTags(), new String[]{"MFA"});
    }

    @Test
    public void testStartsSignInFlowAndRedirectsToPrebuiltUi() throws Exception {

        when(request.getHeader("User-Agent")).thenReturn("JUnit");
        when(client.startFlow(any())).thenReturn(started());

        AuthenticatorFlowStatus status = authenticator.process(request, response, context);

        assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
        verify(response).sendRedirect(CHALLENGE_URL);
        ArgumentCaptor<StartFlowRequest> captor = ArgumentCaptor.forClass(StartFlowRequest.class);
        verify(client).startFlow(captor.capture());
        StartFlowRequest startRequest = captor.getValue();
        assertEquals(startRequest.getActionCode(), "sign-in");
        assertEquals(startRequest.getUserId(), USER_ID);
        assertNull(startRequest.getUserEmail(), "Authsignal takes one user identifier only");
        assertEquals(startRequest.getRedirectUrl(), CALLBACK_URL);
        assertEquals(startRequest.getIpAddress(), "203.0.113.10");
        assertEquals(startRequest.getUserAgent(), "JUnit");
        assertEquals(context.getProperty(AuthsignalAuthenticator.CONTEXT_PROP_AUTHSIGNAL_USER_ID), USER_ID);
        assertEquals(context.getProperty(AuthsignalAuthenticator.CONTEXT_PROP_FLOW_REF), "sign-in");
    }

    @Test
    public void testApiBasedAuthenticationIsSupported() {

        assertTrue(authenticator.isAPIBasedAuthenticationSupported());
    }

    @Test
    public void testApiBasedFlowRedirectsBackToApplication() throws Exception {

        String appRedirectUri = "myapp://oauth2/callback";
        context.setProperty(FrameworkConstants.IS_API_BASED, "true");
        context.setProperty(FrameworkConstants.REDIRECT_URL, appRedirectUri);
        when(client.startFlow(any())).thenReturn(started());

        AuthenticatorFlowStatus status = authenticator.process(request, response, context);

        assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
        ArgumentCaptor<StartFlowRequest> captor = ArgumentCaptor.forClass(StartFlowRequest.class);
        verify(client).startFlow(captor.capture());
        assertEquals(captor.getValue().getRedirectUrl(), appRedirectUri);

        AuthenticatorData data = authenticator.getAuthInitiationData(context).orElseThrow();
        assertEquals(data.getName(), "AuthsignalAuthenticator");
        assertEquals(data.getI18nKey(), "authenticator.authsignal");
        assertEquals(data.getPromptType(), FrameworkConstants.AuthenticatorPromptType.REDIRECTION_PROMPT);
        assertEquals(data.getRequiredParams(), Collections.singletonList("challenge_token"));
        assertEquals(data.getAdditionalData().getRedirectUrl(), CHALLENGE_URL);
    }

    @Test
    public void testApiBasedFlowWithoutRedirectUriFallsBackToCommonauth() throws Exception {

        context.setProperty(FrameworkConstants.IS_API_BASED, "true");
        when(client.startFlow(any())).thenReturn(started());

        authenticator.process(request, response, context);

        ArgumentCaptor<StartFlowRequest> captor = ArgumentCaptor.forClass(StartFlowRequest.class);
        verify(client).startFlow(captor.capture());
        assertEquals(captor.getValue().getRedirectUrl(), CALLBACK_URL);
    }

    @Test
    public void testApiBasedCallbackCompletes() throws Exception {

        // The application posts the challenge_token it received on its redirect URI as an authenticator parameter.
        context.setProperty(FrameworkConstants.IS_API_BASED, "true");
        context.setProperty(AuthsignalAuthenticator.CONTEXT_PROP_CHALLENGE_URL, CHALLENGE_URL);
        flowStarted();
        when(client.verifyFlow("sign-in", "tok")).thenReturn(verified("CHALLENGE_SUCCEEDED", USER_ID));

        AuthenticatorFlowStatus status = authenticator.process(request, response, context);

        assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
        assertNull(context.getProperty(AuthsignalAuthenticator.CONTEXT_PROP_CHALLENGE_URL));
    }

    @Test
    public void testConfiguredSignInFlowRef() throws Exception {

        parameters.put(AuthsignalConnectorConfig.SIGN_IN_FLOW_REF, "custom-sign-in");
        when(client.startFlow(any())).thenReturn(started());

        authenticator.process(request, response, context);

        ArgumentCaptor<StartFlowRequest> captor = ArgumentCaptor.forClass(StartFlowRequest.class);
        verify(client).startFlow(captor.capture());
        assertEquals(captor.getValue().getActionCode(), "custom-sign-in");
    }

    @Test
    public void testStartFlowWithoutChallengeUrlFails() throws Exception {

        when(client.startFlow(any())).thenReturn(new FlowResponse());

        AuthenticationFailedException e = expectThrows(AuthenticationFailedException.class,
                () -> authenticator.process(request, response, context));
        assertEquals(e.getErrorCode(), AuthsignalConstants.ErrorMessages.ERROR_CODE_START_FLOW_FAILED.getCode());
        verify(response, never()).sendRedirect(anyString());
    }

    @Test
    public void testNoPreviousStepFails() {

        context.getSequenceConfig().setStepMap(new HashMap<>());

        AuthenticationFailedException e = expectThrows(AuthenticationFailedException.class,
                () -> authenticator.process(request, response, context));
        assertEquals(e.getErrorCode(),
                AuthsignalConstants.ErrorMessages.ERROR_CODE_NO_AUTHENTICATED_USER.getCode());
    }

    @Test
    public void testMissingSecretFails() {

        parameters.remove(AuthsignalConnectorConfig.SECRET_KEY);

        AuthenticationFailedException e = expectThrows(AuthenticationFailedException.class,
                () -> authenticator.process(request, response, context));
        assertEquals(e.getErrorCode(),
                AuthsignalConstants.ErrorMessages.ERROR_CODE_SECRET_KEY_NOT_CONFIGURED.getCode());
    }

    @Test
    public void testUsernameIdentifier() throws Exception {

        AuthsignalConfig config = new AuthsignalConfig(Map.of(
                AuthsignalConnectorConfig.USER_IDENTIFIER, "username"));
        assertEquals(authenticator.resolveAuthsignalUserId(user, config), "alice");

        user.setUserStoreDomain("LDAP");
        user.setTenantDomain("wso2.com");
        assertEquals(authenticator.resolveAuthsignalUserId(user, config), "LDAP/alice@wso2.com");
    }

    @Test
    public void testCallbackWithSuccessfulFlow() throws Exception {

        flowStarted();
        when(client.verifyFlow("sign-in", "tok")).thenReturn(verified("CHALLENGE_SUCCEEDED", USER_ID));

        AuthenticatorFlowStatus status = authenticator.process(request, response, context);

        assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
        assertNotNull(context.getSubject());
        assertNull(context.getProperty(AuthsignalAuthenticator.CONTEXT_PROP_FLOW_REF), "Flow must be consumed");
        verify(client, never()).startFlow(any());
        assertEquals(claimUpdates.getUsername(), "alice");
        assertEquals(claimUpdates.getClaims(), Collections.singletonMap(PASSKEY_CLAIM, "false"));
    }

    @Test
    public void testPasskeyEnrolledIsNotSavedWithoutConfiguredClaim() throws Exception {

        parameters.remove(AuthsignalConnectorConfig.PASSKEY_ENROLLED_CLAIM);
        flowStarted();
        when(client.verifyFlow("sign-in", "tok")).thenReturn(verified("CHALLENGE_SUCCEEDED", USER_ID));

        assertEquals(authenticator.process(request, response, context), AuthenticatorFlowStatus.SUCCESS_COMPLETED);
        assertNull(claimUpdates.getClaims());
    }

    @Test
    public void testCallbackSavesPasskeyEnrolledWhenUserHasPasskey() throws Exception {

        flowStarted();
        FlowResponse result = verified("CHALLENGE_SUCCEEDED", USER_ID);
        FlowResponse.Authenticator passkey = new FlowResponse.Authenticator();
        passkey.setVerificationMethod("PASSKEY");
        result.getUser().setAuthenticators(Collections.singletonList(passkey));
        when(client.verifyFlow("sign-in", "tok")).thenReturn(result);

        assertEquals(authenticator.process(request, response, context), AuthenticatorFlowStatus.SUCCESS_COMPLETED);
        assertEquals(claimUpdates.getClaims(), Collections.singletonMap(PASSKEY_CLAIM, "true"));
    }

    @Test
    public void testCallbackSavesPasskeyEnrolledWhenPasskeyEnrolledInFlow() throws Exception {

        flowStarted();
        FlowResponse result = verified("CHALLENGE_SUCCEEDED", USER_ID);
        FlowResponse.Step step = new FlowResponse.Step();
        step.setStepType("ENROLLMENT_REQUIRED");
        step.setVerificationMethod("PASSKEY");
        result.getAction().setCompletedSteps(Collections.singletonList(step));
        when(client.verifyFlow("sign-in", "tok")).thenReturn(result);

        assertEquals(authenticator.process(request, response, context), AuthenticatorFlowStatus.SUCCESS_COMPLETED);
        assertEquals(claimUpdates.getClaims(), Collections.singletonMap(PASSKEY_CLAIM, "true"));
    }

    @Test
    public void testPasskeyEnrolledIsNotSavedForFederatedUser() throws Exception {

        user.setFederatedUser(true);
        context.setProperty(AuthsignalAuthenticator.CONTEXT_PROP_FLOW_REF, "sign-in");
        context.setProperty(AuthsignalAuthenticator.CONTEXT_PROP_AUTHSIGNAL_USER_ID, "alice");
        when(request.getParameter("challenge_token")).thenReturn("tok");
        when(client.verifyFlow("sign-in", "tok")).thenReturn(verified("CHALLENGE_SUCCEEDED", "alice"));

        assertEquals(authenticator.process(request, response, context), AuthenticatorFlowStatus.SUCCESS_COMPLETED);
        assertNull(claimUpdates.getClaims());
    }

    @Test
    public void testFailureToSavePasskeyEnrolledDoesNotFailLogin() throws Exception {

        claimUpdates.failWith(new UserStoreException("Claim not found"));
        flowStarted();
        when(client.verifyFlow("sign-in", "tok")).thenReturn(verified("CHALLENGE_SUCCEEDED", USER_ID));

        assertEquals(authenticator.process(request, response, context), AuthenticatorFlowStatus.SUCCESS_COMPLETED);
        assertNotNull(context.getSubject());
    }

    @Test
    public void testCallbackWithFailedFlow() throws Exception {

        flowStarted();
        when(client.verifyFlow("sign-in", "tok")).thenReturn(verified("CHALLENGE_FAILED", USER_ID));

        AuthenticationFailedException e = expectThrows(AuthenticationFailedException.class,
                () -> authenticator.process(request, response, context));
        assertEquals(e.getErrorCode(),
                AuthsignalConstants.ErrorMessages.ERROR_CODE_CHALLENGE_NOT_SUCCEEDED.getCode());
    }

    @Test
    public void testCallbackWithTokenOfAnotherUser() throws Exception {

        flowStarted();
        when(client.verifyFlow("sign-in", "tok")).thenReturn(verified("CHALLENGE_SUCCEEDED", "someone-else"));

        AuthenticationFailedException e = expectThrows(AuthenticationFailedException.class,
                () -> authenticator.process(request, response, context));
        assertEquals(e.getErrorCode(), AuthsignalConstants.ErrorMessages.ERROR_CODE_CHALLENGE_MISMATCH.getCode());
    }

    @Test
    public void testTokenWithoutStartedFlowStartsNewFlow() throws Exception {

        when(request.getParameter("challenge_token")).thenReturn("tok");
        when(client.startFlow(any())).thenReturn(started());

        AuthenticatorFlowStatus status = authenticator.process(request, response, context);

        assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
        verify(client, never()).verifyFlow(anyString(), anyString());
    }

    @Test
    public void testConfigIsReadForTheRequestTenant() throws Exception {

        context.setTenantDomain("acme.com");
        user.setTenantDomain("acme.com");
        Property secret = new Property();
        secret.setName(AuthsignalConnectorConfig.SECRET_KEY);
        secret.setValue("acme-secret");
        Property region = new Property();
        region.setName(AuthsignalConnectorConfig.REGION);
        region.setValue("EU");
        when(governanceService.getConfiguration(any(String[].class), eq("acme.com")))
                .thenReturn(new Property[]{secret, region});

        AuthsignalConfig config = authenticator.getAuthsignalConfig(context);

        assertEquals(config.getSecretKey(), "acme-secret");
        assertEquals(config.getApiBaseUrl(), "https://eu.api.authsignal.com/v1");
        assertEquals(config.getSignInFlowRef(), "sign-in");
        assertEquals(config.getRegistrationFlowRef(), "sign-up");
        assertEquals(config.getRecoveryFlowRef(), "password-reset");
    }

    @Test
    public void testDeploymentTomlParametersAreIgnored() throws Exception {

        // Configuration is tenant-wise only; authenticator parameters in deployment.toml must have no effect.
        parameters.put(AuthsignalConnectorConfig.REGION, "au");
        serverParameters.put("ApiBaseUrl", "https://auth.example.com/v1");
        serverParameters.put("RequestTimeoutMillis", "1");

        AuthsignalConfig config = authenticator.getAuthsignalConfig(context);
        assertEquals(config.getApiBaseUrl(), "https://au.api.authsignal.com/v1");
        assertEquals(config.getRequestTimeoutMillis(), AuthsignalConstants.Defaults.REQUEST_TIMEOUT_MILLIS);
    }

    @Test
    public void testUnsupportedRegionFails() {

        // Tenants cannot supply a URL; an unknown region must not fall back to an arbitrary host.
        parameters.put(AuthsignalConnectorConfig.REGION, "https://internal.example");

        AuthenticationFailedException e = expectThrows(AuthenticationFailedException.class,
                () -> authenticator.process(request, response, context));
        assertEquals(e.getErrorCode(), AuthsignalConstants.ErrorMessages.ERROR_CODE_INVALID_REGION.getCode());
    }

    @Test
    public void testGovernanceErrorFails() throws Exception {

        when(governanceService.getConfiguration(any(String[].class), anyString()))
                .thenThrow(new IdentityGovernanceException("boom"));

        AuthenticationFailedException e = expectThrows(AuthenticationFailedException.class,
                () -> authenticator.process(request, response, context));
        assertEquals(e.getErrorCode(), AuthsignalConstants.ErrorMessages.ERROR_CODE_READING_CONFIG.getCode());
    }

    private void flowStarted() {

        context.setProperty(AuthsignalAuthenticator.CONTEXT_PROP_FLOW_REF, "sign-in");
        context.setProperty(AuthsignalAuthenticator.CONTEXT_PROP_AUTHSIGNAL_USER_ID, USER_ID);
        when(request.getParameter("challenge_token")).thenReturn("tok");
    }

    private static FlowResponse started() {

        FlowResponse startResponse = new FlowResponse();
        startResponse.setChallengeUrl(CHALLENGE_URL);
        startResponse.setChallengeId("challenge-1");
        startResponse.setChallengeToken("start-token");
        return startResponse;
    }

    private static FlowResponse verified(String state, String userId) {

        FlowResponse.Action action = new FlowResponse.Action();
        action.setState(state);
        FlowResponse.User flowUser = new FlowResponse.User();
        flowUser.setUserId(userId);
        FlowResponse verifyResponse = new FlowResponse();
        verifyResponse.setAction(action);
        verifyResponse.setUser(flowUser);
        return verifyResponse;
    }

    /**
     * Replaces the server runtime dependencies (URL builder, deployment.toml config, HTTP client) with test doubles.
     */
    private class TestableAuthenticator extends AuthsignalAuthenticator {

        private static final long serialVersionUID = 1L;

        @Override
        protected String buildCallbackUrl(AuthenticationContext context) {

            return CALLBACK_URL;
        }

        @Override
        protected AuthsignalClient createClient(AuthsignalConfig config) throws AuthenticationFailedException {

            super.createClient(config);
            return client;
        }

        @Override
        protected AuthenticatorConfig getAuthenticatorConfig() {

            AuthenticatorConfig config = new AuthenticatorConfig();
            config.setParameterMap(serverParameters);
            return config;
        }

        @Override
        protected void publishAuthenticationStepAttempt(HttpServletRequest request, AuthenticationContext context,
                                                        org.wso2.carbon.identity.application.common.model.User user,
                                                        boolean success) {

            // Event publishing requires the OSGi runtime.
        }
    }
}
