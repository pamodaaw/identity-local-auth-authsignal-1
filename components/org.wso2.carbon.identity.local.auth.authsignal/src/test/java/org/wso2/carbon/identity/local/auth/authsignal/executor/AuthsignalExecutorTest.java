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

package org.wso2.carbon.identity.local.auth.authsignal.executor;

import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineException;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineServerException;
import org.wso2.carbon.identity.flow.execution.engine.graph.AuthenticationExecutor;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowUser;
import org.wso2.carbon.identity.flow.mgt.Constants.FlowTypes;
import org.wso2.carbon.identity.flow.mgt.model.ExecutorDTO;
import org.wso2.carbon.identity.flow.mgt.model.NodeConfig;
import org.wso2.carbon.identity.local.auth.authsignal.client.AuthsignalClient;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.ConnectorConfig;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.ExecutorErrorMessages;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.ExecutorMetadata;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.FlowContextProps;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.FlowType;
import org.wso2.carbon.identity.local.auth.authsignal.exception.AuthsignalConnectionException;
import org.wso2.carbon.identity.local.auth.authsignal.model.AuthsignalConfig;
import org.wso2.carbon.identity.local.auth.authsignal.model.AuthsignalRequest;
import org.wso2.carbon.identity.local.auth.authsignal.model.AuthsignalResponse;
import org.wso2.carbon.identity.local.auth.authsignal.util.ClaimUpdateRecorder;
import org.wso2.carbon.identity.local.auth.authsignal.util.DiagnosticLogRecorder;
import org.wso2.carbon.user.api.UserStoreException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ErrorMessages.ERROR_CODE_EXECUTOR_FAILURE;

/**
 * Tests for {@link AuthsignalExecutor}.
 */
public class AuthsignalExecutorTest {

    private static final String TENANT = "carbon.super";
    private static final String PORTAL_URL = "https://localhost:9443/accounts/register?flowType=REGISTRATION";
    private static final String CHALLENGE_URL = "https://signin.authsignal.com/challenge";
    private static final String USER_UUID = "8f1c1c0e-3a3b-4d3a-9a51-111111111111";
    private static final String EMAIL = "alice@example.com";
    private static final String MOBILE = "+94770000000";
    private static final String PASSKEY_CLAIM = AuthsignalConstants.PASSKEY_MANAGED_EXTERNALLY_CLAIM;

    private AuthsignalClient client;
    private Map<String, String> tenantProperties;
    private ClaimUpdateRecorder claimUpdates;
    private TestableExecutor executor;
    private MockedStatic<LoggerUtils> loggerUtils;

    @AfterMethod
    public void tearDown() {

        claimUpdates.close();
        loggerUtils.close();
    }

    @BeforeMethod
    public void setUp() {

        // Diagnostic logs are disabled unless a test records them, as they need a running server.
        loggerUtils = mockStatic(LoggerUtils.class);
        client = mock(AuthsignalClient.class);
        tenantProperties = new HashMap<>();
        tenantProperties.put(ConnectorConfig.SECRET_KEY, "secret");
        claimUpdates = ClaimUpdateRecorder.start();
        executor = new TestableExecutor();
    }

    @Test
    public void testMetadata() {

        assertEquals(executor.getName(), "AuthsignalExecutor");
        // The executor must not need a connection.
        assertFalse(AuthenticationExecutor.class.isAssignableFrom(AuthsignalExecutor.class));
        assertEquals(executor.getExecutorMetadata().getDisplayName(), "Authsignal");
        assertTrue(executor.getExecutorMetadata().getIcon().startsWith("data:image/svg+xml;base64,"));
        assertFalse(executor.getExecutorMetadata().isConnectionRequired());
        assertTrue(executor.getSupportedFlowTypes().contains(FlowTypes.REGISTRATION));
        assertTrue(executor.getSupportedFlowTypes().contains(FlowTypes.PASSWORD_RECOVERY));
        assertTrue(executor.getSupportedFlowTypes().contains(FlowTypes.INVITED_USER_REGISTRATION));
        assertTrue(executor.getInitiationData().isEmpty());
    }

    @Test
    public void testRegistrationStartsFlowWithEmailAndPhoneHint() throws Exception {

        FlowExecutionContext context = registrationContext(EMAIL, MOBILE);
        when(client.startFlow(any())).thenReturn(started());

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), "EXTERNAL_REDIRECTION");
        assertEquals(response.getAdditionalInfo().get("redirectUrl"), CHALLENGE_URL);
        assertNull(response.getAdditionalInfo().get("state"));
        assertEquals(response.getRequiredData(), Collections.singletonList("challenge_token"));

        AuthsignalRequest request = captureStartRequest();
        assertEquals(request.getActionCode(), "sign-in");
        assertNull(request.getUserId(), "The WSO2 user does not exist yet");
        assertEquals(request.getUserEmail(), EMAIL);
        assertNull(request.getUserPhoneNumber(), "Authsignal takes one user identifier only");
        assertEquals(request.getHintPhoneNumber(), MOBILE);
        assertTrue(response.getContextProperties() == null || response.getContextProperties().isEmpty(),
                "Nothing is kept in the flow context until the flow is verified");
        assertEquals(request.getRedirectUrl(), PORTAL_URL);
    }

    @Test
    public void testRegistrationWithoutEmailStartsFlowWithPhone() throws Exception {

        when(client.startFlow(any())).thenReturn(started());

        executor.execute(registrationContext(null, MOBILE));

        AuthsignalRequest request = captureStartRequest();
        assertEquals(request.getUserPhoneNumber(), MOBILE);
        assertNull(request.getUserEmail());
        assertNull(request.getHintPhoneNumber());
    }

    @Test
    public void testRegistrationSkipsNonE164Mobile() throws Exception {

        when(client.startFlow(any())).thenReturn(started());

        executor.execute(registrationContext(EMAIL, "0770000000"));

        assertNull(captureStartRequest().getHintPhoneNumber());
    }

    @Test
    public void testRegistrationWithoutContactDetailsFails() throws Exception {

        ExecutorResponse response = executor.execute(registrationContext(null, "0770000000"));

        assertEquals(response.getResult(), "USER_ERROR");
        assertExecutorError(response, ExecutorErrorMessages.CONTACT_DETAILS_NOT_FOUND.getMessage());
        verify(client, never()).startFlow(any());
    }

    @Test
    public void testRegistrationWithoutChallengeUrlFails() throws Exception {

        AuthsignalResponse startResponse = started();
        startResponse.setChallengeUrl(null);
        when(client.startFlow(any())).thenReturn(startResponse);

        assertServerError(registrationContext(EMAIL, MOBILE),
                ExecutorErrorMessages.INVALID_START_FLOW_RESPONSE.getMessage());
    }

    @Test
    public void testConfiguredActionCodeUsedForRegistration() throws Exception {

        tenantProperties.put(ConnectorConfig.ACTION_CODE, "custom-flow");
        when(client.startFlow(any())).thenReturn(started());

        executor.execute(registrationContext(EMAIL, MOBILE));

        assertEquals(captureStartRequest().getActionCode(), "custom-flow");
    }

    @Test
    public void testRegistrationCallbackCompletesAndKeepsChallengeId() throws Exception {

        FlowExecutionContext context = registrationContext(EMAIL, MOBILE);
        when(client.startFlow(any())).thenReturn(started());
        ExecutorResponse redirect = executor.execute(context);
        callback(context, redirect);
        when(client.verifyFlow("sign-in", "tok")).thenReturn(verified("CHALLENGE_SUCCEEDED", "temp-id",
                step("VERIFICATION_REQUIRED", "EMAIL_OTP"), authenticator("EMAIL_OTP", "Alice@Example.com", null),
                authenticator("SMS", null, MOBILE)));

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), "COMPLETE");
        assertEquals(context.getProperties(), Collections.singletonMap(FlowContextProps.CHALLENGE_ID, "challenge-1"),
                "Only the challenge ID of the verified flow is kept for the flow listener");
        assertNull(claimUpdates.getClaims(), "The user does not exist yet");
    }

    @Test
    public void testRegistrationCallbackWithoutChallengeIdFails() throws Exception {

        FlowExecutionContext context = registrationContext(EMAIL, MOBILE);
        when(client.startFlow(any())).thenReturn(started());
        ExecutorResponse redirect = executor.execute(context);
        callback(context, redirect);
        AuthsignalResponse result = verified("CHALLENGE_SUCCEEDED", "temp-id",
                step("VERIFICATION_REQUIRED", "EMAIL_OTP"), authenticator("EMAIL_OTP", EMAIL, null));
        result.setChallengeId(null);
        when(client.verifyFlow("sign-in", "tok")).thenReturn(result);

        assertServerError(context, ExecutorErrorMessages.INVALID_VERIFY_FLOW_RESPONSE.getMessage());
        assertNull(context.getProperty(FlowContextProps.CHALLENGE_ID));
    }

    @Test
    public void testRegistrationCallbackDoesNotSavePasskeyManagedExternally() throws Exception {

        FlowExecutionContext context = registrationContext(EMAIL, MOBILE);
        when(client.startFlow(any())).thenReturn(started());
        ExecutorResponse redirect = executor.execute(context);
        callback(context, redirect);
        when(client.verifyFlow("sign-in", "tok")).thenReturn(verified("CHALLENGE_SUCCEEDED", "temp-id",
                step("VERIFICATION_REQUIRED", "EMAIL_OTP"), step("ENROLLMENT_REQUIRED", "PASSKEY"),
                authenticator("EMAIL_OTP", EMAIL, null)));

        assertEquals(executor.execute(context).getResult(), "COMPLETE");
        assertNull(claimUpdates.getClaims(), "Saved by the flow listener once the user is linked");
    }

    @Test
    public void testRegistrationCallbackWithAnotherVerifiedEmailFails() throws Exception {

        FlowExecutionContext context = registrationContext(EMAIL, MOBILE);
        when(client.startFlow(any())).thenReturn(started());
        ExecutorResponse redirect = executor.execute(context);
        callback(context, redirect);
        when(client.verifyFlow("sign-in", "tok")).thenReturn(verified("CHALLENGE_SUCCEEDED", "temp-id",
                step("VERIFICATION_REQUIRED", "EMAIL_OTP"), authenticator("EMAIL_OTP", "mallory@example.com", null)));

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), "USER_ERROR");
        assertExecutorError(response, ExecutorErrorMessages.CONTACT_DETAILS_MISMATCH.getMessage());
        assertNull(context.getProperty(FlowContextProps.CHALLENGE_ID));
    }

    @Test
    public void testRegistrationCallbackWithoutContactStepFails() throws Exception {

        FlowExecutionContext context = registrationContext(EMAIL, MOBILE);
        when(client.startFlow(any())).thenReturn(started());
        ExecutorResponse redirect = executor.execute(context);
        callback(context, redirect);
        // The user has an email OTP authenticator, but only used a passkey in this flow.
        when(client.verifyFlow("sign-in", "tok")).thenReturn(verified("CHALLENGE_SUCCEEDED", "temp-id",
                step("ENROLLMENT_REQUIRED", "PASSKEY"), authenticator("EMAIL_OTP", EMAIL, null)));

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), "USER_ERROR");
        assertExecutorError(response, ExecutorErrorMessages.CONTACT_DETAILS_MISMATCH.getMessage());
        assertNull(context.getProperty(FlowContextProps.CHALLENGE_ID));
    }

    @Test
    public void testPhoneRegistrationCallbackBindsToVerifiedPhone() throws Exception {

        FlowExecutionContext context = registrationContext(null, MOBILE);
        when(client.startFlow(any())).thenReturn(started());
        ExecutorResponse redirect = executor.execute(context);
        callback(context, redirect);
        when(client.verifyFlow("sign-in", "tok")).thenReturn(verified("CHALLENGE_SUCCEEDED", "temp-id",
                step("VERIFICATION_REQUIRED", "SMS"), authenticator("SMS", null, MOBILE)));

        assertEquals(executor.execute(context).getResult(), "COMPLETE");
        assertEquals(context.getProperty(FlowContextProps.CHALLENGE_ID), "challenge-1");
    }

    @Test
    public void testFailedFlowFails() throws Exception {

        FlowExecutionContext context = registrationContext(EMAIL, MOBILE);
        when(client.startFlow(any())).thenReturn(started());
        ExecutorResponse redirect = executor.execute(context);
        callback(context, redirect);
        when(client.verifyFlow("sign-in", "tok")).thenReturn(verified("CHALLENGE_FAILED", "temp-id",
                step("VERIFICATION_REQUIRED"), authenticator("EMAIL_OTP", EMAIL, null)));

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), "USER_ERROR");
        assertExecutorError(response, ExecutorErrorMessages.CHALLENGE_NOT_SUCCEEDED.getMessage());
    }

    @Test
    public void testCallbackWithoutChallengeTokenFails() throws Exception {

        FlowExecutionContext context = registrationContext(EMAIL, MOBILE);
        when(client.startFlow(any())).thenReturn(started());
        executor.execute(context);
        context.addUserInputData("challenge_token", " ");

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), "USER_ERROR");
        assertExecutorError(response, ExecutorErrorMessages.MISSING_TOKEN.getMessage());
        assertNull(context.getProperty(FlowContextProps.CHALLENGE_ID));
        verify(client, never()).verifyFlow(anyString(), anyString());
    }

    @Test
    public void testRecoveryStartsFlowWithUserId() throws Exception {

        when(client.startFlow(any())).thenReturn(started());

        ExecutorResponse response = executor.execute(recoveryContext());

        assertEquals(response.getResult(), "EXTERNAL_REDIRECTION");
        AuthsignalRequest request = captureStartRequest();
        assertEquals(request.getActionCode(), "sign-in");
        assertEquals(request.getUserId(), USER_UUID);
        assertNull(request.getUserEmail());
        assertNull(request.getHintEmail());
    }

    @Test
    public void testRecoveryForUnknownUserFails() throws Exception {

        FlowExecutionContext context = recoveryContext();
        context.getFlowUser().setUserId(null);

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), "USER_ERROR");
        assertExecutorError(response, ExecutorErrorMessages.USER_NOT_IDENTIFIED.getMessage());
        verify(client, never()).startFlow(any());
    }

    @Test
    public void testRecoveryCallbackCompletes() throws Exception {

        FlowExecutionContext context = recoveryContext();
        when(client.startFlow(any())).thenReturn(started());
        ExecutorResponse redirect = executor.execute(context);
        callback(context, redirect);
        when(client.verifyFlow("sign-in", "tok")).thenReturn(verified("CHALLENGE_SUCCEEDED", USER_UUID,
                step("VERIFICATION_REQUIRED")));

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), "COMPLETE");
        assertNull(context.getProperty(FlowContextProps.CHALLENGE_ID));
        assertEquals(claimUpdates.getUsername(), "alice");
        assertEquals(claimUpdates.getClaims(), Collections.singletonMap(PASSKEY_CLAIM, "false"));
    }

    @Test
    public void testRecoveryCallbackForAnotherUserFails() throws Exception {

        FlowExecutionContext context = recoveryContext();
        when(client.startFlow(any())).thenReturn(started());
        ExecutorResponse redirect = executor.execute(context);
        callback(context, redirect);
        when(client.verifyFlow("sign-in", "tok")).thenReturn(verified("CHALLENGE_SUCCEEDED", "someone",
                step("VERIFICATION_REQUIRED")));

        ExecutorResponse response = executor.execute(context);

        assertExecutorError(response, ExecutorErrorMessages.USER_MISMATCH.getMessage(), USER_UUID);
    }

    @Test
    public void testInvitedUserRegistrationStartsRegistrationFlowWithUserId() throws Exception {

        FlowUser flowUser = existingUser();
        when(client.startFlow(any())).thenReturn(started());

        executor.execute(context(FlowType.INVITED_USER_REGISTRATION, flowUser));

        AuthsignalRequest request = captureStartRequest();
        assertEquals(request.getActionCode(), "sign-in");
        assertEquals(request.getUserId(), USER_UUID);
    }

    @Test
    public void testInvitedUserRegistrationAcceptsEnrolmentAndSavesPasskey() throws Exception {

        // The invited user sets up their authenticators in this flow, so a new passkey is accepted.
        FlowExecutionContext context = context(FlowType.INVITED_USER_REGISTRATION, existingUser());
        when(client.startFlow(any())).thenReturn(started());
        ExecutorResponse redirect = executor.execute(context);
        callback(context, redirect);
        when(client.verifyFlow("sign-in", "tok")).thenReturn(verified("CHALLENGE_SUCCEEDED", USER_UUID,
                step("ENROLLMENT_REQUIRED", "PASSKEY")));

        assertEquals(executor.execute(context).getResult(), "COMPLETE");
        assertEquals(claimUpdates.getClaims(), Collections.singletonMap(PASSKEY_CLAIM, "true"));
        assertNull(context.getProperty(FlowContextProps.CHALLENGE_ID));
    }

    @Test
    public void testUnsupportedFlowTypeFailsAtCallback() throws Exception {

        FlowExecutionContext context = context("ASK_PASSWORD", existingUser());
        callback(context, null);
        when(client.verifyFlow("sign-in", "tok")).thenReturn(verified("CHALLENGE_SUCCEEDED", USER_UUID,
                step("VERIFICATION_REQUIRED")));

        assertServerError(context,
                String.format(ExecutorErrorMessages.UNSUPPORTED_FLOW_TYPE.getMessage(), "ASK_PASSWORD"));
        assertNull(claimUpdates.getClaims());
    }

    @Test
    public void testActionCodeFromExecutorMetadataIsUsed() throws Exception {

        tenantProperties.put(ConnectorConfig.ACTION_CODE, "custom-flow");
        when(client.startFlow(any())).thenReturn(started());
        FlowExecutionContext context = registrationContext(EMAIL, MOBILE);
        setExecutorMetadata(context, Collections.singletonMap(ExecutorMetadata.ACTION_CODE, " sign-up "));

        ExecutorResponse redirect = executor.execute(context);

        assertEquals(captureStartRequest().getActionCode(), "sign-up");
        callback(context, redirect);
        when(client.verifyFlow("sign-up", "tok")).thenReturn(verified("CHALLENGE_SUCCEEDED", "temp-id",
                step("VERIFICATION_REQUIRED"), authenticator("EMAIL_OTP", EMAIL, null)));
        assertEquals(executor.execute(context).getResult(), "COMPLETE");
    }

    @Test
    public void testBlankExecutorMetadataFallsBackToConfiguredActionCode() throws Exception {

        tenantProperties.put(ConnectorConfig.ACTION_CODE, "custom-flow");
        when(client.startFlow(any())).thenReturn(started());
        FlowExecutionContext context = recoveryContext();
        setExecutorMetadata(context, Collections.singletonMap(ExecutorMetadata.ACTION_CODE, " "));

        executor.execute(context);

        assertEquals(captureStartRequest().getActionCode(), "custom-flow");
    }

    @Test
    public void testConfiguredActionCodeUsedForRecovery() throws Exception {

        tenantProperties.put(ConnectorConfig.ACTION_CODE, "custom-flow");
        when(client.startFlow(any())).thenReturn(started());

        executor.execute(recoveryContext());

        assertEquals(captureStartRequest().getActionCode(), "custom-flow");
    }

    @Test
    public void testRecoveryCallbackSavesPasskeyManagedExternallyWhenUserHasPasskey() throws Exception {

        FlowExecutionContext context = recoveryContext();
        when(client.startFlow(any())).thenReturn(started());
        ExecutorResponse redirect = executor.execute(context);
        callback(context, redirect);
        when(client.verifyFlow("sign-in", "tok")).thenReturn(verified("CHALLENGE_SUCCEEDED", USER_UUID,
                step("VERIFICATION_REQUIRED"), authenticator("PASSKEY", null, null)));

        assertEquals(executor.execute(context).getResult(), "COMPLETE");
        assertEquals(claimUpdates.getClaims(), Collections.singletonMap(PASSKEY_CLAIM, "true"));
    }

    @Test
    public void testRecoveryCallbackSavesPasskeyManagedExternallyWhenVerifiedWithPasskey() throws Exception {

        FlowExecutionContext context = recoveryContext();
        when(client.startFlow(any())).thenReturn(started());
        ExecutorResponse redirect = executor.execute(context);
        callback(context, redirect);
        when(client.verifyFlow("sign-in", "tok")).thenReturn(verified("CHALLENGE_SUCCEEDED", USER_UUID,
                step("VERIFICATION_REQUIRED", "PASSKEY")));

        assertEquals(executor.execute(context).getResult(), "COMPLETE");
        assertEquals(claimUpdates.getClaims(), Collections.singletonMap(PASSKEY_CLAIM, "true"));
    }

    @Test
    public void testFailureToSavePasskeyManagedExternallyDoesNotFailFlow() throws Exception {

        claimUpdates.failWith(new UserStoreException("Claim not found"));
        FlowExecutionContext context = recoveryContext();
        when(client.startFlow(any())).thenReturn(started());
        ExecutorResponse redirect = executor.execute(context);
        callback(context, redirect);
        when(client.verifyFlow("sign-in", "tok")).thenReturn(verified("CHALLENGE_SUCCEEDED", USER_UUID,
                step("VERIFICATION_REQUIRED", "PASSKEY")));

        assertEquals(executor.execute(context).getResult(), "COMPLETE");
    }

    @Test
    public void testMissingSecretFails() throws Exception {

        tenantProperties.remove(ConnectorConfig.SECRET_KEY);

        assertServerError(registrationContext(EMAIL, MOBILE),
                ExecutorErrorMessages.SECRET_KEY_NOT_CONFIGURED.getMessage());
    }

    @Test
    public void testMissingPortalUrlFails() throws Exception {

        FlowExecutionContext context = registrationContext(EMAIL, MOBILE);
        context.setPortalUrl(null);

        assertServerError(context, ExecutorErrorMessages.PORTAL_URL_NOT_FOUND.getMessage());
    }

    @Test
    public void testUnsupportedFlowTypeFails() throws Exception {

        assertServerError(context("ASK_PASSWORD", existingUser()),
                String.format(ExecutorErrorMessages.UNSUPPORTED_FLOW_TYPE.getMessage(), "ASK_PASSWORD"));
    }

    @Test
    public void testStartFlowFailure() throws Exception {

        when(client.startFlow(any())).thenThrow(new AuthsignalConnectionException("down", 500));

        FlowEngineServerException e = assertServerError(registrationContext(EMAIL, MOBILE),
                ExecutorErrorMessages.START_FLOW_FAILED.getMessage());
        assertTrue(e.getCause() instanceof AuthsignalConnectionException);
    }

    @Test
    public void testStartFlowRejectedByAuthsignalIsUserError() throws Exception {

        when(client.startFlow(any())).thenThrow(new AuthsignalConnectionException("rejected", 400));

        ExecutorResponse response = executor.execute(registrationContext(EMAIL, MOBILE));

        assertEquals(response.getResult(), "USER_ERROR");
        assertExecutorError(response, ExecutorErrorMessages.START_FLOW_FAILED.getMessage());
    }

    @Test
    public void testVerifyFlowRejectedByAuthsignalIsUserError() throws Exception {

        FlowExecutionContext context = registrationContext(EMAIL, MOBILE);
        when(client.startFlow(any())).thenReturn(started());
        callback(context, executor.execute(context));
        when(client.verifyFlow("sign-in", "tok")).thenThrow(new AuthsignalConnectionException("rejected", 401));

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), "USER_ERROR");
        assertExecutorError(response, ExecutorErrorMessages.VERIFY_FLOW_FAILED.getMessage());
    }

    @Test
    public void testVerifyFlowFailure() throws Exception {

        FlowExecutionContext context = registrationContext(EMAIL, MOBILE);
        when(client.startFlow(any())).thenReturn(started());
        callback(context, executor.execute(context));
        when(client.verifyFlow("sign-in", "tok")).thenThrow(new AuthsignalConnectionException("down", 503));

        FlowEngineServerException e = assertServerError(context,
                ExecutorErrorMessages.VERIFY_FLOW_FAILED.getMessage());
        assertTrue(e.getCause() instanceof AuthsignalConnectionException);
    }

    @Test
    public void testDiagnosticLogsOfFlow() throws Exception {

        DiagnosticLogRecorder diagnosticLogs = DiagnosticLogRecorder.start(loggerUtils);
        FlowExecutionContext context = recoveryContext();
        context.setApplicationId("app-1");
        when(client.startFlow(any())).thenReturn(started());
        callback(context, executor.execute(context));
        when(client.verifyFlow("sign-in", "tok")).thenReturn(verified("CHALLENGE_SUCCEEDED", USER_UUID,
                step("VERIFICATION_REQUIRED", "PASSKEY")));

        executor.execute(context);

        assertEquals(diagnosticLogs.getLogs(), Arrays.asList(
                "start-authsignal-flow | SUCCESS: Started the flow on Authsignal.",
                "verify-authsignal-flow | SUCCESS: Received the flow result from Authsignal.",
                "verify-authsignal-flow | SUCCESS: Authsignal verification completed successfully."));
        assertEquals(diagnosticLogs.getComponentIds(), Collections.nCopies(3, "authsignal-service"));
        Map<String, Object> inputs = diagnosticLogs.getInputs("Received the flow result from Authsignal.");
        assertEquals(inputs.get("flow type"), FlowType.PASSWORD_RECOVERY);
        assertEquals(inputs.get(LogConstants.InputKeys.APPLICATION_ID), "app-1");
        assertEquals(inputs.get("action code"), "sign-in");
        assertEquals(inputs.get(LogConstants.InputKeys.USER_ID), USER_UUID);
        assertEquals(inputs.get("flow state"), "CHALLENGE_SUCCEEDED");
        assertEquals(inputs.get("verification methods"), Collections.singletonList("PASSKEY"));
        Map<String, Object> completedInputs =
                diagnosticLogs.getInputs("Authsignal verification completed successfully.");
        assertEquals(completedInputs.get("flow type"), FlowType.PASSWORD_RECOVERY);
        assertEquals(completedInputs.get(LogConstants.InputKeys.APPLICATION_ID), "app-1");
        assertEquals(completedInputs.get("action code"), "sign-in");
    }

    @Test
    public void testRegistrationLogsHaveNoPersonalData() throws Exception {

        DiagnosticLogRecorder diagnosticLogs = DiagnosticLogRecorder.start(loggerUtils);
        when(client.startFlow(any())).thenReturn(started());

        executor.execute(registrationContext(EMAIL, MOBILE));

        Map<String, Object> inputs = diagnosticLogs.getInputs("Started the flow on Authsignal.");
        assertEquals(inputs.get("flow type"), FlowType.REGISTRATION);
        assertFalse(inputs.toString().contains(EMAIL), "Personal data must not be logged");
        assertFalse(inputs.toString().contains(MOBILE), "Personal data must not be logged");
    }

    @Test
    public void testUserErrorAfterAuthsignalCallIsLogged() throws Exception {

        DiagnosticLogRecorder diagnosticLogs = DiagnosticLogRecorder.start(loggerUtils);
        FlowExecutionContext context = recoveryContext();
        callback(context, null);
        when(client.verifyFlow("sign-in", "tok")).thenReturn(verified("CHALLENGE_SUCCEEDED", "someone-else",
                step("VERIFICATION_REQUIRED")));

        executor.execute(context);

        String message = ExecutorErrorMessages.USER_MISMATCH.getMessage();
        assertEquals(diagnosticLogs.getLogs(), Arrays.asList(
                "verify-authsignal-flow | SUCCESS: Received the flow result from Authsignal.",
                "verify-authsignal-flow | FAILED: " + message));
        // The user ID is logged as an input only.
        Map<String, Object> inputs = diagnosticLogs.getInputs(message);
        assertEquals(inputs.get(LogConstants.InputKeys.USER_ID), USER_UUID);
        assertEquals(inputs.get("action code"), "sign-in");
    }

    @Test
    public void testUserErrorBeforeAuthsignalCallIsLogged() throws Exception {

        DiagnosticLogRecorder diagnosticLogs = DiagnosticLogRecorder.start(loggerUtils);

        executor.execute(registrationContext(null, null));

        String message = ExecutorErrorMessages.CONTACT_DETAILS_NOT_FOUND.getMessage();
        assertEquals(diagnosticLogs.getLogs(),
                Collections.singletonList("start-authsignal-flow | FAILED: " + message));
        Map<String, Object> inputs = diagnosticLogs.getInputs(message);
        assertEquals(inputs.get("flow type"), FlowType.REGISTRATION);
        assertEquals(inputs.get("action code"), "sign-in");
    }

    @Test
    public void testFailedAuthsignalCallIsLogged() throws Exception {

        DiagnosticLogRecorder diagnosticLogs = DiagnosticLogRecorder.start(loggerUtils);
        FlowExecutionContext context = recoveryContext();
        callback(context, null);
        when(client.verifyFlow("sign-in", "tok")).thenThrow(new AuthsignalConnectionException("down", 503));

        expectThrows(FlowEngineServerException.class, () -> executor.execute(context));

        String message = ExecutorErrorMessages.VERIFY_FLOW_FAILED.getMessage();
        assertEquals(diagnosticLogs.getLogs(),
                Collections.singletonList("verify-authsignal-flow | FAILED: " + message));
        Map<String, Object> inputs = diagnosticLogs.getInputs(message);
        assertEquals(inputs.get("authsignal status code"), 503);
        assertEquals(inputs.get("action code"), "sign-in");
        assertEquals(inputs.get("flow type"), FlowType.PASSWORD_RECOVERY);
        assertEquals(inputs.get(LogConstants.InputKeys.USER_ID), USER_UUID);
    }

    @Test
    public void testRejectedAuthsignalCallIsLogged() throws Exception {

        DiagnosticLogRecorder diagnosticLogs = DiagnosticLogRecorder.start(loggerUtils);
        when(client.startFlow(any())).thenThrow(new AuthsignalConnectionException("rejected", 400));

        executor.execute(registrationContext(EMAIL, MOBILE));

        String message = ExecutorErrorMessages.START_FLOW_FAILED.getMessage();
        assertEquals(diagnosticLogs.getLogs(),
                Collections.singletonList("start-authsignal-flow | FAILED: " + message));
        Map<String, Object> inputs = diagnosticLogs.getInputs(message);
        assertEquals(inputs.get("authsignal status code"), 400);
        assertEquals(inputs.get("action code"), "sign-in");
        assertEquals(inputs.get("flow type"), FlowType.REGISTRATION);
    }

    @Test
    public void testRejectedVerifyCallIsLoggedOnce() throws Exception {

        DiagnosticLogRecorder diagnosticLogs = DiagnosticLogRecorder.start(loggerUtils);
        FlowExecutionContext context = recoveryContext();
        callback(context, null);
        when(client.verifyFlow("sign-in", "tok")).thenThrow(new AuthsignalConnectionException("rejected", 401));

        executor.execute(context);

        String message = ExecutorErrorMessages.VERIFY_FLOW_FAILED.getMessage();
        assertEquals(diagnosticLogs.getLogs(),
                Collections.singletonList("verify-authsignal-flow | FAILED: " + message));
        Map<String, Object> inputs = diagnosticLogs.getInputs(message);
        assertEquals(inputs.get("authsignal status code"), 401);
        assertEquals(inputs.get("action code"), "sign-in");
        assertEquals(inputs.get(LogConstants.InputKeys.USER_ID), USER_UUID);
    }

    @Test
    public void testFailureBeforeAuthsignalCallIsLogged() throws Exception {

        DiagnosticLogRecorder diagnosticLogs = DiagnosticLogRecorder.start(loggerUtils);
        tenantProperties.remove(ConnectorConfig.SECRET_KEY);

        expectThrows(FlowEngineServerException.class, () -> executor.execute(recoveryContext()));

        String message = ExecutorErrorMessages.SECRET_KEY_NOT_CONFIGURED.getMessage();
        assertEquals(diagnosticLogs.getLogs(),
                Collections.singletonList("start-authsignal-flow | FAILED: " + message));
        assertEquals(diagnosticLogs.getInputs(message).get("flow type"), FlowType.PASSWORD_RECOVERY);
    }

    private AuthsignalRequest captureStartRequest() throws Exception {

        ArgumentCaptor<AuthsignalRequest> captor = ArgumentCaptor.forClass(AuthsignalRequest.class);
        verify(client).startFlow(captor.capture());
        return captor.getValue();
    }

    private FlowExecutionContext registrationContext(String email, String mobile) {

        FlowUser flowUser = new FlowUser();
        if (email != null) {
            flowUser.addClaim(AuthsignalConstants.EMAIL_CLAIM, email);
        }
        if (mobile != null) {
            flowUser.addClaim(AuthsignalConstants.MOBILE_CLAIM, mobile);
        }
        return context(FlowType.REGISTRATION, flowUser);
    }

    private FlowExecutionContext recoveryContext() {

        return context(FlowType.PASSWORD_RECOVERY, existingUser());
    }

    private static FlowUser existingUser() {

        FlowUser flowUser = new FlowUser();
        flowUser.setUsername("alice");
        flowUser.setUserStoreDomain("PRIMARY");
        flowUser.setUserId(USER_UUID);
        flowUser.addClaim(AuthsignalConstants.EMAIL_CLAIM, EMAIL);
        return flowUser;
    }

    private static void setExecutorMetadata(FlowExecutionContext context, Map<String, String> metadata) {

        ExecutorDTO executorConfig = new ExecutorDTO(AuthsignalConstants.EXECUTOR_NAME, metadata);
        context.setCurrentNode(new NodeConfig.Builder().id("authsignal").executorConfig(executorConfig).build());
    }

    private static FlowExecutionContext context(String flowType, FlowUser flowUser) {

        FlowExecutionContext context = new FlowExecutionContext();
        context.setFlowType(flowType);
        context.setTenantDomain(TENANT);
        context.setPortalUrl(PORTAL_URL);
        context.setFlowUser(flowUser);
        return context;
    }

    /**
     * Simulate the portal sending back the challenge token.
     */
    private static void callback(FlowExecutionContext context, ExecutorResponse redirect) {

        context.addUserInputData("challenge_token", "tok");
    }

    private static AuthsignalResponse started() {

        AuthsignalResponse response = new AuthsignalResponse();
        response.setChallengeUrl(CHALLENGE_URL);
        // Not used: the challenge ID is taken from the verified flow.
        response.setChallengeId("start-challenge");
        response.setChallengeToken("start-token");
        return response;
    }

    private static AuthsignalResponse.Step step(String stepType) {

        return step(stepType, "EMAIL_OTP");
    }

    private static AuthsignalResponse.Step step(String stepType, String verificationMethod) {

        AuthsignalResponse.Step step = new AuthsignalResponse.Step();
        step.setStepType(stepType);
        step.setVerificationMethod(verificationMethod);
        // Matches the authenticator of the same method.
        step.setUserAuthenticatorId(verificationMethod);
        return step;
    }

    private static AuthsignalResponse.Authenticator authenticator(String method, String email, String phoneNumber) {

        AuthsignalResponse.Authenticator authenticator = new AuthsignalResponse.Authenticator();
        authenticator.setUserAuthenticatorId(method);
        authenticator.setVerificationMethod(method);
        authenticator.setEmail(email);
        authenticator.setPhoneNumber(phoneNumber);
        return authenticator;
    }

    private static AuthsignalResponse verified(String state, String userId, Object... stepsAndAuthenticators) {

        List<AuthsignalResponse.Step> steps = new ArrayList<>();
        List<AuthsignalResponse.Authenticator> authenticators = new ArrayList<>();
        for (Object item : stepsAndAuthenticators) {
            if (item instanceof AuthsignalResponse.Step) {
                steps.add((AuthsignalResponse.Step) item);
            } else {
                authenticators.add((AuthsignalResponse.Authenticator) item);
            }
        }
        AuthsignalResponse.Action action = new AuthsignalResponse.Action();
        action.setState(state);
        action.setCompletedSteps(steps);
        AuthsignalResponse.User user = new AuthsignalResponse.User();
        user.setUserId(userId);
        user.setAuthenticators(authenticators);
        AuthsignalResponse response = new AuthsignalResponse();
        response.setChallengeId("challenge-1");
        response.setAction(action);
        response.setUser(user);
        return response;
    }

    /**
     * Replaces server dependencies with test doubles.
     */
    private class TestableExecutor extends AuthsignalExecutor {

        @Override
        public ExecutorResponse execute(FlowExecutionContext context) throws FlowEngineException {

            // Add the context properties of the response as the flow engine does.
            ExecutorResponse response = super.execute(context);
            if (response.getContextProperties() != null) {
                context.addProperties(response.getContextProperties());
            }
            return response;
        }

        @Override
        protected AuthsignalConfig resolveConfig(String tenantDomain) {

            return new AuthsignalConfig(tenantProperties);
        }

        @Override
        protected AuthsignalClient createClient(AuthsignalConfig config) throws AuthsignalConnectionException {

            super.createClient(config);
            return client;
        }
    }

    private static void assertExecutorError(ExecutorResponse response, String message) {

        // The flow engine reports errors without an executor specific error code.
        assertNull(response.getErrorCode());
        assertEquals(response.getErrorMessage(), message);
    }

    private FlowEngineServerException assertServerError(FlowExecutionContext context, String description) {

        FlowEngineServerException e = expectThrows(FlowEngineServerException.class, () -> executor.execute(context));
        assertEquals(e.getErrorCode(), ERROR_CODE_EXECUTOR_FAILURE.getCode());
        assertEquals(e.getDescription(), description);
        return e;
    }

    private static void assertExecutorError(ExecutorResponse response, String message, String userId) {

        assertExecutorError(response, message + " User ID: " + userId);
    }
}
