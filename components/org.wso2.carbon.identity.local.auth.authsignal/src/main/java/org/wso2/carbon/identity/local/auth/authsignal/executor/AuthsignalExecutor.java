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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.flow.execution.engine.graph.Executor;
import org.wso2.carbon.identity.flow.execution.engine.metadata.FlowExecutorMetadata;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowUser;
import org.wso2.carbon.identity.flow.mgt.Constants.FlowTypes;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.local.auth.authsignal.AuthsignalAuthenticator;
import org.wso2.carbon.identity.local.auth.authsignal.client.AuthsignalClient;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.ErrorMessages;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.FlowState;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.StepType;
import org.wso2.carbon.identity.local.auth.authsignal.exception.AuthsignalClientException;
import org.wso2.carbon.identity.local.auth.authsignal.model.AuthsignalConfig;
import org.wso2.carbon.identity.local.auth.authsignal.model.FlowResponse;
import org.wso2.carbon.identity.local.auth.authsignal.model.StartFlowRequest;
import org.wso2.carbon.identity.local.auth.authsignal.util.AuthsignalConfigResolver;
import org.wso2.carbon.identity.local.auth.authsignal.util.AuthsignalUserIdResolver;
import org.wso2.carbon.identity.local.auth.authsignal.util.AuthsignalUserStoreUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_COMPLETE;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_ERROR;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_EXTERNAL_REDIRECTION;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_USER_ERROR;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.REDIRECT_URL;

/**
 * Flow executor that adds Authsignal Flows to registration, invited user registration, password recovery and secured
 * self-service operation (for example, profile update) flows.
 * <p>
 * In registration flows the WSO2 user does not exist yet, so the Authsignal flow is started with the email address
 * the user entered (or the mobile number, if there is no email address), and the mobile number as a hint. The user
 * verifies them in the pre-built UI. Once the WSO2 user is created,
 * {@link org.wso2.carbon.identity.local.auth.authsignal.listener.AuthsignalFlowExecutionListener} links the
 * Authsignal user to the WSO2 user ID with the challenge ID kept in the flow context. In other flows the user already
 * exists and the flow is started with the user's Authsignal user ID.
 * <p>
 * Secured self-service operations verify the signed-in user with the sign-in flow before the operation proceeds.
 * <p>
 * The executor puts its own one-time {@code code} and {@code state} in the redirect URL so the hosted portal can
 * resume the flow, and requires the portal to also post back the {@code challenge_token} Authsignal appends, which is
 * verified server side.
 * <p>
 * Like the Email OTP executor, it needs no connection: it implements {@code Executor} directly and declares no
 * associated authenticator. The flow management API reports an executor as requiring a connection when it extends
 * {@code AuthenticationExecutor} or has an associated authenticator, and the Console then asks for one.
 */
public class AuthsignalExecutor implements Executor {

    public static final String EXECUTOR_NAME = "AuthsignalExecutor";
    public static final String EXECUTOR_DESCRIPTION =
            "Verify the user with Authsignal.";

    // Flow types, as defined by org.wso2.carbon.identity.flow.mgt.Constants.FlowTypes.
    public static final String REGISTRATION = "REGISTRATION";
    public static final String INVITED_USER_REGISTRATION = "INVITED_USER_REGISTRATION";
    public static final String PASSWORD_RECOVERY = "PASSWORD_RECOVERY";
    // Self-service operations of a signed-in user that need verification, such as profile update.
    public static final String SECURED_SELF_SERVICE_OPERATIONS = "SECURED_SELF_SERVICE_OPERATIONS";

    // Inputs the hosted portal posts back after an external redirection.
    public static final String CODE_PARAM = "code";
    public static final String STATE_PARAM = "state";

    // Flow context property keys of a pending Authsignal flow.
    public static final String CONTEXT_PROP_USER_ID = "authsignal.flow.userId";
    public static final String CONTEXT_PROP_FLOW_REF = "authsignal.flow.flowRef";
    public static final String CONTEXT_PROP_STATE = "authsignal.flow.state";
    public static final String CONTEXT_PROP_CODE = "authsignal.flow.code";
    // Email address or phone number a registration flow was started with.
    public static final String CONTEXT_PROP_IDENTIFIER = "authsignal.flow.identifier";
    public static final String CONTEXT_PROP_PENDING_CHALLENGE_ID = "authsignal.flow.pendingChallengeId";
    /*
     * Challenge ID of a registration flow that succeeded. Used to identify the Authsignal user once the WSO2 user is
     * created.
     */
    public static final String CONTEXT_PROP_CHALLENGE_ID = "authsignal.flow.challengeId";
    /*
     * Whether the user of a registration flow that succeeded has a passkey on Authsignal. Saved on the user once the
     * WSO2 user is created.
     */
    public static final String CONTEXT_PROP_PASSKEY_ENROLLED = "authsignal.flow.passkeyEnrolled";

    private static final Log LOG = LogFactory.getLog(AuthsignalExecutor.class);

    private static final String[] PENDING_FLOW_PROPERTIES = {CONTEXT_PROP_USER_ID, CONTEXT_PROP_FLOW_REF,
            CONTEXT_PROP_STATE, CONTEXT_PROP_CODE, CONTEXT_PROP_IDENTIFIER, CONTEXT_PROP_PENDING_CHALLENGE_ID};

    @Override
    public String getName() {

        return EXECUTOR_NAME;
    }

    @Override
    public Set<FlowTypes> getSupportedFlowTypes() {

        Set<FlowTypes> flowTypes =
                EnumSet.of(FlowTypes.REGISTRATION, FlowTypes.INVITED_USER_REGISTRATION, FlowTypes.PASSWORD_RECOVERY);
        // Matched by name, as the flow type is not available in all framework versions.
        for (FlowTypes flowType : FlowTypes.values()) {
            if (SECURED_SELF_SERVICE_OPERATIONS.equals(flowType.name())) {
                flowTypes.add(flowType);
            }
        }
        return flowTypes;
    }

    @Override
    public FlowExecutorMetadata getExecutorMetadata() {

        return FlowExecutorMetadata.builder()
                .displayName(AuthsignalAuthenticator.AUTHENTICATOR_FRIENDLY_NAME)
                .description(EXECUTOR_DESCRIPTION)
                .connectionRequired(false)
                .build();
    }

    @Override
    public List<String> getInitiationData() {

        return Collections.emptyList();
    }

    @Override
    public ExecutorResponse execute(FlowExecutionContext context) {

        if (context.getProperty(CONTEXT_PROP_STATE) != null) {
            return processFlowResult(context);
        }
        return startFlow(context);
    }

    @Override
    public ExecutorResponse rollback(FlowExecutionContext context) {

        clearPendingFlow(context);
        removeProperty(context, CONTEXT_PROP_CHALLENGE_ID);
        removeProperty(context, CONTEXT_PROP_PASSKEY_ENROLLED);
        return null;
    }

    /**
     * Start the Authsignal flow of the flow type and redirect the user to the pre-built UI.
     */
    private ExecutorResponse startFlow(FlowExecutionContext context) {

        String flowType = context.getFlowType();
        if (!isSupportedFlowType(flowType)) {
            return errorResponse(STATUS_ERROR, ErrorMessages.ERROR_CODE_UNSUPPORTED_FLOW_TYPE,
                    String.format(ErrorMessages.ERROR_CODE_UNSUPPORTED_FLOW_TYPE.getMessage(), flowType), null);
        }
        String portalUrl = context.getPortalUrl();
        if (StringUtils.isBlank(portalUrl)) {
            return errorResponse(STATUS_ERROR, ErrorMessages.ERROR_CODE_PORTAL_URL_NOT_FOUND, null);
        }

        AuthsignalConfig config;
        try {
            config = resolveConfig(context.getTenantDomain());
        } catch (IdentityGovernanceException e) {
            return errorResponse(STATUS_ERROR, ErrorMessages.ERROR_CODE_READING_CONFIG, e);
        }
        if (StringUtils.isBlank(config.getSecretKey())) {
            return errorResponse(STATUS_ERROR, ErrorMessages.ERROR_CODE_SECRET_KEY_NOT_CONFIGURED, null);
        }

        String flowRef = getFlowRef(flowType, config);
        String state = UUID.randomUUID().toString();
        String code = UUID.randomUUID().toString();
        StartFlowRequest startRequest = new StartFlowRequest(flowRef)
                .setRedirectUrl(buildRedirectUrl(portalUrl, code, state));

        String authsignalUserId = null;
        String identifier = null;
        if (REGISTRATION.equals(flowType)) {
            // The WSO2 user does not exist yet: start the flow with the user's contact details and no user ID.
            FlowUser flowUser = getFlowUser(context);
            String email = getClaim(flowUser, AuthsignalConstants.EMAIL_CLAIM);
            String mobile = getE164Mobile(flowUser);
            if (email != null) {
                identifier = email;
                startRequest.setUserEmail(email).setHintPhoneNumber(mobile);
            } else if (mobile != null) {
                identifier = mobile;
                startRequest.setUserPhoneNumber(mobile);
            } else {
                return errorResponse(STATUS_USER_ERROR, ErrorMessages.ERROR_CODE_CONTACT_DETAILS_NOT_FOUND, null);
            }
        } else {
            try {
                authsignalUserId = resolveAuthsignalUserId(context, config);
            } catch (UserStoreException | RuntimeException e) {
                return errorResponse(STATUS_ERROR, ErrorMessages.ERROR_CODE_RESOLVING_USER_ID, e);
            }
            if (authsignalUserId == null) {
                // Reported generically to avoid user enumeration.
                return errorResponse(STATUS_USER_ERROR, ErrorMessages.ERROR_CODE_USER_NOT_IDENTIFIED, null);
            }
            startRequest.setUserId(authsignalUserId);
        }

        FlowResponse startResponse;
        try {
            startResponse = createClient(config).startFlow(startRequest);
        } catch (AuthsignalClientException e) {
            return errorResponse(STATUS_ERROR, ErrorMessages.ERROR_CODE_START_FLOW_FAILED, e);
        }
        if (StringUtils.isBlank(startResponse.getChallengeUrl())
                || (REGISTRATION.equals(flowType) && StringUtils.isBlank(startResponse.getChallengeId()))) {
            return errorResponse(STATUS_ERROR, ErrorMessages.ERROR_CODE_START_FLOW_FAILED,
                    "Authsignal did not return a challenge URL or challenge ID.", null);
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Started the Authsignal flow: " + flowRef + " in flow type: " + flowType);
        }

        context.setProperty(CONTEXT_PROP_FLOW_REF, flowRef);
        context.setProperty(CONTEXT_PROP_STATE, state);
        context.setProperty(CONTEXT_PROP_CODE, code);
        if (authsignalUserId != null) {
            context.setProperty(CONTEXT_PROP_USER_ID, authsignalUserId);
        }
        if (identifier != null) {
            context.setProperty(CONTEXT_PROP_IDENTIFIER, identifier);
            context.setProperty(CONTEXT_PROP_PENDING_CHALLENGE_ID, startResponse.getChallengeId());
        }

        ExecutorResponse response = newResponse(STATUS_EXTERNAL_REDIRECTION);
        Map<String, String> additionalInfo = new HashMap<>();
        additionalInfo.put(REDIRECT_URL, startResponse.getChallengeUrl());
        // The hosted portal maps the state to the flow ID so it can resume the flow on return.
        additionalInfo.put(STATE_PARAM, state);
        response.setAdditionalInfo(additionalInfo);
        response.setRequiredData(Arrays.asList(CODE_PARAM, STATE_PARAM, AuthsignalConstants.CHALLENGE_TOKEN_PARAM));
        return response;
    }

    /**
     * Handle the return from the pre-built UI. The returned {@code code} and {@code state} prove the request belongs
     * to this flow, and the {@code challenge_token} is verified on Authsignal.
     */
    private ExecutorResponse processFlowResult(FlowExecutionContext context) {

        String expectedState = (String) context.getProperty(CONTEXT_PROP_STATE);
        String expectedCode = (String) context.getProperty(CONTEXT_PROP_CODE);
        String expectedUserId = (String) context.getProperty(CONTEXT_PROP_USER_ID);
        String flowRef = (String) context.getProperty(CONTEXT_PROP_FLOW_REF);
        String identifier = (String) context.getProperty(CONTEXT_PROP_IDENTIFIER);
        String challengeId = (String) context.getProperty(CONTEXT_PROP_PENDING_CHALLENGE_ID);
        // A flow result can only be consumed once.
        clearPendingFlow(context);

        Map<String, String> inputs = context.getUserInputData();
        String state = inputs != null ? inputs.get(STATE_PARAM) : null;
        String code = inputs != null ? inputs.get(CODE_PARAM) : null;
        String challengeToken = inputs != null ? inputs.get(AuthsignalConstants.CHALLENGE_TOKEN_PARAM) : null;
        if (!constantTimeEquals(expectedState, state) || !constantTimeEquals(expectedCode, code)
                || StringUtils.isBlank(flowRef)) {
            return errorResponse(STATUS_USER_ERROR, ErrorMessages.ERROR_CODE_INVALID_CALLBACK, null);
        }
        if (StringUtils.isBlank(challengeToken)) {
            return errorResponse(STATUS_USER_ERROR, ErrorMessages.ERROR_CODE_MISSING_TOKEN, null);
        }

        AuthsignalConfig config;
        FlowResponse result;
        try {
            config = resolveConfig(context.getTenantDomain());
            result = createClient(config).verifyFlow(flowRef, challengeToken);
        } catch (IdentityGovernanceException e) {
            return errorResponse(STATUS_ERROR, ErrorMessages.ERROR_CODE_READING_CONFIG, e);
        } catch (AuthsignalClientException e) {
            return errorResponse(STATUS_ERROR, ErrorMessages.ERROR_CODE_VERIFY_FLOW_FAILED, e);
        }

        if (!FlowState.CHALLENGE_SUCCEEDED.equals(result.getState())) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Authsignal flow is in state: " + result.getState());
            }
            return errorResponse(STATUS_USER_ERROR, ErrorMessages.ERROR_CODE_CHALLENGE_NOT_SUCCEEDED, null);
        }

        String flowType = context.getFlowType();
        if (REGISTRATION.equals(flowType)) {
            // Before the user is identified, Authsignal returns a temporary user ID, so the flow is bound to the
            // email address or phone number it was started with instead.
            if (!isVerifiedIdentifier(result.getUser(), identifier) || StringUtils.isBlank(challengeId)) {
                return errorResponse(STATUS_USER_ERROR, ErrorMessages.ERROR_CODE_CHALLENGE_MISMATCH, null);
            }
            context.setProperty(CONTEXT_PROP_CHALLENGE_ID, challengeId);
            // The WSO2 user does not exist yet, so the claim is saved once the user is created.
            context.setProperty(CONTEXT_PROP_PASSKEY_ENROLLED, result.hasPasskey());
        } else {
            String verifiedUserId = result.getUser() != null ? result.getUser().getUserId() : null;
            if (StringUtils.isBlank(expectedUserId) || !StringUtils.equals(expectedUserId, verifiedUserId)) {
                return errorResponse(STATUS_USER_ERROR, ErrorMessages.ERROR_CODE_CHALLENGE_MISMATCH, null);
            }
            // The pre-built UI can let an unenrolled user enrol a new authenticator. In password recovery and secured
            // self-service operations that would let whoever started the flow (or holds the user's session) enrol
            // their own authenticator and pass the check, so only verifications with authenticators the user already
            // had are accepted.
            if (requiresEnrolledAuthenticators(flowType) && !isVerifiedWithEnrolledAuthenticators(result)) {
                return errorResponse(STATUS_USER_ERROR, ErrorMessages.ERROR_CODE_USER_NOT_ENROLLED, null);
            }
            FlowUser flowUser = getFlowUser(context);
            String username = StringUtils.trimToNull(flowUser.getUsername());
            if (username != null) {
                AuthsignalUserStoreUtil.savePasskeyEnrolledClaim(config, context.getTenantDomain(),
                        IdentityUtil.addDomainToName(UserCoreUtil.removeDomainFromName(username),
                                flowUser.getUserStoreDomain()), result.hasPasskey());
            }
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Authsignal flow: " + flowRef + " succeeded in flow type: " + flowType);
        }
        return newResponse(STATUS_COMPLETE);
    }

    /**
     * Resolve the Authsignal user ID of an existing flow user.
     *
     * @return The ID, or null if the user does not exist.
     */
    protected String resolveAuthsignalUserId(FlowExecutionContext context, AuthsignalConfig config)
            throws UserStoreException {

        String tenantDomain = context.getTenantDomain();
        FlowUser flowUser = getFlowUser(context);
        String username = StringUtils.trimToNull(flowUser.getUsername());
        if (username == null) {
            return null;
        }
        String userStoreDomain = flowUser.getUserStoreDomain();
        String userId = StringUtils.isNotBlank(flowUser.getUserId()) ? flowUser.getUserId()
                : getUserId(tenantDomain, userStoreDomain, username);
        if (StringUtils.isBlank(userId)) {
            return null;
        }
        return AuthsignalUserIdResolver.toAuthsignalUserId(config, () -> userId, username, userStoreDomain,
                tenantDomain);
    }

    protected String getUserId(String tenantDomain, String userStoreDomain, String username)
            throws UserStoreException {

        return AuthsignalUserIdResolver.getUserId(tenantDomain, userStoreDomain, username);
    }

    protected AuthsignalConfig resolveConfig(String tenantDomain) throws IdentityGovernanceException {

        return AuthsignalConfigResolver.resolve(tenantDomain);
    }

    protected AuthsignalClient createClient(AuthsignalConfig config) throws AuthsignalClientException {

        return AuthsignalClient.forConfig(config);
    }

    /**
     * Check that the email address or phone number a registration flow was started with is among the user's
     * verified authenticators.
     */
    private static boolean isVerifiedIdentifier(FlowResponse.User user, String identifier) {

        if (user == null || identifier == null) {
            return false;
        }
        return identifier.equalsIgnoreCase(user.getVerifiedEmail())
                || identifier.equals(user.getVerifiedPhoneNumber());
    }

    /**
     * Check that the user completed at least one step and that every step verified an authenticator the user already
     * had, rather than enrolled a new one.
     */
    private static boolean isVerifiedWithEnrolledAuthenticators(FlowResponse result) {

        List<FlowResponse.Step> steps = result.getAction().getCompletedSteps();
        if (steps.isEmpty()) {
            return false;
        }
        for (FlowResponse.Step step : steps) {
            if (!StepType.VERIFICATION_REQUIRED.equals(step.getStepType())) {
                return false;
            }
        }
        return true;
    }

    /**
     * Get the mobile number entered by the user, if it is in the E.164 format Authsignal expects.
     */
    private static String getE164Mobile(FlowUser flowUser) {

        String mobile = getClaim(flowUser, AuthsignalConstants.MOBILE_CLAIM);
        return mobile != null && mobile.startsWith("+") ? mobile : null;
    }

    private static String getClaim(FlowUser flowUser, String claimUri) {

        Object value = flowUser.getClaim(claimUri);
        return value != null ? StringUtils.trimToNull(String.valueOf(value)) : null;
    }

    private static FlowUser getFlowUser(FlowExecutionContext context) {

        return context.getFlowUser() != null ? context.getFlowUser() : new FlowUser();
    }

    private static String getFlowRef(String flowType, AuthsignalConfig config) {

        if (PASSWORD_RECOVERY.equals(flowType)) {
            return config.getRecoveryFlowRef();
        }
        if (SECURED_SELF_SERVICE_OPERATIONS.equals(flowType)) {
            // Verifies an existing user with the authenticators they have, like sign-in.
            return config.getSignInFlowRef();
        }
        return config.getRegistrationFlowRef();
    }

    private static boolean isSupportedFlowType(String flowType) {

        return REGISTRATION.equals(flowType) || INVITED_USER_REGISTRATION.equals(flowType)
                || PASSWORD_RECOVERY.equals(flowType) || SECURED_SELF_SERVICE_OPERATIONS.equals(flowType);
    }

    private static boolean requiresEnrolledAuthenticators(String flowType) {

        return PASSWORD_RECOVERY.equals(flowType) || SECURED_SELF_SERVICE_OPERATIONS.equals(flowType);
    }

    /**
     * Append the executor's {@code code} and {@code state} to the portal URL. Authsignal appends its own
     * {@code challenge_token} parameter to this URL.
     */
    static String buildRedirectUrl(String portalUrl, String code, String state) {

        int fragmentIndex = portalUrl.indexOf('#');
        String base = fragmentIndex >= 0 ? portalUrl.substring(0, fragmentIndex) : portalUrl;
        String separator = base.contains("?") ? (base.endsWith("?") || base.endsWith("&") ? "" : "&") : "?";
        return base + separator + CODE_PARAM + "=" + encode(code) + "&" + STATE_PARAM + "="
                + encode(state);
    }

    private static String encode(String value) {

        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static boolean constantTimeEquals(String expected, String actual) {

        if (expected == null || actual == null) {
            return false;
        }
        return MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                actual.getBytes(StandardCharsets.UTF_8));
    }

    private static void clearPendingFlow(FlowExecutionContext context) {

        for (String property : PENDING_FLOW_PROPERTIES) {
            removeProperty(context, property);
        }
    }

    private static void removeProperty(FlowExecutionContext context, String property) {

        if (context.getProperties() != null) {
            context.getProperties().remove(property);
        }
    }

    private static ExecutorResponse newResponse(String status) {

        // Only the no-argument constructor initializes the error details.
        ExecutorResponse response = new ExecutorResponse();
        response.setResult(status);
        return response;
    }

    private static ExecutorResponse errorResponse(String status, ErrorMessages error, Throwable cause) {

        return errorResponse(status, error, error.getMessage(), cause);
    }

    private static ExecutorResponse errorResponse(String status, ErrorMessages error, String message,
                                                  Throwable cause) {

        if (cause != null) {
            LOG.error(error.getCode() + " - " + message, cause);
        } else if (LOG.isDebugEnabled()) {
            LOG.debug(error.getCode() + " - " + message);
        }
        ExecutorResponse response = newResponse(status);
        response.setErrorCode(error.getCode());
        response.setErrorMessage(message);
        response.setErrorDescription(message);
        if (cause != null) {
            response.setThrowable(cause);
        }
        return response;
    }
}
