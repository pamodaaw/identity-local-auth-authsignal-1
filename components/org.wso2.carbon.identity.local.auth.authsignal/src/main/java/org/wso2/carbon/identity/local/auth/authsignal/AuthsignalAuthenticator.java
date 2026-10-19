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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AdditionalData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.local.auth.authsignal.client.AuthsignalClient;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.ErrorMessages;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.FlowState;
import org.wso2.carbon.identity.local.auth.authsignal.exception.AuthsignalClientException;
import org.wso2.carbon.identity.local.auth.authsignal.model.AuthsignalConfig;
import org.wso2.carbon.identity.local.auth.authsignal.model.FlowResponse;
import org.wso2.carbon.identity.local.auth.authsignal.model.StartFlowRequest;
import org.wso2.carbon.identity.local.auth.authsignal.util.AuthsignalConfigResolver;
import org.wso2.carbon.identity.local.auth.authsignal.util.AuthsignalUserIdResolver;
import org.wso2.carbon.identity.local.auth.authsignal.util.AuthsignalUserStoreUtil;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.io.IOException;
import java.util.Collections;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Local authenticator that adds Authsignal MFA to a WSO2 Identity Server login flow using Authsignal Flows.
 * <p>
 * The authenticator must be placed after a step that identifies the user. It:
 * <ol>
 *     <li>Starts the sign-in flow on Authsignal for the user, identified by the user's Authsignal user ID, with the
 *     WSO2 {@code /commonauth} endpoint as the redirect URL.</li>
 *     <li>Redirects the user to the Authsignal pre-built UI, where the steps configured for the flow run.</li>
 *     <li>When the user returns with the {@code challenge_token} query parameter, verifies the flow server side and
 *     completes the step only if the flow succeeded for the same user. Whether the user has a passkey on
 *     Authsignal is then saved in the user's passkey enrolled claim.</li>
 * </ol>
 * <p>
 * App-native (API based) authentication is supported as a redirection prompt: the {@code /oauth2/authn} response
 * carries the pre-built UI URL, Authsignal redirects back to the application's {@code redirect_uri}, and the
 * application posts the {@code challenge_token} it receives there as the authenticator parameter.
 */
public class AuthsignalAuthenticator extends AbstractApplicationAuthenticator
        implements LocalApplicationAuthenticator {

    private static final long serialVersionUID = 4127094857123698412L;
    private static final Log LOG = LogFactory.getLog(AuthsignalAuthenticator.class);

    public static final String AUTHENTICATOR_NAME = "AuthsignalAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Authsignal";
    public static final String AUTHENTICATOR_I18N_KEY = "authenticator.authsignal";
    // Groups Authsignal with the other MFA options in the Console.
    public static final String AUTHENTICATOR_TAG_MFA = "MFA";

    // Request parameters.
    public static final String SESSION_DATA_KEY = "sessionDataKey";
    public static final String USER_AGENT_HEADER = "User-Agent";

    // Authentication context property keys of a pending flow.
    public static final String CONTEXT_PROP_AUTHSIGNAL_USER_ID = "authsignal.userId";
    public static final String CONTEXT_PROP_FLOW_REF = "authsignal.flowRef";
    // Pre-built UI URL of the pending flow, returned to API based clients as the URL to open.
    public static final String CONTEXT_PROP_CHALLENGE_URL = "authsignal.challengeUrl";

    @Override
    public String getName() {

        return AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {

        return AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getI18nKey() {

        return AUTHENTICATOR_I18N_KEY;
    }

    @Override
    public String[] getTags() {

        return new String[]{AUTHENTICATOR_TAG_MFA};
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        return request.getParameter(SESSION_DATA_KEY);
    }

    @Override
    public boolean canHandle(HttpServletRequest request) {

        return StringUtils.isNotBlank(request.getParameter(AuthsignalConstants.CHALLENGE_TOKEN_PARAM));
    }

    @Override
    public boolean isAPIBasedAuthenticationSupported() {

        return true;
    }

    /**
     * Describe the pending flow to API based clients: open the pre-built UI URL, then post back the
     * {@code challenge_token} Authsignal appends to the application's redirect URI.
     */
    @Override
    public Optional<AuthenticatorData> getAuthInitiationData(AuthenticationContext context) {

        AuthenticatorData authenticatorData = new AuthenticatorData();
        authenticatorData.setName(getName());
        authenticatorData.setDisplayName(getFriendlyName());
        authenticatorData.setI18nKey(getI18nKey());
        if (context.getExternalIdP() != null) {
            authenticatorData.setIdp(context.getExternalIdP().getIdPName());
        }
        authenticatorData.setPromptType(FrameworkConstants.AuthenticatorPromptType.REDIRECTION_PROMPT);
        authenticatorData.setRequiredParams(Collections.singletonList(AuthsignalConstants.CHALLENGE_TOKEN_PARAM));
        AdditionalData additionalData = new AdditionalData();
        additionalData.setRedirectUrl((String) context.getProperty(CONTEXT_PROP_CHALLENGE_URL));
        authenticatorData.setAdditionalData(additionalData);
        return Optional.of(authenticatorData);
    }

    @Override
    protected boolean retryAuthenticationEnabled() {

        // A failed Authsignal flow must fail the login rather than silently starting another flow.
        return false;
    }

    @Override
    protected boolean retryAuthenticationEnabled(AuthenticationContext context) {

        return false;
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        }

        // The user is returning from the Authsignal pre-built UI for a flow this login started.
        if (isFlowCallback(request, context)) {
            return super.process(request, response, context);
        }

        startSignInFlow(request, response, context);
        return AuthenticatorFlowStatus.INCOMPLETE;
    }

    /**
     * Not reached in practice: {@link #process} handles initiation itself, and retry is disabled.
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        startSignInFlow(request, response, context);
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        AuthenticatedUser user = getAuthenticatedUserFromContext(context);
        if (user == null) {
            throw failure(ErrorMessages.ERROR_CODE_NO_AUTHENTICATED_USER, null);
        }

        String challengeToken = request.getParameter(AuthsignalConstants.CHALLENGE_TOKEN_PARAM);
        if (StringUtils.isBlank(challengeToken)) {
            throw failure(ErrorMessages.ERROR_CODE_MISSING_TOKEN, user);
        }

        String expectedUserId = (String) context.getProperty(CONTEXT_PROP_AUTHSIGNAL_USER_ID);
        String flowRef = (String) context.getProperty(CONTEXT_PROP_FLOW_REF);
        // A flow result can only be consumed once.
        context.removeProperty(CONTEXT_PROP_AUTHSIGNAL_USER_ID);
        context.removeProperty(CONTEXT_PROP_FLOW_REF);
        context.removeProperty(CONTEXT_PROP_CHALLENGE_URL);

        AuthsignalConfig config = getAuthsignalConfig(context);
        FlowResponse result;
        try {
            result = createClient(config).verifyFlow(flowRef, challengeToken);
        } catch (AuthsignalClientException e) {
            throw failure(ErrorMessages.ERROR_CODE_VERIFY_FLOW_FAILED, user, e);
        }

        if (!FlowState.CHALLENGE_SUCCEEDED.equals(result.getState())) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Authsignal flow verification returned state: " + result.getState());
            }
            throw failure(ErrorMessages.ERROR_CODE_CHALLENGE_NOT_SUCCEEDED, user);
        }

        // Bind the token to the user of this authentication context to prevent token swapping.
        String verifiedUserId = result.getUser() != null ? result.getUser().getUserId() : null;
        if (StringUtils.isBlank(expectedUserId) || !StringUtils.equals(expectedUserId, verifiedUserId)) {
            throw failure(ErrorMessages.ERROR_CODE_CHALLENGE_MISMATCH, user);
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Authsignal sign-in flow succeeded.");
        }
        // Federated users have no local profile to update.
        if (!user.isFederatedUser() && StringUtils.isNotBlank(user.getUserName())) {
            AuthsignalUserStoreUtil.savePasskeyEnrolledClaim(config, user.getTenantDomain(),
                    UserCoreUtil.addDomainToName(user.getUserName(), user.getUserStoreDomain()), result.hasPasskey());
        }
        context.setSubject(new AuthenticatedUser(user));
    }

    /**
     * Start the sign-in flow on Authsignal and redirect the user to the pre-built UI.
     */
    private void startSignInFlow(HttpServletRequest request, HttpServletResponse response,
                                 AuthenticationContext context) throws AuthenticationFailedException {

        AuthenticatedUser user = getAuthenticatedUserFromContext(context);
        if (user == null) {
            throw failure(ErrorMessages.ERROR_CODE_NO_AUTHENTICATED_USER, null);
        }

        AuthsignalConfig config = getAuthsignalConfig(context);
        String authsignalUserId = resolveAuthsignalUserId(user, config);
        String flowRef = config.getSignInFlowRef();

        StartFlowRequest startRequest = new StartFlowRequest(flowRef)
                .setUserId(authsignalUserId)
                .setRedirectUrl(resolveRedirectUrl(context))
                .setIpAddress(IdentityUtil.getClientIpAddress(request))
                .setUserAgent(request.getHeader(USER_AGENT_HEADER));

        FlowResponse startResponse;
        try {
            startResponse = createClient(config).startFlow(startRequest);
        } catch (AuthsignalClientException e) {
            throw failure(ErrorMessages.ERROR_CODE_START_FLOW_FAILED, user, e);
        }
        if (StringUtils.isBlank(startResponse.getChallengeUrl())) {
            throw new AuthenticationFailedException(ErrorMessages.ERROR_CODE_START_FLOW_FAILED.getCode(),
                    "Authsignal did not return a challenge URL.", user);
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Started the Authsignal flow: " + flowRef + ". Redirecting the user to the pre-built UI.");
        }

        context.setCurrentAuthenticator(getName());
        context.setProperty(CONTEXT_PROP_AUTHSIGNAL_USER_ID, authsignalUserId);
        context.setProperty(CONTEXT_PROP_FLOW_REF, flowRef);
        context.setProperty(CONTEXT_PROP_CHALLENGE_URL, startResponse.getChallengeUrl());
        // In API based flows the response is not sent to a browser; the client reads the URL from the auth
        // initiation data instead.
        try {
            response.sendRedirect(startResponse.getChallengeUrl());
        } catch (IOException e) {
            throw failure(ErrorMessages.ERROR_CODE_REDIRECTING, user, e);
        }
    }

    private boolean isFlowCallback(HttpServletRequest request, AuthenticationContext context) {

        // REQ_ATTR_HANDLED is set when a previous step already consumed this request in the same round trip.
        return canHandle(request)
                && context.getProperty(CONTEXT_PROP_FLOW_REF) != null
                && !Boolean.TRUE.equals(request.getAttribute(FrameworkConstants.REQ_ATTR_HANDLED));
    }

    /**
     * Resolve the URL Authsignal redirects the user back to after the flow: the application's redirect URI in API
     * based flows, so the application can read the {@code challenge_token} and post it to {@code /oauth2/authn}, and
     * the {@code /commonauth} endpoint otherwise.
     */
    protected String resolveRedirectUrl(AuthenticationContext context) throws AuthenticationFailedException {

        if (Boolean.parseBoolean(String.valueOf(context.getProperty(FrameworkConstants.IS_API_BASED)))) {
            String applicationRedirectUrl = (String) context.getProperty(FrameworkConstants.REDIRECT_URL);
            if (StringUtils.isNotBlank(applicationRedirectUrl)) {
                return applicationRedirectUrl;
            }
        }
        return buildCallbackUrl(context);
    }

    /**
     * Build the URL Authsignal redirects the user back to after the flow. Authsignal appends the
     * {@code challenge_token} query parameter to it.
     */
    protected String buildCallbackUrl(AuthenticationContext context) throws AuthenticationFailedException {

        try {
            return ServiceURLBuilder.create()
                    .addPath(FrameworkConstants.COMMONAUTH)
                    .addParameter(SESSION_DATA_KEY, context.getContextIdentifier())
                    .build()
                    .getAbsolutePublicURL();
        } catch (URLBuilderException e) {
            throw failure(ErrorMessages.ERROR_CODE_BUILDING_CALLBACK_URL, null, e);
        }
    }

    protected AuthsignalClient createClient(AuthsignalConfig config) throws AuthenticationFailedException {

        try {
            return AuthsignalClient.forConfig(config);
        } catch (AuthsignalClientException e) {
            throw new AuthenticationFailedException(e.getErrorCode(), e.getMessage(), e);
        }
    }

    /**
     * Build the configuration from the governance connector properties of the tenant the authentication request
     * belongs to.
     */
    protected AuthsignalConfig getAuthsignalConfig(AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            return AuthsignalConfigResolver.resolve(context.getTenantDomain());
        } catch (IdentityGovernanceException e) {
            throw failure(ErrorMessages.ERROR_CODE_READING_CONFIG, null, e);
        }
    }

    /**
     * Map the WSO2 user to the user ID known to Authsignal.
     */
    protected String resolveAuthsignalUserId(AuthenticatedUser user, AuthsignalConfig config)
            throws AuthenticationFailedException {

        if (user.isFederatedUser()) {
            return user.getAuthenticatedSubjectIdentifier();
        }
        try {
            return AuthsignalUserIdResolver.toAuthsignalUserId(config, user::getUserId, user.getUserName(),
                    user.getUserStoreDomain(), user.getTenantDomain());
        } catch (UserIdNotFoundException e) {
            throw failure(ErrorMessages.ERROR_CODE_RESOLVING_USER_ID, user, e);
        } catch (IllegalStateException e) {
            throw new AuthenticationFailedException(ErrorMessages.ERROR_CODE_INVALID_USER_IDENTIFIER.getCode(),
                    e.getMessage(), user);
        }
    }

    /**
     * Get the user identified by a previous step.
     */
    private AuthenticatedUser getAuthenticatedUserFromContext(AuthenticationContext context) {

        if (context.getSequenceConfig() != null && context.getSequenceConfig().getStepMap() != null) {
            for (StepConfig stepConfig : context.getSequenceConfig().getStepMap().values()) {
                AuthenticatedUser user = stepConfig.getAuthenticatedUser();
                if (stepConfig.isSubjectAttributeStep() && user != null && user.getUserName() != null) {
                    return user;
                }
            }
        }
        AuthenticatedUser lastAuthenticatedUser = context.getLastAuthenticatedUser();
        if (lastAuthenticatedUser != null && lastAuthenticatedUser.getUserName() != null) {
            return lastAuthenticatedUser;
        }
        return null;
    }

    private static AuthenticationFailedException failure(ErrorMessages error, AuthenticatedUser user) {

        return new AuthenticationFailedException(error.getCode(), error.getMessage(), user);
    }

    private static AuthenticationFailedException failure(ErrorMessages error, AuthenticatedUser user,
                                                         Throwable cause) {

        return new AuthenticationFailedException(error.getCode(), error.getMessage(), user, cause);
    }
}
