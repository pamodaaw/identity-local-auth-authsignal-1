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
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.local.auth.authsignal.client.AuthsignalClient;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.ActionState;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.AuthContextProps;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.ErrorMessages;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.LogConstants.Messages;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.RequestParams;
import org.wso2.carbon.identity.local.auth.authsignal.exception.AuthsignalConnectionException;
import org.wso2.carbon.identity.local.auth.authsignal.model.AuthsignalConfig;
import org.wso2.carbon.identity.local.auth.authsignal.model.AuthsignalRequest;
import org.wso2.carbon.identity.local.auth.authsignal.model.AuthsignalResponse;
import org.wso2.carbon.identity.local.auth.authsignal.util.AuthsignalDiagnosticLogUtil;
import org.wso2.carbon.identity.local.auth.authsignal.util.AuthsignalUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.LogConstants.ActionIDs.LINK_AUTHSIGNAL_USER;
import static org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.LogConstants.ActionIDs.START_AUTHSIGNAL_FLOW;
import static org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.LogConstants.ActionIDs.VERIFY_AUTHSIGNAL_FLOW;

/**
 * Local authenticator that adds Authsignal MFA to the login flow.
 * <p>
 * Place it after a step that identifies the user. It starts an Authsignal flow, sends the user to the Authsignal
 * pre-built UI, and verifies the result when the user comes back.
 */
public class AuthsignalAuthenticator extends AbstractApplicationAuthenticator
        implements LocalApplicationAuthenticator {

    private static final long serialVersionUID = 4127094857123698412L;
    private static final Log LOG = LogFactory.getLog(AuthsignalAuthenticator.class);

    @Override
    public String getName() {

        return AuthsignalConstants.AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {

        return AuthsignalConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getI18nKey() {

        return AuthsignalConstants.AUTHENTICATOR_I18N_KEY;
    }

    @Override
    public String[] getTags() {

        return new String[]{AuthsignalConstants.AUTHENTICATOR_TAG_MFA};
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        return request.getParameter(RequestParams.SESSION_DATA_KEY);
    }

    @Override
    public boolean canHandle(HttpServletRequest request) {

        return StringUtils.isNotBlank(request.getParameter(RequestParams.CHALLENGE_TOKEN));
    }

    @Override
    public boolean isAPIBasedAuthenticationSupported() {

        return true;
    }

    /**
     * Give API based clients the pre-built UI URL to open.
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
        authenticatorData.setRequiredParams(Collections.singletonList(RequestParams.CHALLENGE_TOKEN));
        AdditionalData additionalData = new AdditionalData();
        additionalData.setRedirectUrl((String) context.getProperty(AuthContextProps.CHALLENGE_URL));
        authenticatorData.setAdditionalData(additionalData);
        return Optional.of(authenticatorData);
    }

    @Override
    protected boolean retryAuthenticationEnabled() {

        // Fail the login when the Authsignal flow fails.
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

        // The user is back from the Authsignal pre-built UI.
        boolean isFlowCallback = isFlowCallback(request, context);
        // Read before the callback clears it.
        String actionCode = isFlowCallback ? (String) context.getProperty(AuthContextProps.ACTION_CODE) : null;
        try {
            if (isFlowCallback) {
                return super.process(request, response, context);
            }
            startSignInFlow(request, response, context);
            return AuthenticatorFlowStatus.INCOMPLETE;
        } catch (AuthenticationFailedException e) {
            AuthsignalDiagnosticLogUtil.triggerFailureLog(isFlowCallback ? VERIFY_AUTHSIGNAL_FLOW
                    : START_AUTHSIGNAL_FLOW, e.getMessage(), e, () -> logInputs(context,
                    getAuthenticatedUserFromContext(context), actionCode));
            throw e;
        }
    }

    /**
     * Not used, as {@link #process} starts the flow itself.
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
            throw handleFailure(ErrorMessages.ERROR_CODE_NO_AUTHENTICATED_USER, null);
        }

        String challengeToken = request.getParameter(RequestParams.CHALLENGE_TOKEN);
        if (StringUtils.isBlank(challengeToken)) {
            throw handleFailure(ErrorMessages.ERROR_CODE_MISSING_TOKEN, user);
        }

        String actionCode = (String) context.getProperty(AuthContextProps.ACTION_CODE);
        // Clear the flow so that it can be used only once.
        context.removeProperty(AuthContextProps.ACTION_CODE);
        context.removeProperty(AuthContextProps.CHALLENGE_URL);

        AuthsignalConfig config = getAuthsignalConfig(context);
        AuthsignalResponse result;
        try {
            result = createClient(config).verifyFlow(actionCode, challengeToken);
        } catch (AuthsignalConnectionException e) {
            throw handleFailure(ErrorMessages.ERROR_CODE_VERIFY_FLOW_FAILED, user, e);
        }
        AuthsignalDiagnosticLogUtil.triggerSuccessLog(VERIFY_AUTHSIGNAL_FLOW, Messages.FLOW_RESULT_RECEIVED,
                () -> AuthsignalDiagnosticLogUtil.addFlowResult(logInputs(context, user, actionCode), result));
        if (!ActionState.CHALLENGE_SUCCEEDED.equals(result.getState())) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Authsignal flow verification returned state: " + result.getState());
            }
            throw handleFailure(ErrorMessages.ERROR_CODE_CHALLENGE_NOT_SUCCEEDED, user);
        }

        // Make sure the flow belongs to the same user.
        String expectedUserId = resolveAuthsignalUserId(user);
        String verifiedUserId = result.getUser() != null ? result.getUser().getUserId() : null;
        if (StringUtils.isBlank(expectedUserId) || !StringUtils.equals(expectedUserId, verifiedUserId)) {
            throw handleFailure(ErrorMessages.ERROR_CODE_CHALLENGE_MISMATCH, user);
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Authsignal sign-in flow succeeded.");
        }
        AuthsignalDiagnosticLogUtil.triggerSuccessLog(VERIFY_AUTHSIGNAL_FLOW, Messages.VERIFICATION_COMPLETED,
                () -> logInputs(context, user, actionCode));
        // Federated users have no local profile to update.
        if (!user.isFederatedUser() && StringUtils.isNotBlank(user.getUserName())) {
            AuthsignalUtil.savePasskeyEnrolledClaim(config, user.getTenantDomain(),
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
            throw handleFailure(ErrorMessages.ERROR_CODE_NO_AUTHENTICATED_USER, null);
        }

        AuthsignalConfig config = getAuthsignalConfig(context);
        String authsignalUserId = resolveAuthsignalUserId(user);
        if (!user.isFederatedUser()) {
            completePendingLink(config, user, authsignalUserId, context);
        }
        String actionCode = config.getActionCode();

        AuthsignalRequest startRequest = new AuthsignalRequest(actionCode)
                .setUserId(authsignalUserId)
                .setRedirectUrl(resolveRedirectUrl(context))
                .setIpAddress(IdentityUtil.getClientIpAddress(request))
                .setUserAgent(request.getHeader(AuthsignalConstants.USER_AGENT_HEADER));

        AuthsignalResponse startResponse;
        try {
            startResponse = createClient(config).startFlow(startRequest);
        } catch (AuthsignalConnectionException e) {
            throw handleFailure(ErrorMessages.ERROR_CODE_START_FLOW_FAILED, user, e);
        }
        AuthsignalDiagnosticLogUtil.triggerSuccessLog(START_AUTHSIGNAL_FLOW, Messages.FLOW_STARTED,
                () -> logInputs(context, user, actionCode));
        if (StringUtils.isBlank(startResponse.getChallengeUrl())) {
            throw new AuthenticationFailedException(ErrorMessages.ERROR_CODE_START_FLOW_FAILED.getCode(),
                    "Authsignal did not return a challenge URL when starting the flow.", user);
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Started the Authsignal flow: " + actionCode + ". Redirecting the user to the pre-built UI.");
        }

        context.setCurrentAuthenticator(getName());
        context.setProperty(AuthContextProps.ACTION_CODE, actionCode);
        context.setProperty(AuthContextProps.CHALLENGE_URL, startResponse.getChallengeUrl());
        // API based clients get the URL from the auth initiation data instead.
        try {
            response.sendRedirect(startResponse.getChallengeUrl());
        } catch (IOException e) {
            throw handleFailure(ErrorMessages.ERROR_CODE_REDIRECTING, user, e);
        }
    }

    /**
     * Link the user to the Authsignal user of their registration, if that could not be done when the user registered.
     * Once linked, the verified contact details and the passkey status are saved as at registration. Errors are logged
     * and never fail the sign-in.
     */
    private void completePendingLink(AuthsignalConfig config, AuthenticatedUser user, String authsignalUserId,
                                     AuthenticationContext context) {

        String tenantDomain = user.getTenantDomain();
        String username = UserCoreUtil.addDomainToName(user.getUserName(), user.getUserStoreDomain());
        String challengeId;
        try {
            challengeId = AuthsignalUtil.getUserClaim(tenantDomain, username,
                    AuthsignalConstants.CHALLENGE_ID_CLAIM);
        } catch (UserStoreException | RuntimeException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Unable to read the pending Authsignal link of the user.", e);
            }
            return;
        }
        if (StringUtils.isBlank(challengeId)) {
            return;
        }

        Map<String, String> claims = new HashMap<>();
        try {
            claims = AuthsignalUtil.syncUserIdToAuthsignal(createClient(config), config, authsignalUserId, challengeId,
                    AuthsignalUtil.getUserClaim(tenantDomain, username, AuthsignalConstants.EMAIL_CLAIM),
                    AuthsignalUtil.getUserClaim(tenantDomain, username, AuthsignalConstants.MOBILE_CLAIM));
            if (LOG.isDebugEnabled()) {
                LOG.debug("Completed the pending Authsignal link of the user in the tenant: " + tenantDomain);
            }
            Map<String, String> linkedClaims = claims;
            AuthsignalDiagnosticLogUtil.triggerSuccessLog(LINK_AUTHSIGNAL_USER, Messages.USER_LINKED,
                    () -> AuthsignalDiagnosticLogUtil.addUpdatedClaims(logInputs(context, user, null), linkedClaims));
        } catch (AuthsignalConnectionException e) {
            if (e.isTransient()) {
                LOG.warn("Failed to complete the pending Authsignal link of the user in the tenant: " + tenantDomain
                        + ". It will be retried at the next sign-in.");
                AuthsignalDiagnosticLogUtil.triggerFailureLog(LINK_AUTHSIGNAL_USER, Messages.LINK_FAILED_RETRIED, e,
                        () -> logInputs(context, user, null));
                return;
            }
            // Authsignal rejected the link, for example the challenge has expired, so do not retry it.
            LOG.warn("Authsignal rejected the pending link of the user in the tenant: " + tenantDomain
                    + ". The pending link is removed.");
            AuthsignalDiagnosticLogUtil.triggerFailureLog(LINK_AUTHSIGNAL_USER, Messages.LINK_FAILED_NOT_RETRIED, e,
                    () -> logInputs(context, user, null));
        } catch (AuthenticationFailedException | UserStoreException | RuntimeException e) {
            LOG.warn("Failed to complete the pending Authsignal link of the user in the tenant: " + tenantDomain
                    + ".", e);
            AuthsignalDiagnosticLogUtil.triggerFailureLog(LINK_AUTHSIGNAL_USER, Messages.LINK_FAILED, e,
                    () -> logInputs(context, user, null));
            return;
        }

        claims.put(AuthsignalConstants.CHALLENGE_ID_CLAIM, "");
        try {
            AuthsignalUtil.setUserClaims(tenantDomain, username, claims);
        } catch (UserStoreException | RuntimeException e) {
            LOG.error("Failed to save the Authsignal link of the user in the tenant: " + tenantDomain + ".", e);
            AuthsignalDiagnosticLogUtil.triggerFailureLog(LINK_AUTHSIGNAL_USER, Messages.SAVING_LINK_FAILED, e,
                    () -> logInputs(context, user, null));
        }
    }

    private boolean isFlowCallback(HttpServletRequest request, AuthenticationContext context) {

        // Skip the request if an earlier step already handled it.
        return canHandle(request)
                && context.getProperty(AuthContextProps.ACTION_CODE) != null
                && !Boolean.TRUE.equals(request.getAttribute(FrameworkConstants.REQ_ATTR_HANDLED));
    }

    /**
     * Get the URL Authsignal sends the user back to: the application's redirect URI in API based flows, and
     * {@code /commonauth} otherwise.
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
     * Build the {@code /commonauth} URL Authsignal sends the user back to.
     */
    protected String buildCallbackUrl(AuthenticationContext context) throws AuthenticationFailedException {

        try {
            return ServiceURLBuilder.create()
                    .addPath(FrameworkConstants.COMMONAUTH)
                    .addParameter(RequestParams.SESSION_DATA_KEY, context.getContextIdentifier())
                    .build()
                    .getAbsolutePublicURL();
        } catch (URLBuilderException e) {
            throw handleFailure(ErrorMessages.ERROR_CODE_BUILDING_CALLBACK_URL, null, e);
        }
    }

    protected AuthsignalClient createClient(AuthsignalConfig config) throws AuthenticationFailedException {

        try {
            return new AuthsignalClient(config);
        } catch (AuthsignalConnectionException e) {
            throw new AuthenticationFailedException(e.getErrorCode(), e.getMessage(), e);
        }
    }

    /**
     * Get the Authsignal configuration of the tenant.
     */
    protected AuthsignalConfig getAuthsignalConfig(AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            return AuthsignalUtil.getConfig(context.getTenantDomain());
        } catch (IdentityGovernanceException e) {
            throw handleFailure(ErrorMessages.ERROR_CODE_READING_CONFIG, null, e);
        }
    }

    /**
     * Get the Authsignal user ID of the user: the WSO2 user UUID, or the subject identifier of a federated user.
     */
    protected String resolveAuthsignalUserId(AuthenticatedUser user) throws AuthenticationFailedException {

        if (user.isFederatedUser()) {
            return user.getAuthenticatedSubjectIdentifier();
        }
        try {
            return user.getUserId();
        } catch (UserIdNotFoundException e) {
            throw handleFailure(ErrorMessages.ERROR_CODE_RESOLVING_USER_ID, user, e);
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

    /**
     * Get the inputs of a sign-in diagnostic log: the step, the application, the action code and the user ID.
     */
    private static Map<String, Object> logInputs(AuthenticationContext context, AuthenticatedUser user,
                                                 String actionCode) {

        Map<String, Object> inputs = AuthsignalDiagnosticLogUtil.commonInputs(actionCode,
                getUserId(user).orElse(null));
        inputs.put(LogConstants.InputKeys.STEP, context.getCurrentStep());
        FrameworkUtils.getApplicationResourceId(context).ifPresent(applicationId ->
                inputs.put(LogConstants.InputKeys.APPLICATION_ID, applicationId));
        FrameworkUtils.getApplicationName(context).ifPresent(applicationName ->
                inputs.put(LogConstants.InputKeys.APPLICATION_NAME, applicationName));
        return inputs;
    }

    /**
     * Get the user ID of a local user. Federated users are skipped, as their subject identifier may be personal data.
     */
    private static Optional<String> getUserId(AuthenticatedUser user) {

        if (user == null || user.isFederatedUser()) {
            return Optional.empty();
        }
        try {
            return Optional.ofNullable(user.getUserId());
        } catch (UserIdNotFoundException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Unable to resolve the user ID of the user for diagnostic logs.", e);
            }
            return Optional.empty();
        }
    }

    private AuthenticationFailedException handleFailure(ErrorMessages error, AuthenticatedUser user) {

        return new AuthenticationFailedException(error.getCode(), error.getMessage(), user);
    }

    private AuthenticationFailedException handleFailure(ErrorMessages error, AuthenticatedUser user,
                                                        Throwable cause) {

        return new AuthenticationFailedException(error.getCode(), error.getMessage(), user, cause);
    }
}
