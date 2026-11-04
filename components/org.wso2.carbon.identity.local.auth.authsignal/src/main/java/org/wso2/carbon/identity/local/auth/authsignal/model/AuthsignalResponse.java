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

import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.VerificationMethod;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Response of the Authsignal Start Flow, Verify Flow and Identify User APIs.
 * See https://docs.authsignal.com/api-reference/server-api/verify-flow
 */
public class AuthsignalResponse {

    private String challengeUrl;
    private String challengeId;
    private String challengeToken;
    private Action action;
    private User user;

    /**
     * @return URL of the pre-built UI to redirect the user to.
     */
    public String getChallengeUrl() {

        return challengeUrl;
    }

    public void setChallengeUrl(String challengeUrl) {

        this.challengeUrl = challengeUrl;
    }

    /**
     * @return ID of the challenge.
     */
    public String getChallengeId() {

        return challengeId;
    }

    public void setChallengeId(String challengeId) {

        this.challengeId = challengeId;
    }

    /**
     * @return Token issued when the flow started. Not used to verify the flow.
     */
    public String getChallengeToken() {

        return challengeToken;
    }

    public void setChallengeToken(String challengeToken) {

        this.challengeToken = challengeToken;
    }

    public Action getAction() {

        return action;
    }

    public void setAction(Action action) {

        this.action = action;
    }

    public User getUser() {

        return user;
    }

    public void setUser(User user) {

        this.user = user;
    }

    /**
     * @return The flow state, or null if the response has no action.
     */
    public String getState() {

        return action != null ? action.getState() : null;
    }

    /**
     * @return True if the user has a passkey on Authsignal, including one enrolled in this flow.
     */
    public boolean hasPasskey() {

        if (user != null && user.hasPasskey()) {
            return true;
        }
        if (action != null) {
            for (Step step : action.getCompletedSteps()) {
                if (VerificationMethod.PASSKEY.equals(step.getVerificationMethod())) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * @return True if the user verified a passkey, as per {@link #getVerifiedAuthenticators}.
     */
    public boolean hasVerifiedPasskey() {

        return !getVerifiedAuthenticators(VerificationMethod.PASSKEY).isEmpty();
    }

    /**
     * @return The email address the user verified with email OTP or magic link, as per
     * {@link #getVerifiedAuthenticators}, or null if there is none.
     */
    public String getVerifiedEmail() {

        for (Authenticator authenticator : getVerifiedAuthenticators(VerificationMethod.EMAIL_OTP,
                VerificationMethod.EMAIL_MAGIC_LINK)) {
            if (authenticator.getEmail() != null) {
                return authenticator.getEmail();
            }
        }
        return null;
    }

    /**
     * @return The phone number the user verified with SMS or WhatsApp, as per {@link #getVerifiedAuthenticators},
     * or null if there is none.
     */
    public String getVerifiedPhoneNumber() {

        for (Authenticator authenticator : getVerifiedAuthenticators(VerificationMethod.SMS,
                VerificationMethod.WHATSAPP)) {
            if (authenticator.getPhoneNumber() != null) {
                return authenticator.getPhoneNumber();
            }
        }
        return null;
    }

    /**
     * Get the user's authenticators of the given verification methods that the user verified. If the response has
     * completed steps, as in Verify Flow, only the authenticators used in those steps are returned. Otherwise, as in
     * Identify User, which returns no completed steps, all the user's authenticators of the methods are returned.
     */
    private List<Authenticator> getVerifiedAuthenticators(String... verificationMethods) {

        List<String> methods = Arrays.asList(verificationMethods);
        List<Authenticator> verifiedAuthenticators = new ArrayList<>();
        if (user == null) {
            return verifiedAuthenticators;
        }
        List<Step> steps = action != null ? action.getCompletedSteps() : Collections.emptyList();
        for (Authenticator authenticator : user.getAuthenticators()) {
            if (methods.contains(authenticator.getVerificationMethod())
                    && (steps.isEmpty() || isUsedInStep(authenticator, steps))) {
                verifiedAuthenticators.add(authenticator);
            }
        }
        return verifiedAuthenticators;
    }

    private static boolean isUsedInStep(Authenticator authenticator, List<Step> steps) {

        for (Step step : steps) {
            if (step.getUserAuthenticatorId() != null
                    && step.getUserAuthenticatorId().equals(authenticator.getUserAuthenticatorId())) {
                return true;
            }
        }
        return false;
    }

    /**
     * State and completed steps of a flow.
     */
    public static class Action {

        private String state;
        private List<Step> completedSteps;

        public String getState() {

            return state;
        }

        public void setState(String state) {

            this.state = state;
        }

        public List<Step> getCompletedSteps() {

            return completedSteps != null ? completedSteps : Collections.emptyList();
        }

        public void setCompletedSteps(List<Step> completedSteps) {

            this.completedSteps = completedSteps;
        }
    }

    /**
     * A step the user completed in a flow.
     */
    public static class Step {

        private String stepType;
        private String verificationMethod;
        private String userAuthenticatorId;

        public String getStepType() {

            return stepType;
        }

        public void setStepType(String stepType) {

            this.stepType = stepType;
        }

        public String getVerificationMethod() {

            return verificationMethod;
        }

        public void setVerificationMethod(String verificationMethod) {

            this.verificationMethod = verificationMethod;
        }

        public String getUserAuthenticatorId() {

            return userAuthenticatorId;
        }

        public void setUserAuthenticatorId(String userAuthenticatorId) {

            this.userAuthenticatorId = userAuthenticatorId;
        }
    }

    /**
     * The Authsignal user and the user's verified authenticators.
     */
    public static class User {

        private String userId;
        private List<Authenticator> authenticators;

        public String getUserId() {

            return userId;
        }

        public void setUserId(String userId) {

            this.userId = userId;
        }

        public List<Authenticator> getAuthenticators() {

            return authenticators != null ? authenticators : Collections.emptyList();
        }

        public void setAuthenticators(List<Authenticator> authenticators) {

            this.authenticators = authenticators;
        }

        /**
         * @return True if the user has a passkey authenticator.
         */
        public boolean hasPasskey() {

            for (Authenticator authenticator : getAuthenticators()) {
                if (VerificationMethod.PASSKEY.equals(authenticator.getVerificationMethod())) {
                    return true;
                }
            }
            return false;
        }
    }

    /**
     * An authenticator of the user.
     */
    public static class Authenticator {

        private String userAuthenticatorId;
        private String verificationMethod;
        private String email;
        private String phoneNumber;

        public String getUserAuthenticatorId() {

            return userAuthenticatorId;
        }

        public void setUserAuthenticatorId(String userAuthenticatorId) {

            this.userAuthenticatorId = userAuthenticatorId;
        }

        public String getVerificationMethod() {

            return verificationMethod;
        }

        public void setVerificationMethod(String verificationMethod) {

            this.verificationMethod = verificationMethod;
        }

        public String getEmail() {

            return email;
        }

        public void setEmail(String email) {

            this.email = email;
        }

        public String getPhoneNumber() {

            return phoneNumber;
        }

        public void setPhoneNumber(String phoneNumber) {

            this.phoneNumber = phoneNumber;
        }
    }
}
