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

package org.wso2.carbon.identity.local.auth.authsignal.constant;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Constants used by the Authsignal authenticator.
 */
public class AuthsignalConstants {

    private AuthsignalConstants() {

    }

    // Claim URIs of the user's contact details.
    public static final String EMAIL_CLAIM = "http://wso2.org/claims/emailaddress";
    public static final String MOBILE_CLAIM = "http://wso2.org/claims/mobile";
    // Identity claims set by WSO2 when the user verifies the email address or mobile number.
    public static final String EMAIL_VERIFIED_CLAIM = "http://wso2.org/claims/identity/emailVerified";
    public static final String MOBILE_VERIFIED_CLAIM = "http://wso2.org/claims/identity/phoneVerified";

    // Query parameter Authsignal appends to the redirect URL once the user completes a flow in the pre-built UI.
    public static final String CHALLENGE_TOKEN_PARAM = "challenge_token";

    /**
     * Default values for the configuration.
     */
    public static class Defaults {

        private Defaults() {

        }

        public static final String REGION = Region.US;
        public static final String USER_IDENTIFIER = UserIdentifier.USER_ID;
        // Action codes of the flows configured in the Authsignal Portal, one per journey.
        public static final String SIGN_IN_FLOW_REF = "sign-in";
        public static final String REGISTRATION_FLOW_REF = "sign-up";
        public static final String RECOVERY_FLOW_REF = "password-reset";
        // Off by default so that a tenant does not start sharing contact details with Authsignal without opting in.
        public static final boolean SYNC_CONTACT_DETAILS = false;
        /*
         * On by default so that a deleted user's authenticators do not linger on Authsignal, where a new user given the
         * same Authsignal user ID (for example the same username) would inherit them.
         */
        public static final boolean DELETE_USERS = true;
        public static final int REQUEST_TIMEOUT_MILLIS = 10000;
    }

    /**
     * Authsignal regions and their Server API base URLs.
     * See https://docs.authsignal.com/api-reference/server-api/overview
     */
    public static class Region {

        private Region() {

        }

        public static final String US = "us";
        public static final String EU = "eu";
        public static final String AU = "au";
        public static final String CA = "ca";
        public static final String UK = "uk";

        public static final Map<String, String> API_BASE_URLS;

        static {
            Map<String, String> urls = new LinkedHashMap<>();
            urls.put(US, "https://api.authsignal.com/v1");
            urls.put(EU, "https://eu.api.authsignal.com/v1");
            urls.put(AU, "https://au.api.authsignal.com/v1");
            urls.put(CA, "https://ca.api.authsignal.com/v1");
            urls.put(UK, "https://uk.api.authsignal.com/v1");
            API_BASE_URLS = Collections.unmodifiableMap(urls);
        }
    }

    /**
     * Supported strategies for mapping a WSO2 user to an Authsignal user ID.
     */
    public static class UserIdentifier {

        private UserIdentifier() {

        }

        // The immutable WSO2 user UUID (recommended).
        public static final String USER_ID = "userId";
        // The tenant-qualified, user store domain aware username.
        public static final String USERNAME = "username";
    }

    /**
     * States of an Authsignal flow.
     * See https://docs.authsignal.com/api-reference/server-api/verify-flow
     */
    public static class FlowState {

        private FlowState() {

        }

        public static final String CHALLENGE_REQUIRED = "CHALLENGE_REQUIRED";
        public static final String CHALLENGE_SUCCEEDED = "CHALLENGE_SUCCEEDED";
        public static final String CHALLENGE_FAILED = "CHALLENGE_FAILED";
    }

    /**
     * Types of the steps completed in an Authsignal flow.
     */
    public static class StepType {

        private StepType() {

        }

        public static final String VERIFICATION_REQUIRED = "VERIFICATION_REQUIRED";
        public static final String ENROLLMENT_REQUIRED = "ENROLLMENT_REQUIRED";
        public static final String ENROLLMENT_OPTIONAL = "ENROLLMENT_OPTIONAL";
    }

    /**
     * Authsignal verification methods that carry the user's email address or phone number.
     */
    public static class VerificationMethod {

        private VerificationMethod() {

        }

        public static final String EMAIL_OTP = "EMAIL_OTP";
        public static final String EMAIL_MAGIC_LINK = "EMAIL_MAGIC_LINK";
        public static final String SMS = "SMS";
        public static final String WHATSAPP = "WHATSAPP";
        public static final String PASSKEY = "PASSKEY";
    }

    /**
     * Error messages of the Authsignal authenticator.
     */
    public enum ErrorMessages {

        ERROR_CODE_NO_AUTHENTICATED_USER("ASIG-60001",
                "No authenticated user found. Authsignal must be configured after a step that identifies the user."),
        ERROR_CODE_SECRET_KEY_NOT_CONFIGURED("ASIG-60002",
                "Authsignal secret key is not configured for the tenant."),
        ERROR_CODE_INVALID_USER_IDENTIFIER("ASIG-60003",
                "Unsupported Authsignal user identifier configuration: %s."),
        ERROR_CODE_RESOLVING_USER_ID("ASIG-60004",
                "Error while resolving the Authsignal user ID for the user."),
        ERROR_CODE_START_FLOW_FAILED("ASIG-60005",
                "Error while starting the flow on Authsignal."),
        ERROR_CODE_VERIFY_FLOW_FAILED("ASIG-60006",
                "Error while verifying the flow on Authsignal."),
        ERROR_CODE_CHALLENGE_NOT_SUCCEEDED("ASIG-60007",
                "The Authsignal challenge was not completed successfully."),
        ERROR_CODE_CHALLENGE_MISMATCH("ASIG-60008",
                "The Authsignal challenge result does not belong to the current flow."),
        ERROR_CODE_BUILDING_CALLBACK_URL("ASIG-60009",
                "Error while building the Authsignal callback URL."),
        ERROR_CODE_REDIRECTING("ASIG-60010",
                "Error while redirecting the user to the Authsignal challenge."),
        ERROR_CODE_MISSING_TOKEN("ASIG-60011",
                "The Authsignal challenge token is missing in the request."),
        ERROR_CODE_INVALID_REGION("ASIG-60012",
                "Unsupported Authsignal region: %s."),
        ERROR_CODE_READING_CONFIG("ASIG-60013",
                "Error while reading the Authsignal configuration of the tenant."),
        ERROR_CODE_UNSUPPORTED_FLOW_TYPE("ASIG-60014",
                "Authsignal is not supported in the flow type: %s."),
        ERROR_CODE_PORTAL_URL_NOT_FOUND("ASIG-60015",
                "The portal URL to return to after the Authsignal challenge is not available in the flow."),
        ERROR_CODE_USER_NOT_IDENTIFIED("ASIG-60016",
                "The user could not be verified."),
        ERROR_CODE_USER_NOT_ENROLLED("ASIG-60017",
                "The user could not be verified."),
        ERROR_CODE_INVALID_CALLBACK("ASIG-60018",
                "The Authsignal challenge result does not belong to the current flow."),
        ERROR_CODE_CONTACT_DETAILS_NOT_FOUND("ASIG-60019",
                "An email address or a mobile number is required to register with Authsignal.");

        private final String code;
        private final String message;

        ErrorMessages(String code, String message) {

            this.code = code;
            this.message = message;
        }

        public String getCode() {

            return code;
        }

        public String getMessage() {

            return message;
        }

        @Override
        public String toString() {

            return code + " - " + message;
        }
    }
}
