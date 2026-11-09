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

    public static final String AUTHENTICATOR_NAME = "authsignal-authenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Authsignal";
    public static final String AUTHENTICATOR_I18N_KEY = "authenticator.authsignal";
    // Groups Authsignal with the other MFA options in the Console.
    public static final String AUTHENTICATOR_TAG_MFA = "MFA";
    public static final String EXECUTOR_NAME = "AuthsignalExecutor";
    public static final String EXECUTOR_DISPLAY_NAME = "Authsignal";
    // Transparent icon shown in the flow builder, like the icons of the built-in steps.
    public static final String EXECUTOR_ICON_PATH = "icons/authsignal.svg";

    public static final String USER_AGENT_HEADER = "User-Agent";

    // Claim URIs of the user's contact details.
    public static final String EMAIL_CLAIM = "http://wso2.org/claims/emailaddress";
    public static final String MOBILE_CLAIM = "http://wso2.org/claims/mobile";
    // Identity claims set by WSO2 when the user verifies the email address or mobile number.
    public static final String EMAIL_VERIFIED_CLAIM = "http://wso2.org/claims/identity/emailVerified";
    public static final String MOBILE_VERIFIED_CLAIM = "http://wso2.org/claims/identity/phoneVerified";
    // Challenge ID of a registration that could not be linked to the user yet.
    public static final String CHALLENGE_ID_CLAIM = "http://wso2.org/claims/authsignalChallengeId";

    /**
     * Diagnostic log constants.
     */
    public static class LogConstants {

        private LogConstants() {

        }

        public static final String AUTHSIGNAL_SERVICE = "authsignal-service";

        /**
         * Action IDs of the diagnostic logs.
         */
        public static class ActionIDs {

            private ActionIDs() {

            }

            // One action ID per Authsignal API, shared by sign-in and the flows built in the Console.
            public static final String START_AUTHSIGNAL_FLOW = "start-authsignal-flow";
            public static final String VERIFY_AUTHSIGNAL_FLOW = "verify-authsignal-flow";
            public static final String LINK_AUTHSIGNAL_USER = "link-authsignal-user";
        }

        /**
         * Input keys of the diagnostic logs.
         */
        public static class InputKeys {

            private InputKeys() {

            }

            public static final String ACTION_CODE = "action code";
            public static final String FLOW_TYPE = "flow type";
            public static final String FLOW_STATE = "flow state";
            public static final String VERIFICATION_METHODS = "verification methods";
            public static final String UPDATED_CLAIMS = "updated claims";
            public static final String STATUS_CODE = "authsignal status code";
        }

        /**
         * Result messages of the diagnostic logs, shared by sign-in and the flows built in the Console. Failures
         * of the sign-in and the flow executor are logged with the message of their error.
         */
        public static class Messages {

            private Messages() {

            }

            public static final String FLOW_STARTED = "Started the flow on Authsignal.";
            public static final String FLOW_RESULT_RECEIVED = "Received the flow result from Authsignal.";
            public static final String VERIFICATION_COMPLETED = "Authsignal verification completed successfully.";
            public static final String USER_LINKED = "Linked the Authsignal user to the WSO2 user.";
            public static final String LINK_FAILED = "Failed to link the Authsignal user to the WSO2 user.";
            public static final String LINK_FAILED_RETRIED = "Failed to link the Authsignal user to the WSO2 user. "
                    + "The link will be retried at the user's next sign-in.";
            public static final String LINK_FAILED_NOT_RETRIED = "Failed to link the Authsignal user to the WSO2 "
                    + "user. The link is not retried.";
            public static final String SAVING_LINK_FAILED = "Failed to save the Authsignal link on the WSO2 user.";
            public static final String USER_NOT_CREATED = "The user registered with Authsignal is not created. The "
                    + "Authsignal user is not linked to a WSO2 user.";
        }
    }

    /**
     * Governance connector details and property names.
     */
    public static class ConnectorConfig {

        private ConnectorConfig() {

        }

        // Must match the authenticator name: the Console uses the authenticator ID as the connector ID.
        public static final String NAME = AUTHENTICATOR_NAME;
        public static final String FRIENDLY_NAME = "Authsignal";
        public static final String CATEGORY = "Multi Factor Authenticators";
        public static final String SUB_CATEGORY = "DEFAULT";
        public static final int ORDER = 0;

        // The __secret__ prefix shows the field as a password input.
        public static final String SECRET_KEY = "__secret__.Authsignal.SecretKey";
        public static final String REGION = "Authsignal.Region";
        // The default action code of the Authsignal flow used in all journeys.
        public static final String ACTION_CODE = "Authsignal.ActionCode";
        // URI of the claim that records whether the user has a passkey on Authsignal.
        public static final String PASSKEY_ENROLLED_CLAIM = "Authsignal.PasskeyEnrolledClaim";
    }

    /**
     * Request parameters and flow inputs.
     */
    public static class RequestParams {

        private RequestParams() {

        }

        public static final String SESSION_DATA_KEY = "sessionDataKey";
        // Added by Authsignal to the redirect URL when the user completes a flow.
        public static final String CHALLENGE_TOKEN = "challenge_token";
    }

    /**
     * Authentication context property keys of a pending Authsignal flow.
     */
    public static class AuthContextProps {

        private AuthContextProps() {

        }

        public static final String ACTION_CODE = "authsignal.actionCode";
        // Pre-built UI URL, returned to API based clients.
        public static final String CHALLENGE_URL = "authsignal.challengeUrl";
    }

    /**
     * Flow context property keys of a pending Authsignal flow.
     */
    public static class FlowContextProps {

        private FlowContextProps() {

        }

        // Challenge ID of the verified registration flow, used to link the Authsignal user to the new WSO2 user.
        public static final String CHALLENGE_ID = "authsignalChallengeId";
    }

    /**
     * Metadata keys of the executor, set on the flow node.
     */
    public static class ExecutorMetadata {

        private ExecutorMetadata() {

        }

        // Action code of the Authsignal flow, overriding the connector configuration.
        public static final String ACTION_CODE = "authsignalActionCode";
    }

    /**
     * Flow types the executor supports.
     */
    public static class FlowType {

        private FlowType() {

        }

        public static final String REGISTRATION = "REGISTRATION";
        public static final String INVITED_USER_REGISTRATION = "INVITED_USER_REGISTRATION";
        public static final String PASSWORD_RECOVERY = "PASSWORD_RECOVERY";
    }

    /**
     * Default values for the configuration.
     */
    public static class Defaults {

        private Defaults() {

        }

        public static final String REGION = Region.US;
        // Action code of the flow in the Authsignal Portal.
        public static final String ACTION_CODE = "sign-in";
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
     * States of an Authsignal flow.
     * See https://docs.authsignal.com/api-reference/server-api/verify-flow
     */
    public static class ActionState {

        private ActionState() {

        }

        public static final String CHALLENGE_SUCCEEDED = "CHALLENGE_SUCCEEDED";
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
                "Error while reading the Authsignal configuration of the tenant.");

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

    /**
     * Error messages of the Authsignal executor. The flow engine reports them under its own error codes, with
     * the message as the error description, so they must not contain any personal data.
     */
    public enum ExecutorErrorMessages {

        UNSUPPORTED_FLOW_TYPE("Authsignal is not supported in the flow type: %s."),
        PORTAL_URL_NOT_FOUND("The portal URL to return to after the Authsignal challenge is not available in the " +
                "flow."),
        READING_CONFIG("Error while reading the Authsignal configuration of the tenant."),
        SECRET_KEY_NOT_CONFIGURED("Authsignal secret key is not configured for the tenant."),
        CONTACT_DETAILS_NOT_FOUND("An email address or a mobile number is required to register with Authsignal."),
        // Kept generic so that it does not reveal whether the user exists.
        USER_NOT_IDENTIFIED("The user could not be verified."),
        START_FLOW_FAILED("Error while starting the flow on Authsignal."),
        INVALID_START_FLOW_RESPONSE("Authsignal did not return a challenge URL when starting the flow."),
        MISSING_TOKEN("The Authsignal challenge token is missing in the request."),
        VERIFY_FLOW_FAILED("Error while verifying the flow on Authsignal."),
        INVALID_VERIFY_FLOW_RESPONSE("Authsignal did not return a challenge ID when verifying the flow."),
        CHALLENGE_NOT_SUCCEEDED("The Authsignal challenge was not completed successfully."),
        CONTACT_DETAILS_MISMATCH("The email address or mobile number verified on Authsignal does not match the one " +
                "the challenge was started for."),
        USER_MISMATCH("The user verified on Authsignal does not match the user the challenge was started for.");

        private final String message;

        ExecutorErrorMessages(String message) {

            this.message = message;
        }

        public String getMessage() {

            return message;
        }

        @Override
        public String toString() {

            return message;
        }
    }
}
