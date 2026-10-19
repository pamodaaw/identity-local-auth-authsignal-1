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

/**
 * Request body of the Authsignal Start Flow API. Null fields are omitted when serialized.
 * See https://docs.authsignal.com/api-reference/server-api/start-flow
 */
public class StartFlowRequest {

    private final String actionCode;
    private final UserLookup user = new UserLookup();
    private Hints hints;
    private Attributes attributes;
    private String redirectUrl;

    public StartFlowRequest(String actionCode) {

        this.actionCode = actionCode;
    }

    public String getActionCode() {

        return actionCode;
    }

    /**
     * Identify an existing user by the Authsignal user ID. Authsignal takes one identifier only.
     */
    public StartFlowRequest setUserId(String userId) {

        user.userId = userId;
        return this;
    }

    /**
     * Identify a user that does not exist yet by the email address. Authsignal takes one identifier only.
     */
    public StartFlowRequest setUserEmail(String email) {

        user.email = email;
        return this;
    }

    /**
     * Identify a user that does not exist yet by the phone number (E.164). Authsignal takes one identifier only.
     */
    public StartFlowRequest setUserPhoneNumber(String phoneNumber) {

        user.phoneNumber = phoneNumber;
        return this;
    }

    public String getUserId() {

        return user.userId;
    }

    public String getUserEmail() {

        return user.email;
    }

    public String getUserPhoneNumber() {

        return user.phoneNumber;
    }

    /**
     * Pre-fill an email address the user is not identified by, so the flow does not ask for it again.
     */
    public StartFlowRequest setHintEmail(String email) {

        getOrCreateHints().email = email;
        return this;
    }

    /**
     * Pre-fill a phone number (E.164) the user is not identified by, so the flow does not ask for it again.
     */
    public StartFlowRequest setHintPhoneNumber(String phoneNumber) {

        getOrCreateHints().phoneNumber = phoneNumber;
        return this;
    }

    public String getHintEmail() {

        return hints != null ? hints.email : null;
    }

    public String getHintPhoneNumber() {

        return hints != null ? hints.phoneNumber : null;
    }

    public StartFlowRequest setIpAddress(String ipAddress) {

        getOrCreateAttributes().ipAddress = ipAddress;
        return this;
    }

    public StartFlowRequest setUserAgent(String userAgent) {

        getOrCreateAttributes().userAgent = userAgent;
        return this;
    }

    public String getIpAddress() {

        return attributes != null ? attributes.ipAddress : null;
    }

    public String getUserAgent() {

        return attributes != null ? attributes.userAgent : null;
    }

    public StartFlowRequest setRedirectUrl(String redirectUrl) {

        this.redirectUrl = redirectUrl;
        return this;
    }

    public String getRedirectUrl() {

        return redirectUrl;
    }

    private Hints getOrCreateHints() {

        if (hints == null) {
            hints = new Hints();
        }
        return hints;
    }

    private Attributes getOrCreateAttributes() {

        if (attributes == null) {
            attributes = new Attributes();
        }
        return attributes;
    }

    private static class UserLookup {

        private String userId;
        private String email;
        private String phoneNumber;
    }

    private static class Hints {

        private String email;
        private String phoneNumber;
    }

    private static class Attributes {

        private String ipAddress;
        private String userAgent;
    }
}
