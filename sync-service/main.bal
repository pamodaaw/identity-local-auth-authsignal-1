// Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
//
// WSO2 LLC. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. See the License for the
// specific language governing permissions and limitations
// under the License.

import ballerina/http;
import ballerina/log;

const SIGNATURE_HEADER = "x-hub-signature";

// Keeps Authsignal's users in step with WSO2 IS / Asgardeo, driven by the platform's webhooks:
// - user profile updated: changed email and mobile (by default, only verified ones) are set as verified on the
//   Authsignal user
// - user deleted: the Authsignal user and their authenticators are deleted
//
// Logs never carry email addresses, phone numbers or user IDs.
service / on new http:Listener(port) {

    # WebSub verification of a subscription or unsubscription: echo `hub.challenge`.
    #
    # + request - Verification request with `hub.mode`, `hub.topic` and `hub.challenge`
    # + return - The challenge, or 404 if the topic belongs to a tenant this service does not serve
    isolated resource function get events(http:Request request) returns http:Ok|http:BadRequest|http:NotFound {

        string? challenge = request.getQueryParamValue("hub.challenge");
        if challenge is () || challenge == "" {
            return <http:BadRequest>{body: "Missing hub.challenge."};
        }
        string? topic = request.getQueryParamValue("hub.topic");
        if topic is () || findTopicTenant(topic) is () {
            log:printWarn("Refused a webhook verification for a tenant that is not configured.",
                    mode = request.getQueryParamValue("hub.mode"));
            return <http:NotFound>{};
        }
        log:printInfo("Answered a webhook verification.", mode = request.getQueryParamValue("hub.mode"),
                topic = topic);
        return <http:Ok>{body: challenge, mediaType: "text/plain"};
    }

    # A webhook delivery. Answers 2xx for anything that must not be redelivered, and 503 when Authsignal could not
    # be updated, so the platform redelivers the event.
    #
    # + request - Delivery, signed with `x-hub-signature`
    # + return - Outcome of the delivery
    isolated resource function post events(http:Request request)
            returns http:Ok|http:BadRequest|http:Unauthorized|http:ServiceUnavailable {

        byte[]|error body = request.getBinaryPayload();
        if body is error {
            return <http:BadRequest>{body: "Unreadable body."};
        }
        SecurityEventToken|error token = parseToken(body);
        if token is error {
            log:printWarn("Ignored a webhook delivery that is not a security event token.");
            return <http:BadRequest>{body: "Not a security event token."};
        }
        string? tenantName = getTenantName(token);
        TenantConfig? tenant = tenantName is string ? findTenant(tenantName) : ();
        if tenant is () {
            // Redelivering would not help, so the delivery is accepted and dropped.
            log:printWarn("Ignored a webhook delivery for a tenant that is not configured.", tenant = tenantName,
                    jti = token?.jti);
            return <http:Ok>{};
        }
        string|http:HeaderNotFoundError signature = request.getHeader(SIGNATURE_HEADER);
        if signature is http:HeaderNotFoundError || !isValidSignature(body, signature, tenant.webhookSecret) {
            log:printWarn("Refused a webhook delivery with a missing or invalid signature.", tenant = tenant.name,
                    jti = token?.jti);
            return <http:Unauthorized>{};
        }

        foreach [string, json] [eventType, event] in token.events.entries() {
            error? result = handleEvent(tenant, eventType, event);
            if result is error {
                log:printError("Failed to sync a webhook event to Authsignal. It will be redelivered.",
                        result, tenant = tenant.name, eventType = eventType, jti = token?.jti);
                return <http:ServiceUnavailable>{};
            }
        }
        return <http:Ok>{};
    }

    // Liveness check.
    isolated resource function get healthz() returns http:Ok {

        return <http:Ok>{body: "OK", mediaType: "text/plain"};
    }
}

isolated function parseToken(byte[] body) returns SecurityEventToken|error {

    json payload = check (check string:fromBytes(body)).fromJsonString();
    return payload.cloneWithType();
}

isolated function handleEvent(TenantConfig tenant, string eventType, json event) returns error? {

    if eventType != USER_PROFILE_UPDATED_EVENT && eventType != USER_DELETED_EVENT {
        log:printDebug("Ignored an event the service does not handle.", eventType = eventType);
        return;
    }
    UserEvent|error payload = event.cloneWithType();
    EventUser? user = payload is UserEvent ? payload?.user : ();
    if payload is error || user is () {
        log:printWarn("Ignored an event without a user.", tenant = tenant.name, eventType = eventType);
        return;
    }
    if eventType == USER_PROFILE_UPDATED_EVENT {
        return syncContactDetails(tenant, payload, user);
    }
    return deleteUser(tenant, payload, user);
}

// Set the email and mobile that a profile update changed on the Authsignal user, marked as verified.
isolated function syncContactDetails(TenantConfig tenant, UserEvent payload, EventUser user) returns error? {

    if !tenant.syncContactDetails {
        return;
    }
    VerifiedContactDetails details = getVerifiedContactDetails(user, tenant.requireVerifiedContactDetails);
    if details.email is () && details.phoneNumber is () {
        log:printDebug("The profile update carries no email or mobile to sync.",
                tenant = tenant.name);
        return;
    }
    // A profile update does not carry the username, so username based IDs can only use the claims that changed.
    string? userId = toAuthsignalUserId(tenant, user?.id, getClaimValue(user?.updatedClaims, USERNAME_CLAIM),
            payload?.userStore?.name);
    if userId is () {
        log:printWarn("Cannot resolve the Authsignal user ID of a profile update. Skipping the sync.",
                tenant = tenant.name, userIdentifier = tenant.userIdentifier);
        return;
    }

    AuthsignalUser? existing = check getAuthsignalUser(tenant, userId);
    if existing is () || existing?.isEnrolled == false {
        // No authenticators on Authsignal, so there is nothing to keep in sync.
        log:printDebug("The user has no authenticators on Authsignal. Skipping the sync.", tenant = tenant.name);
        return;
    }
    // Compare first, so duplicate deliveries and Authsignal's own webhooks do not cause further writes.
    VerifiedContactDetails changes = {
        email: details.email is string && (details.email != existing?.email || existing?.emailVerified != true)
            ? details.email : (),
        phoneNumber: details.phoneNumber is string
            && (details.phoneNumber != existing?.phoneNumber || existing?.phoneNumberVerified != true)
            ? details.phoneNumber : ()
    };
    if changes.email is () && changes.phoneNumber is () {
        log:printDebug("Authsignal already holds the verified contact details.", tenant = tenant.name);
        return;
    }
    boolean updated = check updateAuthsignalUser(tenant, userId, changes);
    if updated {
        log:printInfo("Updated verified contact details of a user on Authsignal.", tenant = tenant.name,
                email = changes.email is string, phoneNumber = changes.phoneNumber is string);
    }
}

// Delete the Authsignal user of a user deleted in WSO2.
isolated function deleteUser(TenantConfig tenant, UserEvent payload, EventUser user) returns error? {

    if !tenant.deleteUsers {
        return;
    }
    string? userId = toAuthsignalUserId(tenant, user?.id, getClaimValue(user?.claims, USERNAME_CLAIM),
            payload?.userStore?.name);
    if userId is () {
        log:printWarn("Cannot resolve the Authsignal user ID of a deleted user. Skipping the deletion.",
                tenant = tenant.name, userIdentifier = tenant.userIdentifier);
        return;
    }
    check deleteAuthsignalUser(tenant, userId);
    log:printInfo("Deleted a user on Authsignal.", tenant = tenant.name);
}

// Get the tenant a WebSub topic belongs to. Topics have the form
// `{root-org-domain}.{org-id}.schema.{profile}.{version}.event.{type}`, and IS tenant domains may contain dots.
isolated function findTopicTenant(string topic) returns TenantConfig? {

    // The longest match wins, so tenant `acme` does not take the topics of tenant `acme.com`.
    TenantConfig? found = ();
    foreach TenantConfig tenant in tenants {
        if topic.toLowerAscii().startsWith(tenant.name.toLowerAscii() + ".")
                && (found is () || tenant.name.length() > found.name.length()) {
            found = tenant;
        }
    }
    return found;
}
