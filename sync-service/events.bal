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

// Event types of the WSO2 event profile, sent by WSO2 IS 7.2+ and Asgardeo. See WSO2EventProfileManager and
// Constants in https://github.com/wso2-extensions/identity-webhook-event-handlers.
const USER_PROFILE_UPDATED_EVENT = "https://schemas.identity.wso2.org/events/user/event-type/userProfileUpdated";
const USER_DELETED_EVENT = "https://schemas.identity.wso2.org/events/user/event-type/userDeleted";

const EMAIL_CLAIM = "http://wso2.org/claims/emailaddress";
const MOBILE_CLAIM = "http://wso2.org/claims/mobile";
const EMAIL_VERIFIED_CLAIM = "http://wso2.org/claims/identity/emailVerified";
const MOBILE_VERIFIED_CLAIM = "http://wso2.org/claims/identity/phoneVerified";
const USERNAME_CLAIM = "http://wso2.org/claims/username";

# A webhook delivery: a Security Event Token (RFC 8417) with the event payloads keyed by event type.
#
# + iss - Issuer
# + jti - Unique ID of the event
# + events - Event payloads keyed by event type URI
type SecurityEventToken record {
    string iss?;
    string jti?;
    map<json> events;
};

# Payload of a user account event, as built by WSO2UserOperationEventPayloadBuilder.
#
# + user - User the event is about
# + tenant - Root tenant (organisation) of the user
# + userStore - User store of the user
type UserEvent record {
    EventUser user?;
    EventTenant tenant?;
    EventUserStore userStore?;
};

# User in an event. A profile update carries the changed claims; a deletion carries `claims` (username and email).
#
# + id - WSO2 user ID
# + claims - Claims of a deleted user
# + addedClaims - Claims a profile update added
# + updatedClaims - Claims a profile update changed
# + removedClaims - Claims a profile update removed
type EventUser record {
    string id?;
    EventClaim[] claims?;
    EventClaim[] addedClaims?;
    EventClaim[] updatedClaims?;
    EventClaim[] removedClaims?;
};

# A claim of the user.
#
# + uri - Local claim URI
# + value - Claim value; multi-valued claims carry a string array
type EventClaim record {
    string uri;
    json value?;
};

type EventTenant record {
    string id?;
    string name?;
};

type EventUserStore record {
    string id?;
    string name?;
};

# Contact details of an event, to set as verified on Authsignal.
#
# + email - Email address, or nil if the event has none to sync
# + phoneNumber - Mobile number in E.164 format, or nil if the event has none to sync
type VerifiedContactDetails record {|
    string? email = ();
    string? phoneNumber = ();
|};

# Read the root tenant of a delivery, needed to pick the webhook secret before the signature is checked.
#
# + token - Delivery
# + return - Tenant name, or nil if no event names one
isolated function getTenantName(SecurityEventToken token) returns string? {

    foreach json event in token.events {
        UserEvent|error payload = event.cloneWithType();
        if payload is UserEvent {
            string? name = payload?.tenant?.name;
            if name is string && name.trim() != "" {
                return name.trim();
            }
        }
    }
    return ();
}

# Get the contact details of a profile update to set as verified on Authsignal.
#
# The event carries only the claims that changed. By default a value is synced only when the same update also marks
# it as verified, which is how the email and mobile verification flows of WSO2 IS and Asgardeo write it; a changed
# value without its verified flag is then not synced. When verification is not required, every changed value is
# synced, whatever its verified flag. A flag without the value, and removals, are never synced.
#
# + user - User of the profile update event
# + requireVerified - Whether a value needs its verified flag set to true in the same update
# + return - Email and mobile number to sync, each nil when there is none
isolated function getVerifiedContactDetails(EventUser user, boolean requireVerified = true)
        returns VerifiedContactDetails {

    map<string> changed = {};
    foreach EventClaim claim in [...(user?.addedClaims ?: []), ...(user?.updatedClaims ?: [])] {
        string? value = toSingleValue(claim?.value);
        if value is string {
            changed[claim.uri] = value;
        }
    }

    string? email = ();
    string? emailValue = changed[EMAIL_CLAIM];
    if emailValue is string && emailValue != "" && (!requireVerified || isTrue(changed[EMAIL_VERIFIED_CLAIM])) {
        email = emailValue;
    }

    string? phoneNumber = ();
    string? mobileValue = changed[MOBILE_CLAIM];
    // Authsignal takes E.164 numbers only, which is what the connector writes.
    if mobileValue is string && mobileValue.startsWith("+")
            && (!requireVerified || isTrue(changed[MOBILE_VERIFIED_CLAIM])) {
        phoneNumber = mobileValue;
    }
    return {email, phoneNumber};
}

# Get a claim value of an event user.
#
# + claims - Claims of the user
# + uri - Claim URI
# + return - The value, or nil if the claim is missing or empty
isolated function getClaimValue(EventClaim[]? claims, string uri) returns string? {

    foreach EventClaim claim in claims ?: [] {
        if claim.uri == uri {
            return toSingleValue(claim?.value);
        }
    }
    return ();
}

isolated function toSingleValue(json value) returns string? {

    if value is string {
        string trimmed = value.trim();
        return trimmed == "" ? () : trimmed;
    }
    if value is boolean {
        return value.toString();
    }
    return ();
}

isolated function isTrue(string? value) returns boolean {

    return value is string && value.equalsIgnoreCaseAscii("true");
}
