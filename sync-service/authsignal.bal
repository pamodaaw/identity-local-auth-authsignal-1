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
import ballerina/url;

// Calls to the Authsignal Server API. See https://docs.authsignal.com/api-reference/server-api/overview

# A user on Authsignal, as returned by Get User. Only the fields the sync reads.
#
# + isEnrolled - Whether the user has at least one authenticator
# + email - Email address
# + emailVerified - Whether the email address is verified
# + phoneNumber - Phone number in E.164 format
# + phoneNumberVerified - Whether the phone number is verified
type AuthsignalUser record {
    boolean isEnrolled?;
    string? email?;
    boolean? emailVerified?;
    string? phoneNumber?;
    boolean? phoneNumberVerified?;
};

# An Authsignal call that failed after its retries.
type AuthsignalError distinct error<record {|int? statusCode;|}>;

isolated class AuthsignalClients {

    private final map<http:Client> clients = {};

    // Get the HTTP client of an Authsignal base URL, creating it on first use.
    isolated function get(string baseUrl) returns http:Client|error {

        lock {
            http:Client? existing = self.clients[baseUrl];
            if existing is http:Client {
                return existing;
            }
            http:Client created = check new (baseUrl, {
                timeout: requestTimeout,
                retryConfig: {
                    count: maxAttempts - 1,
                    interval: 0.5,
                    backOffFactor: 2.0,
                    maxWaitInterval: 2,
                    statusCodes: [429, 500, 502, 503, 504]
                }
            });
            self.clients[baseUrl] = created;
            return created;
        }
    }
}

final AuthsignalClients authsignalClients = new;

# Get a user on Authsignal.
#
# + tenant - Tenant settings
# + userId - Authsignal user ID
# + return - The user, nil if Authsignal does not know the user, or an error
isolated function getAuthsignalUser(TenantConfig tenant, string userId) returns AuthsignalUser?|error {

    http:Response response = check send(tenant, http:HTTP_GET, userId, ());
    if response.statusCode == http:STATUS_NOT_FOUND {
        return ();
    }
    check expectSuccess(response, "get user");
    json body = check response.getJsonPayload();
    return check body.cloneWithType();
}

# Set the email address and phone number of a user on Authsignal as verified. Authsignal moves the user's email and
# SMS authenticators to verified values without sending an OTP.
#
# + tenant - Tenant settings
# + userId - Authsignal user ID
# + details - Values to set; nil fields are left unchanged
# + return - Whether the user exists on Authsignal, or an error
isolated function updateAuthsignalUser(TenantConfig tenant, string userId, VerifiedContactDetails details)
        returns boolean|error {

    map<json> body = {};
    string? email = details.email;
    if email is string {
        body["email"] = email;
        body["emailVerified"] = true;
    }
    string? phoneNumber = details.phoneNumber;
    if phoneNumber is string {
        body["phoneNumber"] = phoneNumber;
        body["phoneNumberVerified"] = true;
    }
    http:Response response = check send(tenant, http:HTTP_PATCH, userId, body);
    if response.statusCode == http:STATUS_NOT_FOUND {
        return false;
    }
    check expectSuccess(response, "update user");
    return true;
}

# Delete a user and their authenticators on Authsignal. A user Authsignal does not know counts as deleted.
#
# + tenant - Tenant settings
# + userId - Authsignal user ID
# + return - An error if the deletion failed
isolated function deleteAuthsignalUser(TenantConfig tenant, string userId) returns error? {

    http:Response response = check send(tenant, http:HTTP_DELETE, userId, ());
    if response.statusCode == http:STATUS_NOT_FOUND {
        return;
    }
    check expectSuccess(response, "delete user");
}

isolated function send(TenantConfig tenant, string method, string userId, json body) returns http:Response|error {

    string baseUrl = authsignalBaseUrl != "" ? authsignalBaseUrl : REGION_BASE_URLS.get(tenant.region.toLowerAscii());
    http:Client httpClient = check authsignalClients.get(baseUrl);
    string path = "/users/" + check encodePathSegment(userId);
    http:Request request = new;
    request.setHeader("Authorization", "Basic " + (tenant.authsignalSecretKey + ":").toBytes().toBase64());
    if body !is () {
        request.setJsonPayload(body);
    }
    http:Response|http:ClientError response = httpClient->execute(method, path, request);
    if response is http:ClientError {
        return error AuthsignalError("Authsignal could not be reached.", response, statusCode = ());
    }
    return response;
}

isolated function expectSuccess(http:Response response, string operation) returns AuthsignalError? {

    int status = response.statusCode;
    if status < 200 || status > 299 {
        return error AuthsignalError(string `Authsignal ${operation} returned HTTP ${status}.`, statusCode = status);
    }
    return ();
}

isolated function encodePathSegment(string value) returns string|error {

    // url:encode is form encoding, which turns spaces into '+'; a path needs '%20'.
    string encoded = check url:encode(value, "UTF-8");
    return re `\+`.replaceAll(encoded, "%20");
}
