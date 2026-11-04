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
import ballerina/test;

const WEBHOOK_SECRET = "test-webhook-secret";

final http:Client syncService = check new ("http://localhost:9090");

// Payload shapes follow WSO2UserOperationEventPayloadBuilder in identity-webhook-event-handlers.

isolated function profileUpdate(string tenant, string userId, json[] addedClaims = [], json[] updatedClaims = [],
        json[] removedClaims = []) returns json => {
    iss: "https://localhost:9443/t/" + tenant,
    iat: 1761800000000,
    jti: "4e2b3b8c-0000-4000-8000-000000000001",
    rci: "c2b8a9f0-0000-4000-8000-000000000002",
    events: {
        [USER_PROFILE_UPDATED_EVENT]: {
            initiatorType: "USER",
            action: "UPDATE",
            user: {
                id: userId,
                ref: "https://localhost:9443/t/" + tenant + "/scim2/Users/" + userId,
                organization: {id: "10084a8d-0000-4000-8000-000000000003", name: tenant, orgHandle: tenant, depth: 0},
                addedClaims,
                updatedClaims,
                removedClaims
            },
            tenant: {id: "1", name: tenant},
            organization: {id: "10084a8d-0000-4000-8000-000000000003", name: tenant, orgHandle: tenant, depth: 0},
            userStore: {id: "UFJJTUFSWQ==", name: "PRIMARY"}
        }
    }
};

isolated function userDeleted(string tenant, string userId, string username, string userStore = "PRIMARY")
        returns json => {
    iss: "https://localhost:9443/t/" + tenant,
    iat: 1761800000000,
    jti: "4e2b3b8c-0000-4000-8000-000000000004",
    events: {
        [USER_DELETED_EVENT]: {
            initiatorType: "ADMIN",
            action: "DELETE",
            user: {
                id: userId,
                claims: [{uri: USERNAME_CLAIM, value: username}, {uri: EMAIL_CLAIM, value: "gone@example.com"}]
            },
            tenant: {id: "1", name: tenant},
            userStore: {id: "UFJJTUFSWQ==", name: userStore}
        }
    }
};

isolated function claim(string uri, json value) returns json => {uri, value};

function deliver(json payload, string? secret = WEBHOOK_SECRET) returns http:Response|error {

    byte[] body = payload.toJsonString().toBytes();
    http:Request request = new;
    request.setBinaryPayload(body, "application/json");
    if secret is string {
        request.setHeader(SIGNATURE_HEADER, check sign(body, secret));
    }
    return syncService->post("/events", request);
}

@test:BeforeEach
function clearCalls() {

    _ = takeCalls();
}

// --- WebSub verification ---

@test:Config
function testVerificationEchoesChallenge() returns error? {

    http:Response response = check syncService->get(
            "/events?hub.mode=subscribe&hub.topic=acme.com.10084a8d.schema.WSO2.v1.event.userProfileUpdated"
            + "&hub.challenge=abc123&hub.lease_seconds=864000");
    test:assertEquals(response.statusCode, 200);
    test:assertEquals(check response.getTextPayload(), "abc123");
}

@test:Config
function testVerificationOfUnknownTenantIsRefused() returns error? {

    http:Response response = check syncService->get(
            "/events?hub.mode=subscribe&hub.topic=other.10084a8d.schema.WSO2.v1.event.userDeleted&hub.challenge=x");
    test:assertEquals(response.statusCode, 404);
}

@test:Config
function testVerificationWithoutChallengeIsRejected() returns error? {

    http:Response response = check syncService->get("/events?hub.mode=subscribe");
    test:assertEquals(response.statusCode, 400);
}

// --- Signature ---

@test:Config
function testMissingSignatureIsRejected() returns error? {

    http:Response response = check deliver(profileUpdate("acme.com", "enrolled"), secret = ());
    test:assertEquals(response.statusCode, 401);
    test:assertEquals(takeCalls().length(), 0);
}

@test:Config
function testWrongSignatureIsRejected() returns error? {

    http:Response response = check deliver(profileUpdate("acme.com", "enrolled"), secret = "wrong-secret");
    test:assertEquals(response.statusCode, 401);
    test:assertEquals(takeCalls().length(), 0);
}

@test:Config
function testUnknownTenantIsAcceptedAndDropped() returns error? {

    http:Response response = check deliver(profileUpdate("other", "enrolled"));
    test:assertEquals(response.statusCode, 200);
    test:assertEquals(takeCalls().length(), 0);
}

@test:Config
function testNonEventBodyIsRejected() returns error? {

    http:Request request = new;
    request.setTextPayload("not json");
    http:Response response = check syncService->post("/events", request);
    test:assertEquals(response.statusCode, 400);
}

// --- Profile updated ---

@test:Config
function testVerifiedEmailAndMobileAreSynced() returns error? {

    http:Response response = check deliver(profileUpdate("acme.com", "enrolled", updatedClaims = [
        claim(EMAIL_CLAIM, "new@example.com"),
        claim(EMAIL_VERIFIED_CLAIM, "true"),
        claim(MOBILE_CLAIM, "+94771111111"),
        claim(MOBILE_VERIFIED_CLAIM, "true")
    ]));
    test:assertEquals(response.statusCode, 200);
    RecordedCall[] calls = takeCalls();
    test:assertEquals(calls.length(), 2);
    test:assertEquals(calls[0].method, "GET");
    test:assertEquals(calls[1].method, "PATCH");
    test:assertEquals(calls[1].userId, "enrolled");
    test:assertEquals(calls[1].authorization, "Basic " + "test-secret-key:".toBytes().toBase64());
    test:assertEquals(calls[1].body, {
        email: "new@example.com",
        emailVerified: true,
        phoneNumber: "+94771111111",
        phoneNumberVerified: true
    });
}

@test:Config
function testOnlyChangedValuesArePatched() returns error? {

    // Mobile verification flow: the number and its verified flag are added together.
    http:Response response = check deliver(profileUpdate("acme.com", "enrolled", addedClaims = [
        claim(MOBILE_CLAIM, "+94771111111"),
        claim(MOBILE_VERIFIED_CLAIM, "true")
    ]));
    test:assertEquals(response.statusCode, 200);
    RecordedCall[] calls = takeCalls();
    test:assertEquals(calls.length(), 2);
    test:assertEquals(calls[1].body, {phoneNumber: "+94771111111", phoneNumberVerified: true});
}

@test:Config
function testValueAlreadyOnAuthsignalIsNotPatched() returns error? {

    http:Response response = check deliver(profileUpdate("acme.com", "current", updatedClaims = [
        claim(EMAIL_CLAIM, "new@example.com"),
        claim(EMAIL_VERIFIED_CLAIM, "true")
    ]));
    test:assertEquals(response.statusCode, 200);
    RecordedCall[] calls = takeCalls();
    test:assertEquals(calls.length(), 1);
    test:assertEquals(calls[0].method, "GET");
}

@test:Config
function testUnverifiedChangeIsNotSynced() returns error? {

    http:Response response = check deliver(profileUpdate("acme.com", "enrolled", updatedClaims = [
        claim(EMAIL_CLAIM, "new@example.com"),
        claim(EMAIL_VERIFIED_CLAIM, "false")
    ]));
    test:assertEquals(response.statusCode, 200);
    test:assertEquals(takeCalls().length(), 0);
}

@test:Config
function testUnverifiedChangeIsSyncedAsVerifiedWhenVerificationIsNotRequired() returns error? {

    http:Response response = check deliver(profileUpdate("unverified", "enrolled", updatedClaims = [
        claim(EMAIL_CLAIM, "new@example.com"),
        claim(MOBILE_CLAIM, "+94771111111")
    ]), secret = "unverified-webhook-secret");
    test:assertEquals(response.statusCode, 200);
    RecordedCall[] calls = takeCalls();
    test:assertEquals(calls.length(), 2);
    test:assertEquals(calls[1].method, "PATCH");
    test:assertEquals(calls[1].body, {
        email: "new@example.com",
        emailVerified: true,
        phoneNumber: "+94771111111",
        phoneNumberVerified: true
    });
}

@test:Config
function testUnrelatedChangeMakesNoCalls() returns error? {

    http:Response response = check deliver(profileUpdate("acme.com", "enrolled", updatedClaims = [
        claim("http://wso2.org/claims/givenname", "Alice")
    ]));
    test:assertEquals(response.statusCode, 200);
    test:assertEquals(takeCalls().length(), 0);
}

@test:Config
function testUserWithoutAuthenticatorsIsSkipped() returns error? {

    json[] claims = [claim(EMAIL_CLAIM, "new@example.com"), claim(EMAIL_VERIFIED_CLAIM, "true")];
    http:Response response = check deliver(profileUpdate("acme.com", "not-enrolled", updatedClaims = claims));
    test:assertEquals(response.statusCode, 200);
    test:assertEquals(takeCalls().length(), 1);

    response = check deliver(profileUpdate("acme.com", "unknown", updatedClaims = claims));
    test:assertEquals(response.statusCode, 200);
    test:assertEquals(takeCalls().length(), 1);
}

@test:Config
function testAuthsignalFailureAsksForRedelivery() returns error? {

    http:Response response = check deliver(profileUpdate("acme.com", "unavailable", updatedClaims = [
        claim(EMAIL_CLAIM, "new@example.com"),
        claim(EMAIL_VERIFIED_CLAIM, "true")
    ]));
    test:assertEquals(response.statusCode, 503);
    // maxAttempts = 2 in tests/Config.toml.
    test:assertEquals(takeCalls().length(), 2);
}

@test:Config
function testSyncCanBeTurnedOff() returns error? {

    json payload = profileUpdate("nodelete", "enrolled", updatedClaims = [
        claim(EMAIL_CLAIM, "new@example.com"),
        claim(EMAIL_VERIFIED_CLAIM, "true")
    ]);
    http:Response response = check deliver(payload, secret = "nodelete-webhook-secret");
    test:assertEquals(response.statusCode, 200);
    test:assertEquals(takeCalls().length(), 0);
}

// --- User deleted ---

@test:Config
function testDeletedUserIsDeletedOnAuthsignal() returns error? {

    http:Response response = check deliver(userDeleted("acme.com", "d1e2f3a4", "alice"));
    test:assertEquals(response.statusCode, 200);
    RecordedCall[] calls = takeCalls();
    test:assertEquals(calls.length(), 1);
    test:assertEquals(calls[0].method, "DELETE");
    test:assertEquals(calls[0].userId, "d1e2f3a4");
}

@test:Config
function testDeletingUnknownUserSucceeds() returns error? {

    http:Response response = check deliver(userDeleted("acme.com", "missing", "bob"));
    test:assertEquals(response.statusCode, 200);
}

@test:Config
function testDeletionFailureAsksForRedelivery() returns error? {

    http:Response response = check deliver(userDeleted("acme.com", "unavailable", "carol"));
    test:assertEquals(response.statusCode, 503);
}

@test:Config
function testDeletionCanBeTurnedOff() returns error? {

    http:Response response = check deliver(userDeleted("nodelete", "d1e2f3a4", "alice"),
            secret = "nodelete-webhook-secret");
    test:assertEquals(response.statusCode, 200);
    test:assertEquals(takeCalls().length(), 0);
}
