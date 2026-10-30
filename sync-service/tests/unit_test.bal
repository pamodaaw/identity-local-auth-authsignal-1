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

import ballerina/test;

// --- Signature ---

@test:Config
function testSignatureRoundTrip() returns error? {

    byte[] body = "{\"events\":{}}".toBytes();
    string signature = check sign(body, "secret");
    test:assertTrue(signature.startsWith("sha256="));
    test:assertTrue(isValidSignature(body, signature, "secret"));
    test:assertTrue(isValidSignature(body, signature.toUpperAscii().substring(7), "secret"));
    test:assertFalse(isValidSignature(body, signature, "other"));
    test:assertFalse(isValidSignature("{}".toBytes(), signature, "secret"));
    test:assertFalse(isValidSignature(body, "", "secret"));
}

@test:Config
function testKnownSignature() {

    // echo -n 'hello' | openssl dgst -sha256 -hmac 'key'
    test:assertTrue(isValidSignature("hello".toBytes(),
            "sha256=9307b3b915efb5171ff14d8cb55fbcc798c6c0ef1456d66ded1a6aa723a58b7b", "key"));
}

// --- Verified contact details ---

@test:Config
function testValueWithVerifiedFlagIsProven() {

    VerifiedContactDetails details = getVerifiedContactDetails({
        addedClaims: [{uri: MOBILE_CLAIM, value: "+94771111111"}, {uri: MOBILE_VERIFIED_CLAIM, value: "true"}],
        updatedClaims: [{uri: EMAIL_CLAIM, value: " new@example.com "}, {uri: EMAIL_VERIFIED_CLAIM, value: "TRUE"}]
    });
    test:assertEquals(details, {email: "new@example.com", phoneNumber: "+94771111111"});
}

@test:Config
function testValueWithoutVerifiedFlagIsNotProven() {

    VerifiedContactDetails details = getVerifiedContactDetails({
        updatedClaims: [{uri: EMAIL_CLAIM, value: "new@example.com"}, {uri: MOBILE_CLAIM, value: "+94771111111"}]
    });
    test:assertEquals(details, {email: (), phoneNumber: ()});
}

@test:Config
function testVerifiedFlagWithoutValueIsNotProven() {

    VerifiedContactDetails details = getVerifiedContactDetails({
        updatedClaims: [{uri: EMAIL_VERIFIED_CLAIM, value: "true"}, {uri: MOBILE_VERIFIED_CLAIM, value: "true"}]
    });
    test:assertEquals(details, {email: (), phoneNumber: ()});
}

@test:Config
function testRemovalsAndNonE164NumbersAreNotSynced() {

    VerifiedContactDetails details = getVerifiedContactDetails({
        updatedClaims: [{uri: MOBILE_CLAIM, value: "0771111111"}, {uri: MOBILE_VERIFIED_CLAIM, value: "true"}],
        removedClaims: [{uri: EMAIL_CLAIM, value: "old@example.com"}, {uri: EMAIL_VERIFIED_CLAIM, value: "true"}]
    });
    test:assertEquals(details, {email: (), phoneNumber: ()});
}

@test:Config
function testMultiValuedClaimsAreIgnored() {

    VerifiedContactDetails details = getVerifiedContactDetails({
        updatedClaims: [
            {uri: "http://wso2.org/claims/emailAddresses", value: ["a@example.com", "b@example.com"]},
            {uri: EMAIL_VERIFIED_CLAIM, value: "true"}
        ]
    });
    test:assertEquals(details, {email: (), phoneNumber: ()});
}

// --- Authsignal user ID ---

final readonly & TenantConfig byUserId = {name: "acme.com", webhookSecret: "s", authsignalSecretKey: "k"};
final readonly & TenantConfig byUsername = {
    name: "acme.com",
    webhookSecret: "s",
    authsignalSecretKey: "k",
    userIdentifier: USERNAME
};

@test:Config
function testUserIdMode() {

    test:assertEquals(toAuthsignalUserId(byUserId, "d1e2f3a4", "alice", "PRIMARY"), "d1e2f3a4");
    test:assertEquals(toAuthsignalUserId(byUserId, (), "alice", "PRIMARY"), ());
}

@test:Config
function testUsernameMode() {

    test:assertEquals(toAuthsignalUserId(byUsername, "d1e2f3a4", "alice", "PRIMARY"), "alice@acme.com");
    test:assertEquals(toAuthsignalUserId(byUsername, "d1e2f3a4", "alice", "primary"), "alice@acme.com");
    test:assertEquals(toAuthsignalUserId(byUsername, "d1e2f3a4", "alice", "LDAP"), "LDAP/alice@acme.com");
    test:assertEquals(toAuthsignalUserId(byUsername, "d1e2f3a4", "LDAP/alice", "PRIMARY"), "LDAP/alice@acme.com");
    test:assertEquals(toAuthsignalUserId(byUsername, "d1e2f3a4", (), "PRIMARY"), ());
}

@test:Config
function testSuperTenantAndAsgardeoPrimaryStoreAreLeftOut() {

    test:assertEquals(toQualifiedUsername("alice", "PRIMARY", "carbon.super", "PRIMARY"), "alice");
    test:assertEquals(toQualifiedUsername("alice", "DEFAULT", "myorg", "DEFAULT"), "alice@myorg");
    test:assertEquals(toQualifiedUsername("alice", (), "myorg", "DEFAULT"), "alice@myorg");
}

// --- Tenants ---

@test:Config
function testTenantLookup() {

    test:assertEquals(findTenant("ACME.com")?.name, "acme.com");
    test:assertEquals(findTenant("other"), ());
    test:assertEquals(findTopicTenant("acme.com.10084a8d.schema.WSO2.v1.event.userDeleted")?.name, "acme.com");
    test:assertEquals(findTopicTenant("acme.10084a8d.schema.WSO2.v1.event.userDeleted"), ());
}

@test:Config
function testPathSegmentEncoding() returns error? {

    test:assertEquals(check encodePathSegment("LDAP/alice smith@acme.com"), "LDAP%2Falice%20smith%40acme.com");
}
