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

import ballerina/crypto;

const SIGNATURE_PREFIX = "sha256=";

# Check the `x-hub-signature` header of a webhook delivery: HMAC-SHA256 of the raw body, keyed with the webhook secret,
# in the form `sha256=<hex>`.
#
# + body - Raw request body, as received
# + signature - Value of the `x-hub-signature` header
# + secret - Secret of the webhook
# + return - Whether the signature matches
isolated function isValidSignature(byte[] body, string signature, string secret) returns boolean {

    string value = signature.trim();
    if value.toLowerAscii().startsWith(SIGNATURE_PREFIX) {
        value = value.substring(SIGNATURE_PREFIX.length());
    }
    byte[]|error expected = crypto:hmacSha256(body, secret.toBytes());
    if expected is error {
        return false;
    }
    return constantTimeEquals(expected.toBase16(), value.toLowerAscii());
}

// Compare two strings in time that depends only on their length, so the comparison does not leak how much of a
// signature matched.
isolated function constantTimeEquals(string a, string b) returns boolean {

    byte[] x = a.toBytes();
    byte[] y = b.toBytes();
    if x.length() != y.length() {
        return false;
    }
    int diff = 0;
    foreach int i in 0 ..< x.length() {
        diff = diff | (x[i] ^ y[i]);
    }
    return diff == 0;
}

# Build the `x-hub-signature` value of a body. Used by the tests and by local tooling.
#
# + body - Raw request body
# + secret - Secret of the webhook
# + return - Header value in the form `sha256=<hex>`
isolated function sign(byte[] body, string secret) returns string|error {

    byte[] mac = check crypto:hmacSha256(body, secret.toBytes());
    return SIGNATURE_PREFIX + mac.toBase16();
}
