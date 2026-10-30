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

// A stand-in for the Authsignal Server API on port 9091 that records the calls it receives. Users:
// - enrolled: enrolled with old verified contact details
// - current: enrolled and already holds the values the tests send
// - not-enrolled: known but without authenticators
// - unavailable: every call fails with 503
// - any other ID: unknown (404) on GET and PATCH, deleted on DELETE

type RecordedCall record {|
    string method;
    string userId;
    string authorization;
    json body;
|};

isolated RecordedCall[] recordedCalls = [];

isolated function recordCall(string method, string userId, http:Request request) {

    json body = ();
    if method == "PATCH" {
        json|error payload = request.getJsonPayload();
        body = payload is json ? payload : ();
    }
    string|http:HeaderNotFoundError authorization = request.getHeader("Authorization");
    RecordedCall call = {
        method,
        userId,
        authorization: authorization is string ? authorization : "",
        body: body.cloneReadOnly()
    };
    lock {
        recordedCalls.push(call.cloneReadOnly());
    }
}

isolated function takeCalls() returns RecordedCall[] {

    lock {
        RecordedCall[] calls = recordedCalls.clone();
        recordedCalls.removeAll();
        return calls.cloneReadOnly();
    }
}

service /v1 on new http:Listener(9091) {

    isolated resource function get users/[string userId](http:Request request) returns json|http:NotFound|http:ServiceUnavailable {

        recordCall("GET", userId, request);
        match userId {
            "enrolled" => {
                return {
                    userId,
                    isEnrolled: true,
                    email: "old@example.com",
                    emailVerified: true,
                    phoneNumber: "+94770000000",
                    phoneNumberVerified: true
                };
            }
            "current" => {
                return {
                    userId,
                    isEnrolled: true,
                    email: "new@example.com",
                    emailVerified: true,
                    phoneNumber: "+94771111111",
                    phoneNumberVerified: true
                };
            }
            "not-enrolled" => {
                return {userId, isEnrolled: false, email: null};
            }
            "unavailable" => {
                return <http:ServiceUnavailable>{};
            }
        }
        return <http:NotFound>{};
    }

    isolated resource function patch users/[string userId](http:Request request) returns json|http:NotFound {

        recordCall("PATCH", userId, request);
        if userId == "enrolled" || userId == "current" {
            return {userId};
        }
        return <http:NotFound>{};
    }

    isolated resource function delete users/[string userId](http:Request request)
            returns json|http:NotFound|http:ServiceUnavailable {

        recordCall("DELETE", userId, request);
        if userId == "unavailable" {
            return <http:ServiceUnavailable>{};
        }
        if userId == "missing" {
            return <http:NotFound>{};
        }
        return {removed: true};
    }
}
