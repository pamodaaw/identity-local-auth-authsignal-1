# Authsignal Authenticator for WSO2 Identity Server

A custom **local authenticator** that adds [Authsignal](https://www.authsignal.com) MFA to a self-hosted WSO2 Identity
Server login flow, plus a flow executor for registration and password recovery. Every journey uses
[Authsignal Flows](https://docs.authsignal.com/api-reference/server-api/start-flow): the connector starts the flow
configured for the journey in the Authsignal Portal, the user completes it in Authsignal's
[pre-built UI](https://docs.authsignal.com/implementation-options/prebuilt-ui/overview), and the connector verifies the
result server side.

| Journey | Flow (default action code of `Authsignal.ActionCode`) | User at start |
|---|---|---|
| Sign-in | `sign-in` | Authsignal user ID of the WSO2 user |
| Registration | `sign-in` | Email address (or mobile number) entered by the user; no user ID yet |
| Invited-user registration | `sign-in` | Authsignal user ID of the WSO2 user |
| Password recovery | `sign-in` | Authsignal user ID of the WSO2 user |

The Authsignal user ID of a WSO2 user is the WSO2 user ID (UUID), which stays the same when the user is renamed.
Federated users use their subject identifier.

Email and phone update journeys are handled in a separate effort.

## How it works

```text
Step 1 (e.g. Username & Password) identifies the user
        │
        ▼
AuthsignalAuthenticator ── POST /v1/flows {actionCode, user: {userId}, redirectUrl} ──▶ Authsignal
        │                    redirectUrl = https://<is>/commonauth?sessionDataKey=<ctx>
        │
        └─ 302 to challengeUrl (Authsignal pre-built UI: passkey, TOTP, SMS, email OTP, …)
                                       │
                                       ▼
                     302 back to /commonauth?sessionDataKey=<ctx>&challenge_token=<token>
                                       │
AuthsignalAuthenticator ── POST /v1/flows/verify {actionCode, challengeToken} ──▶ Authsignal
        │
        └─ step completes only if action.state = CHALLENGE_SUCCEEDED and user.userId matches the user
           the flow was started for
```

The secret key never leaves the server. Matching `user.userId` binds the returned token to the user of this login. A
token for another user is rejected (ASIG-60008). A `challenge_token` parameter is ignored unless this login started a
flow. The rules and steps of each journey (whether to challenge, which methods to offer) are configured on the flow in
the Authsignal Portal.

## Build

Requires JDK 11+ and Maven 3.6+.

```bash
mvn clean install
```

The OSGi bundle is created at
`components/org.wso2.carbon.identity.local.auth.authsignal/target/org.wso2.carbon.identity.local.auth.authsignal-1.0.0-SNAPSHOT.jar`.

## Deploy

1. Copy the JAR to `<IS_HOME>/repository/components/dropins/`.
2. Enable the authenticator by adding the following to `<IS_HOME>/repository/conf/deployment.toml`, then restart the
   server. Without it the authenticator is registered as disabled and is not listed in the Console. No parameters are
   needed: all other configuration is tenant-wise.

   ```toml
   [[authentication.custom_authenticator]]
   name = "authsignal-authenticator"
   ```
3. Configure Authsignal for each tenant (see below).
4. In the Console, open the application > **Login Flow**. Add **Authsignal** as the **second** step, after a step that
   identifies the user (Username & Password, Identifier First, or a federated IdP).

## Configuration (tenant-wise)

Each tenant (or Asgardeo organization) has its own Authsignal configuration. It is an identity governance connector
(`authsignal-authenticator`, category *Multi Factor Authenticators*) and is stored with the tenant's resident IdP.
There are no server-wide settings.

Tenant admins manage it with the identity-governance REST API. The path IDs are the base64url forms of the category
and connector names:

```bash
curl -X PATCH \
  "https://<host>/t/<tenant-domain>/api/server/v1/identity-governance/TXVsdGkgRmFjdG9yIEF1dGhlbnRpY2F0b3Jz/connectors/YXV0aHNpZ25hbC1hdXRoZW50aWNhdG9y" \
  -H "Authorization: Bearer <token with the identity governance update scope>" \
  -H "Content-Type: application/json" \
  -d '{
    "operation": "UPDATE",
    "properties": [
      { "name": "__secret__.Authsignal.SecretKey", "value": "<Authsignal API key>" },
      { "name": "Authsignal.Region", "value": "us" }
    ]
  }'
```

Send a `GET` to the same URL to read the configuration. The secret key is a confidential property, so the API
masks it in responses. Only send the properties you want to change; the others keep their defaults.

| Property | Default | Description |
|---|---|---|
| `__secret__.Authsignal.SecretKey` | – (required) | Authsignal Server API key (Authsignal Portal > Settings > API keys). |
| `Authsignal.Region` | `us` | Region of the Authsignal tenant: `us`, `eu`, `au`, `ca` or `uk`, which selects the API base URL (`https://api.authsignal.com/v1` or `https://<region>.api.authsignal.com/v1`). Match it to the API Host shown in the Authsignal Portal. Tenants pick a region rather than a URL, so the server only calls Authsignal's own hosts. |
| `Authsignal.ActionCode` | `sign-in` | Action code of the Authsignal flow used at sign-in and in all registration, invited-user registration and password recovery flows. |
| `Authsignal.PasskeyEnrolledClaim` | _(empty)_ | URI of the local claim set to whether the user has a passkey on Authsignal, for example `http://wso2.org/claims/authsignalPasskeyEnrolled`. Not updated when empty. See [Passkey enrolled claim](#passkey-enrolled-claim). |

Each Authsignal API call has a fixed 10 second timeout. It is not configurable, so that one tenant cannot hold server
threads for long periods.

Calls go through the identity server's shared external API client. A call that fails without a response, for example
on a dropped connection or a timeout, is retried. The retry count, connection pool size and connections per route are
the server-wide `[external_api_client]` settings in `deployment.toml`. Calls that get an HTTP error status are not
retried.

### App-native (API-based) authentication

The sign-in authenticator supports [app-native authentication](https://is.docs.wso2.com/en/latest/references/app-native-authentication/)
as a redirection prompt:

1. When the Authsignal step is reached, the `/oauth2/authn` response lists `authsignal-authenticator` with
   `promptType: REDIRECTION_PROMPT`, `requiredParams: ["challenge_token"]` and the pre-built UI URL in
   `metadata.additionalData.redirectUrl`.
2. The application opens that URL in a browser (for example an in-app browser tab). Authsignal sends the user back to
   the application's `redirect_uri` from the authorize request, with `challenge_token` appended.
3. The application posts the token to `/oauth2/authn`:

   ```json
   {
     "flowId": "<flowId>",
     "selectedAuthenticator": {
       "authenticatorId": "<authenticatorId>",
       "params": { "challenge_token": "<challenge_token>" }
     }
   }
   ```

The token is verified server side as in the browser flow. If the authorize request has no `redirect_uri`, Authsignal
redirects to `/commonauth` instead.

### Conditional MFA with adaptive scripts

You can use the authenticator from an adaptive script like any other step, for example:

```js
var onLoginRequest = function (context) {
    executeStep(1, {
        onSuccess: function (context) {
            executeStep(2); // step 2 = Authsignal
        }
    });
};
```

The Authsignal flow decides whether and how the user is challenged. Most risk logic therefore belongs in the
Authsignal Portal, not in the script.

## Keeping users in sync

This bundle does not sync profile changes or user deletions to Authsignal. The [Sync Service](sync-service/README.md)
in `sync-service/` does that: a Ballerina service deployed on Choreo that receives the IS 7.2+ (or Asgardeo) webhooks
**User profile updated** and **User deleted**, sets verified email and mobile changes on the Authsignal user, and
deletes the Authsignal user when the WSO2 user is deleted. Its README covers deployment and the webhook setup.

The reverse direction, Authsignal webhooks (authenticator added, changed or removed) written back into IS, is not
built yet.

## Registration and password recovery flows

The bundle also registers **`AuthsignalExecutor`**, which adds Authsignal to the flows built in Console > **Flows**:
self registration, invited-user registration and password recovery. It works with the hosted portal (`/accounts`).

### Registration

During registration the WSO2 user does not exist yet. The executor starts the configured flow with the email address
the user entered as `user.email` and the E.164 mobile number as `hints.phoneNumber` (or with the mobile number as
`user.phoneNumber` if there is no email address). Nothing is kept in the flow context at this point; everything is read
again from the flow user and the node configuration when the user comes back. The user verifies the email address and
phone number in the pre-built UI.

On return the executor verifies the flow and checks that a completed step of this flow verified the email address (or
phone number) it started with: an `EMAIL_OTP` or `EMAIL_MAGIC_LINK` step for an email address, an `SMS` or `WHATSAPP`
step for a phone number. A flow completed with only a passkey does not verify any contact detail. This also means a
token from another sign-up cannot be replayed (ASIG-60008). The executor then keeps the `challengeId` of the verified
flow in the flow context as `authsignalChallengeId`, the only value it keeps there. Once the registration flow creates
the user, the bundle's **`AuthsignalFlowExecutionListener`** calls Identify User (`POST /identify {userId,
challengeId}`), which moves everything enrolled in the flow to the user's Authsignal user ID. Only when Identify User
succeeds, the listener sets the email verified claim to `true` if the user has an `EMAIL_OTP` or `EMAIL_MAGIC_LINK`
authenticator with the same email address as the user's own, and the phone verified claim to `true` if the user has an
`SMS` or `WHATSAPP` authenticator with the same mobile number as the user's own. If the response has
`action.completedSteps[]`, only the authenticators used in those steps (matched by `userAuthenticatorId`) are
considered; Identify User returns none, so all the user's authenticators of those methods are considered. The passkey
enrolled claim is set the same way, from `PASSKEY` authenticators. The email address and mobile number are never copied
from Authsignal. If the registration is pending approval, the user is not created when the flow completes and is not
linked.

### Pending link

Identify User is called up to 3 times. Only network errors, HTTP 429 and 5xx responses are retried; any other error
(for example an expired challenge) is logged and the link is dropped. If all 3 calls fail, the challenge ID is saved in
the `http://wso2.org/claims/authsignalChallengeId` claim and the registration still completes. At the user's next
sign-in, before redirecting to Authsignal, `AuthsignalAuthenticator` reads the claim and calls Identify User again:

- On success it saves the verified claims and the passkey status as at registration, and clears the claim.
- If Authsignal rejects the call (a 4xx other than 429), it clears the claim, and the user has to enrol their authenticators again.
- On any other error it keeps the claim and the sign-in carries on.

Authsignal keeps a challenge valid for 10 minutes by default (configurable in Authsignal). Add the claim to the local
claim dialect as hidden and read-only, so it is not shown or editable in the Console or My Account.

### Passkey enrolled claim

When `Authsignal.PasskeyEnrolledClaim` is set for a tenant, whenever an Authsignal flow succeeds the claim with that
URI (for example `http://wso2.org/claims/authsignalPasskeyEnrolled`) is set to `true` if the user has a passkey on Authsignal (a `PASSKEY` authenticator on the user, or a `PASSKEY` step
completed in the flow, such as one enrolled in it), and to `false` otherwise. In registration the claim is saved with
the verified contact details once the user is linked; in the other flows the executor saves it right after the
verification. The `AuthsignalAuthenticator` saves it the same way after every successful sign-in flow, so a passkey
enrolled or removed on Authsignal is reflected on the next login (federated users, who have no local profile, are
skipped). Add the claim to the local claim dialect first. When the property is empty (the default), no claim is
updated. A failure to save it is logged and does not fail the flow or the login.

### Round trip

```text
AuthsignalExecutor ── POST /flows {actionCode, user, hints, redirectUrl = <portal>}
        └─ portal redirects to challengeUrl (Authsignal pre-built UI)
                                      │
                    302 back to <portal>?challenge_token=<token>
                                      │
portal resumes the flow with {challenge_token}
AuthsignalExecutor ── POST /flows/verify {actionCode, challengeToken}
        └─ continues only if action.state = CHALLENGE_SUCCEEDED and the flow belongs to this user
```

**Portal requirement:** Verify Flow needs the `challenge_token` Authsignal appends to the redirect URL; the token
returned by Start Flow is invalidated as the user completes steps. The executor therefore requires `challenge_token`.
The hosted portal (`accounts/execution-flow.jsp`) must post it back when it resumes the flow; current versions post
only `code` and `state`, and may also need to stop expecting a `code` in the callback URL.

### Setup

1. In the Authsignal Portal, configure the `sign-in` flow (or the action code set in `Authsignal.ActionCode`). For
   registration, verify the email address and then the phone number.
2. In Console > **Flows**, add the **Authsignal** node:
   - **Registration:** after the attribute collection form and **before** the user onboarding step. Collect the email
     address or mobile number in the form.
   - **Password recovery:** after the user is identified and before the password reset step.

   Like Email OTP, the node needs no connection. The Console's password recovery check accepts only Email OTP,
   SMS OTP, Magic Link or authentication executors (which require a connection) as the recovery factor, so keep one
   of those before the reset step and use Authsignal as an extra check.

   To use a different Authsignal flow for a node, set the `authsignalActionCode` metadata of its executor to the flow's action
   code. For example, use a `sign-up` flow in registration:

   ```json
   "executor": {
     "name": "AuthsignalExecutor",
     "meta": { "authsignalActionCode": "sign-up" }
   }
   ```

   Without it, the node uses `Authsignal.ActionCode`.

In password recovery, the executor accepts any successful Authsignal flow of the user, including one where an
authenticator was enrolled in the flow. Configure the Authsignal flow used for password recovery to only verify
authenticators the user already has, and not to allow enrolment, as whoever starts the recovery could otherwise enrol
their own authenticator and reset the user's password. Use a separate action code for that node (see above) if the
default flow allows enrolment. Unknown users get a generic error.

## Troubleshooting

Enable debug logs in `<IS_HOME>/repository/conf/log4j2.properties`:

```properties
logger.authsignal.name = org.wso2.carbon.identity.local.auth.authsignal
logger.authsignal.level = DEBUG
```

### Login

The authenticator reports these error codes:

| Error code | Meaning |
|---|---|
| ASIG-60001 | No user identified before the Authsignal step. Move it to step 2 or later. |
| ASIG-60002 | The tenant has not set `__secret__.Authsignal.SecretKey`. |
| ASIG-60004 | The Authsignal user ID of the user could not be resolved. |
| ASIG-60005 / 60006 | Start Flow / Verify Flow failed. Check the tenant's secret key, region, flow action codes and network egress. |
| ASIG-60007 | The user failed or abandoned the flow. |
| ASIG-60008 | The challenge token does not belong to the user this flow started. |
| ASIG-60011 | The `challenge_token` is missing on return. |
| ASIG-60012 | The tenant's `Authsignal.Region` is not one of `us`, `eu`, `au`, `ca`, `uk`. |
| ASIG-60013 | The tenant's Authsignal configuration could not be read. |

### Registration and password recovery flows

Like the other flow executors, the executor has no error codes of its own. The flow engine reports its errors as
`FE-65013` (server errors) or `FE-60006` (user errors), and the error description tells the failure apart. Once the
user is known, the description ends with the WSO2 user ID of the user (`User ID: <user ID>`). It never contains the
username, email address or mobile number.

| Error description | Meaning |
|---|---|
| Authsignal is not supported in the flow type: ... | The executor is used in a flow type it does not support. |
| The portal URL to return to after the Authsignal challenge is not available in the flow. | The flow has no portal URL to return to after the challenge. |
| Error while reading the Authsignal configuration of the tenant. | The tenant's Authsignal configuration could not be read. |
| Authsignal secret key is not configured for the tenant. | The tenant has not set `__secret__.Authsignal.SecretKey`. |
| An email address or a mobile number is required to register with Authsignal. | Registration: neither an email address nor an E.164 mobile number was entered. |
| Error while resolving the Authsignal user ID for the user. | The Authsignal user ID of the user could not be resolved. |
| The user could not be verified. | The user could not be found. Kept generic so that it does not reveal whether the user exists. |
| Error while starting the flow on Authsignal. / Error while verifying the flow on Authsignal. | Start Flow / Verify Flow failed. Check the tenant's secret key, region, flow action codes and network egress. |
| Authsignal did not return a challenge URL when starting the flow. | Start Flow returned an incomplete response. |
| Authsignal did not return a challenge ID when verifying the flow. | Registration: Verify Flow returned no `challengeId`, so the user cannot be linked. |
| The Authsignal challenge token is missing in the request. | The `challenge_token` is missing on return. Check that the portal forwards it. |
| The Authsignal challenge was not completed successfully. | The user failed or abandoned the flow. |
| The email address or mobile number verified on Authsignal does not match the one the challenge was started for. | Registration: the challenge token belongs to another registration. |
| The user verified on Authsignal does not match the user the challenge was started for. | The challenge token belongs to another user. |
| The user was verified with an authenticator that was not enrolled before the flow. | Password recovery: the user enrolled a new authenticator instead of verifying an existing one. |

## Limitations / future work

- Second-factor only. Using it as a passwordless first factor would need an identifier-first step or the client-side
  passkey flow from [authsignal-wso2-authenticator](https://github.com/authsignal-examples/authsignal-wso2-authenticator).
- The secret key is masked by the REST API but stored unencrypted with the tenant's resident IdP properties, as with
  other governance connectors. Encrypting it at rest would need WSO2's secret management service.
- The connector may not appear as a form in the Console, which has dedicated screens for known connectors. The REST
  API always works.
