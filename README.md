# Authsignal Authenticator for WSO2 Identity Server

A custom **local authenticator** that adds [Authsignal](https://www.authsignal.com) MFA to a self-hosted WSO2 Identity
Server login flow, plus a flow executor for registration and password recovery. Every journey uses
[Authsignal Flows](https://docs.authsignal.com/api-reference/server-api/start-flow): the connector starts the flow
configured for the journey in the Authsignal Portal, the user completes it in Authsignal's
[pre-built UI](https://docs.authsignal.com/implementation-options/prebuilt-ui/overview), and the connector verifies the
result server side.

| Journey | Flow (default action code) | User at start |
|---|---|---|
| Sign-in | `sign-in` | Authsignal user ID of the WSO2 user |
| Registration | `sign-up` | Email address (or mobile number) entered by the user; no user ID yet |
| Invited-user registration | `sign-up` | Authsignal user ID of the WSO2 user |
| Password recovery | `password-reset` | Authsignal user ID of the WSO2 user |

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
   name = "AuthsignalAuthenticator"
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
| `Authsignal.UserIdentifier` | `userId` | Which value becomes the Authsignal user ID. `userId` is the WSO2 user UUID, which stays stable across renames. `username` is `[DOMAIN/]username[@tenant]`, where the primary domain and `carbon.super` are omitted. Federated users always use their subject identifier. |
| `Authsignal.SignInFlowRef` | `sign-in` | Action code of the Authsignal flow used at sign-in. |
| `Authsignal.RegistrationFlowRef` | `sign-up` | Action code of the Authsignal flow used in registration and invited-user registration flows. |
| `Authsignal.RecoveryFlowRef` | `password-reset` | Action code of the Authsignal flow used in password recovery flows. |
| `Authsignal.SyncContactDetails` | `false` | Enrol the user's email address and mobile number on Authsignal when they change and are verified in WSO2. See [Contact detail sync](#contact-detail-sync). |
| `Authsignal.DeleteUsers` | `true` | Delete the user and their authenticators on Authsignal when the user is deleted in WSO2. See [User deletion](#user-deletion). |
| `Authsignal.PasskeyEnrolledClaim` | _(empty)_ | URI of the local claim set to whether the user has a passkey on Authsignal, for example `http://wso2.org/claims/authsignalPasskeyEnrolled`. Not updated when empty. See [Passkey enrolled claim](#passkey-enrolled-claim). |

Each Authsignal API call has a fixed 10 second timeout. It is not configurable, so that one tenant cannot hold server
threads for long periods.

### App-native (API-based) authentication

The sign-in authenticator supports [app-native authentication](https://is.docs.wso2.com/en/latest/references/app-native-authentication/)
as a redirection prompt:

1. When the Authsignal step is reached, the `/oauth2/authn` response lists `AuthsignalAuthenticator` with
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

## Contact detail sync

When `Authsignal.SyncContactDetails` is on for a tenant, the bundle's `AuthsignalUserOperationEventListener` sends
new values of the `http://wso2.org/claims/emailaddress` and `http://wso2.org/claims/mobile` claims to the user's
Authsignal account with Update User (`PATCH /users/{userId}`), marked as verified with `emailVerified` /
`phoneNumberVerified` set to `true`. Authsignal only moves the user's email OTP / magic link and SMS authenticators to
the new values when they are marked as verified, and does so without sending an OTP.

Only values WSO2 has verified are sent: the user's `http://wso2.org/claims/identity/emailVerified` /
`http://wso2.org/claims/identity/phoneVerified` claim must be `true` after the update. Unverified values should be
changed through Authsignal's email and phone update flows instead.

- It covers every way the claims change: Console, My Account, SCIM and the user store APIs.
- When email or mobile verification on update is enabled, the change is synced only after the user verifies it,
  because the claim itself only changes then.
- Removed claims are not synced.
- A mobile number that is not in E.164 format is not synced.
- Users who do not exist on Authsignal are skipped. Federated (JIT provisioned) users are identified on Authsignal by
  their subject identifier and are not synced.
- A failed sync never fails the profile update. A warning is logged and Authsignal keeps the old value.

## User deletion

When `Authsignal.DeleteUsers` is on for a tenant (the default), `AuthsignalUserOperationEventListener` deletes the
user and their authenticators on Authsignal with Delete User (`DELETE /users/{userId}`) when the user is deleted in
WSO2. This stops a new user who is given the same Authsignal user ID, for example the same username with
`Authsignal.UserIdentifier` set to `username`, from inheriting the deleted user's authenticators.

- It covers every way a user is deleted: Console, SCIM and the user store APIs.
- The Authsignal user ID is resolved before the deletion, while the user still exists, and the user is deleted on
  Authsignal only after the deletion succeeds in WSO2.
- Users who do not exist on Authsignal are skipped.
- A failed call never fails the user deletion. A warning is logged and the user must be deleted in the Authsignal
  Portal.

## Registration and password recovery flows

The bundle also registers **`AuthsignalExecutor`**, which adds Authsignal to the flows built in Console > **Flows**:
self registration, invited-user registration and password recovery. It works with the hosted portal (`/accounts`).

### Registration

During registration the WSO2 user does not exist yet. The executor starts the `sign-up` flow with the email address
the user entered as `user.email` and the E.164 mobile number as `hints.phoneNumber` (or with the mobile number as
`user.phoneNumber` if there is no email address), and keeps the returned `challengeId` in the flow context. The user
verifies the email address and phone number in the pre-built UI.

On return the executor verifies the flow and checks that the email address (or phone number) it started with is among
the verified authenticators, so a token from another sign-up cannot be replayed (ASIG-60008). Once the registration
flow creates the user, the bundle's **`AuthsignalFlowExecutionListener`** calls Identify User
(`POST /identify {userId, challengeId}`), which moves everything enrolled in the flow to the user's Authsignal user ID,
and saves the verified email address and phone number on the user, with the email / phone verified claims set to
`true`. A failure there is logged and does not fail the registration, as the user is already created. If the
registration is pending approval, the user is not created when the flow completes and is not linked.

### Passkey enrolled claim

When `Authsignal.PasskeyEnrolledClaim` is set for a tenant, whenever an Authsignal flow succeeds the claim with that
URI (for example `http://wso2.org/claims/authsignalPasskeyEnrolled`) is set to `true` if the user has a passkey on Authsignal (a `PASSKEY` authenticator on the user, or a `PASSKEY` step
completed in the flow, such as one enrolled in it), and to `false` otherwise. In registration the claim is saved with
the verified contact details once the user is created; in the other flows the executor saves it right after the
verification. The `AuthsignalAuthenticator` saves it the same way after every successful sign-in flow, so a passkey
enrolled or removed on Authsignal is reflected on the next login (federated users, who have no local profile, are
skipped). Add the claim to the local claim dialect first. When the property is empty (the default), no claim is
updated. A failure to save it is logged and does not fail the flow or the login.

### Round trip

```text
AuthsignalExecutor ── POST /flows {actionCode, user, hints, redirectUrl = <portal>?code=<nonce>&state=<nonce>}
        └─ portal redirects to challengeUrl (Authsignal pre-built UI)
                                      │
                    302 back to <portal>?code=<nonce>&state=<nonce>&challenge_token=<token>
                                      │
portal resumes the flow with {code, state, challenge_token}
AuthsignalExecutor ── checks both nonces (one-time), then POST /flows/verify {actionCode, challengeToken}
        └─ continues only if action.state = CHALLENGE_SUCCEEDED and the flow belongs to this user
```

**Portal requirement:** Verify Flow needs the `challenge_token` Authsignal appends to the redirect URL; the token
returned by Start Flow is invalidated as the user completes steps. The executor therefore requires `challenge_token`
next to `code` and `state`. The hosted portal (`accounts/execution-flow.jsp`) must post it back when it resumes the
flow; current versions post only `code` and `state`.

### Setup

1. In the Authsignal Portal, configure the `sign-up` and `password-reset` flows (or the action codes set in
   `Authsignal.RegistrationFlowRef` / `Authsignal.RecoveryFlowRef`). For `sign-up`, verify the email address and then
   the phone number.
2. In Console > **Flows**, add the **Authsignal** node:
   - **Registration:** after the attribute collection form and **before** the user onboarding step. Collect the email
     address or mobile number in the form.
   - **Password recovery:** after the user is identified and before the password reset step.

   Like Email OTP, the node needs no connection. The Console's password recovery check accepts only Email OTP,
   SMS OTP, Magic Link or authentication executors (which require a connection) as the recovery factor, so keep one
   of those before the reset step and use Authsignal as an extra check.

In password recovery, only verifications with authenticators the user already had are accepted (ASIG-60017). If the
flow enrolled a new authenticator, the recovery fails, as whoever started it could otherwise enrol their own. Unknown
users get a generic error.

## Troubleshooting

Enable debug logs in `<IS_HOME>/repository/conf/log4j2.properties`:

```properties
logger.authsignal.name = org.wso2.carbon.identity.local.auth.authsignal
logger.authsignal.level = DEBUG
```

| Error code | Meaning |
|---|---|
| ASIG-60001 | No user identified before the Authsignal step. Move it to step 2 or later. |
| ASIG-60002 | The tenant has not set `__secret__.Authsignal.SecretKey`. |
| ASIG-60004 | The Authsignal user ID of the user could not be resolved. |
| ASIG-60005 / 60006 | Start Flow / Verify Flow failed. Check the tenant's secret key, region, flow action codes and network egress. |
| ASIG-60007 | The user failed or abandoned the flow. |
| ASIG-60008 | The challenge token does not belong to the user or registration this flow started. |
| ASIG-60011 | The `challenge_token` is missing on return. For registration and recovery, check that the portal forwards it. |
| ASIG-60012 | The tenant's `Authsignal.Region` is not one of `us`, `eu`, `au`, `ca`, `uk`. |
| ASIG-60013 | The tenant's Authsignal configuration could not be read. |
| ASIG-60015 | The flow has no portal URL to return to after the challenge. |
| ASIG-60016 / 60017 | Password recovery: the user does not exist / enrolled a new authenticator instead of verifying an existing one. |
| ASIG-60018 | The `code` / `state` returned to the flow do not match (forged, or a reused link). |
| ASIG-60019 | Registration: neither an email address nor an E.164 mobile number was entered. |

## Limitations / future work

- Second-factor only. Using it as a passwordless first factor would need an identifier-first step or the client-side
  passkey flow from [authsignal-wso2-authenticator](https://github.com/authsignal-examples/authsignal-wso2-authenticator).
- The secret key is masked by the REST API but stored unencrypted with the tenant's resident IdP properties, as with
  other governance connectors. Encrypting it at rest would need WSO2's secret management service.
- The connector may not appear as a form in the Console, which has dedicated screens for known connectors. The REST
  API always works.
