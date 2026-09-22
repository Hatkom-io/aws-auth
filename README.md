# AWS Auth Client

A lightweight AWS Cognito authentication client built on top of `amazon-cognito-identity-js`.

## Install

```sh
npm i @hatkom/aws-auth
```

## Usage

```ts
import { AWSAuthClient } from '@hatkom/aws-auth'

const auth = new AWSAuthClient('us-east-1_xxxxxxx', 'xxxxxxxxxxxxxxxxxxxxxxxxxx')

// Sign in
const session = await auth.authenticateUser({ email: 'user@example.com', password: 'password' })

// Get current session token (auto-refreshes if expired)
const token = await auth.getCurrentSessionToken()
const idToken = await auth.getCurrentSessionToken('id')

// Adopt a session obtained elsewhere (e.g. a server-mediated sign-in)
await auth.adoptSession({ username, idToken, accessToken, refreshToken })

// Sign out. Rejects when Cognito did not acknowledge the revocation
await auth.signOut()
```

## API

- `authenticateUser({ email, password })` — sign in, returns session or `'new-password-required'`
- `getCurrentSessionToken(tokenUse?)` — returns the current JWT, refreshing if needed. `tokenUse` is `'access'` (default) or `'id'`
- `adoptSession({ username, idToken, accessToken, refreshToken })` — store a session obtained outside the browser, so the SDK handles renewal, revocation and storage from then on
- `signOut()` — signs out the current user; rejects when the refresh token revocation failed
- `completeNewPasswordChallenge({ username, newPassword })` — complete a new password challenge
- `forgotPassword(username)` — initiate forgot password flow
- `forgotPasswordSubmit({ username, verificationCode, password })` — submit new password
- `resendVerificationCode(username)` — resend email verification code
- `verifyUserEmail({ username, code })` — confirm email registration

### `signOut`

Rejects when the revocation failed, so a caller that must guarantee the session ended has
something to catch. Two distinct failures reach the same rejection:

- the SDK could not refresh the session before revoking it — it returns **without clearing its
  cached tokens**, so the refresh token is live both remotely and locally
- the `RevokeToken` call itself failed — the SDK clears its cached tokens first, so storage is
  empty while the refresh token stays usable at Cognito until it expires

Emptied storage therefore says nothing about whether the remote session ended; only a resolved
`signOut()` does. Sign-out flows that navigate away should still do so on rejection, after
handling the local tokens themselves.

### `adoptSession`

Use it when sign-in happens on your server (`InitiateAuth` / `RespondToAuthChallenge`) and the
browser receives a finished `AuthenticationResult`. The tokens are cached under the same storage
keys a browser-side login writes, so `getCurrentSessionToken()`, refresh and `signOut()` all work
afterwards, including across a page reload.

`username` must be the **Cognito username**, not the e-mail. A pool configured with
`usernameAttributes: ['email']` generates a UUID internal username, and the cache keys are built
from it — passing the e-mail leaves nothing findable on the next page load.

If your API authorizes on e-mail, read the ID token (`getCurrentSessionToken('id')`): with a
UUID username the access token carries no `email` claim.
