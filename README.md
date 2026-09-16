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

// Sign out
await auth.signOut()
```

## API

- `authenticateUser({ email, password })` — sign in, returns session or `'new-password-required'`
- `getCurrentSessionToken(tokenUse?)` — returns the current JWT, refreshing if needed. `tokenUse` is `'access'` (default) or `'id'`
- `adoptSession({ username, idToken, accessToken, refreshToken })` — store a session obtained outside the browser, so the SDK handles renewal, revocation and storage from then on
- `signOut()` — signs out the current user
- `completeNewPasswordChallenge({ username, newPassword })` — complete a new password challenge
- `forgotPassword(username)` — initiate forgot password flow
- `forgotPasswordSubmit({ username, verificationCode, password })` — submit new password
- `resendVerificationCode(username)` — resend email verification code
- `verifyUserEmail({ username, code })` — confirm email registration

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
