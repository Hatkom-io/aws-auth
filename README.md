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

// Sign out
await auth.signOut()
```

## API

- `authenticateUser({ email, password })` — sign in, returns session or `'new-password-required'`
- `getCurrentSessionToken()` — returns current access JWT, refreshing if needed
- `signOut()` — signs out the current user
- `completeNewPasswordChallenge({ username, newPassword })` — complete a new password challenge
- `forgotPassword(username)` — initiate forgot password flow
- `forgotPasswordSubmit({ username, verificationCode, password })` — submit new password
- `resendVerificationCode(username)` — resend email verification code
- `verifyUserEmail({ username, code })` — confirm email registration
