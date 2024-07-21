import {
  AuthenticationDetails,
  CognitoUser,
  CognitoUserPool,
  CognitoUserSession,
} from 'amazon-cognito-identity-js'

type AuthenticateUserArgs = {
  email: string
  password: string
}

type ForgotPasswordSubmitArgs = {
  username: string
  verificationCode: string
  password: string
}

type VerifyUserEmailArgs = {
  username: string
  code: string
}

type CognitoPoolWithAsyncStorage = CognitoUserPool & {
  storage: { sync: (callback: unknown) => void }
}

const needsToSyncStorage = (
  userPool: CognitoUserPool,
): userPool is CognitoPoolWithAsyncStorage =>
  !!(
    'storage' in userPool &&
    typeof userPool.storage === 'function' &&
    'sync' in userPool.storage &&
    typeof userPool.storage.sync === 'function'
  )

export class AWSAuthClient {
  private userPool: CognitoUserPool
  private syncStoragePromise: Promise<void>

  constructor(UserPoolId: string, ClientId: string) {
    this.userPool = new CognitoUserPool({
      UserPoolId,
      ClientId,
    })

    this.syncStoragePromise = new Promise((resolve) => {
      if (needsToSyncStorage(this.userPool)) {
        this.userPool.storage.sync(resolve)

        return
      }

      resolve()
    })
  }

  signOut = async () => {
    await this.syncStoragePromise

    const user = this.userPool.getCurrentUser()

    if (!user) {
      return
    }

    try {
      await new Promise<void>((resolve) => {
        user.signOut(resolve)
      })
    } catch (error) {
      console.error('SignOut error', { extra: JSON.stringify(error) })
    }
  }

  resendVerificationCode = async (username: string) => {
    await this.syncStoragePromise

    return new Promise((resolve, reject) => {
      this.cognitoUser(username).resendConfirmationCode((err, result) => {
        if (err) {
          reject(err)

          return
        }

        resolve(result)
      })
    })
  }

  verifyUserEmail = async ({ username, code }: VerifyUserEmailArgs) => {
    await this.syncStoragePromise

    return new Promise((resolve, reject) => {
      this.cognitoUser(username).confirmRegistration(code, true, (error) => {
        if (error) {
          reject(error)

          return
        }

        resolve(true)
      })
    })
  }

  forgotPassword = async (username: string) => {
    await this.syncStoragePromise

    return new Promise((resolve, reject) => {
      this.cognitoUser(username).forgotPassword({
        onSuccess: resolve,
        onFailure: reject,
      })
    })
  }

  forgotPasswordSubmit = async ({
    username,
    verificationCode,
    password,
  }: ForgotPasswordSubmitArgs) => {
    await this.syncStoragePromise

    return new Promise((resolve, reject) => {
      this.cognitoUser(username).confirmPassword(verificationCode, password, {
        onSuccess: resolve,
        onFailure: reject,
      })
    })
  }

  authenticateUser = async ({ email, password }: AuthenticateUserArgs) => {
    await this.syncStoragePromise

    const authenticationDetails = new AuthenticationDetails({
      Username: email,
      Password: password,
    })

    return new Promise<CognitoUserSession | 'new-password-required'>(
      (resolve, reject) => {
        this.cognitoUser(email).authenticateUser(authenticationDetails, {
          onSuccess: resolve,
          onFailure: reject,
          newPasswordRequired: () => {
            resolve('new-password-required')
          },
        })
      },
    )
  }

  getCurrentSessionToken = async () => {
    await this.syncStoragePromise

    const currentUser = this.userPool.getCurrentUser()

    if (!currentUser) {
      return null
    }

    const session = await new Promise<CognitoUserSession>((resolve, reject) => {
      currentUser.getSession(
        (err: Error | null, s: CognitoUserSession | null) => {
          if (err || !s) {
            reject(err)
          } else {
            resolve(s)
          }
        },
      )
    })

    const valid = this.isValid(session.getAccessToken().getExpiration())

    if (valid) {
      return session.getAccessToken().getJwtToken()
    }

    const updatedSession = await new Promise<CognitoUserSession>(
      (resolve, reject) => {
        currentUser.refreshSession(
          session.getRefreshToken(),
          (error, value: CognitoUserSession) => {
            if (error) {
              reject(error)
            } else {
              resolve(value)
            }
          },
        )
      },
    )

    return updatedSession.getAccessToken().getJwtToken()
  }

  private isValid = (tokenExpiration: number) => {
    const now = Math.floor(new Date().getTime() / 1000)
    const adjusted = now + 15

    return adjusted < tokenExpiration
  }

  private cognitoUser = (() => {
    let user: CognitoUser | undefined

    return (username: string) => {
      if (!user) {
        user = new CognitoUser({
          Username: username,
          Pool: this.userPool,
        })
      }

      return user
    }
  })()
}
