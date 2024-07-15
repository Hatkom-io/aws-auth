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

type VerifyUserArgs = { username: string; code: string }

export class AWSAuthClient {
  private userPool: CognitoUserPool

  constructor(UserPoolId: string, ClientId: string) {
    this.userPool = new CognitoUserPool({
      UserPoolId,
      ClientId,
    })
  }

  signOut = async () => {
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

  verifyUser = ({ username, code }: VerifyUserArgs) => {
    return new Promise((resolve, reject) => {
      this.cognitoUser(username).verifyAttribute('email', code, {
        onSuccess: resolve,
        onFailure: reject,
      })
    })
  }

  forgotPassword = (username: string) => {
    return new Promise((resolve, reject) => {
      this.cognitoUser(username).forgotPassword({
        onSuccess: resolve,
        onFailure: reject,
      })
    })
  }

  forgotPasswordSubmit = ({
    username,
    verificationCode,
    password,
  }: ForgotPasswordSubmitArgs) => {
    return new Promise((resolve, reject) => {
      this.cognitoUser(username).confirmPassword(verificationCode, password, {
        onSuccess: resolve,
        onFailure: reject,
      })
    })
  }

  authenticateUser = ({ email, password }: AuthenticateUserArgs) => {
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
