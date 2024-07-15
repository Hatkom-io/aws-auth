"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AWSAuthClient = void 0;
const amazon_cognito_identity_js_1 = require("amazon-cognito-identity-js");
class AWSAuthClient {
    userPool;
    constructor(UserPoolId, ClientId) {
        this.userPool = new amazon_cognito_identity_js_1.CognitoUserPool({
            UserPoolId,
            ClientId,
        });
    }
    signOut = async () => {
        const user = this.userPool.getCurrentUser();
        if (!user) {
            return;
        }
        try {
            await new Promise((resolve) => {
                user.signOut(resolve);
            });
        }
        catch (error) {
            console.error('SignOut error', { extra: JSON.stringify(error) });
        }
    };
    verifyUser = ({ username, code }) => {
        return new Promise((resolve, reject) => {
            this.cognitoUser(username).verifyAttribute('email', code, {
                onSuccess: resolve,
                onFailure: reject,
            });
        });
    };
    forgotPassword = (username) => {
        return new Promise((resolve, reject) => {
            this.cognitoUser(username).forgotPassword({
                onSuccess: resolve,
                onFailure: reject,
            });
        });
    };
    forgotPasswordSubmit = ({ username, verificationCode, password, }) => {
        return new Promise((resolve, reject) => {
            this.cognitoUser(username).confirmPassword(verificationCode, password, {
                onSuccess: resolve,
                onFailure: reject,
            });
        });
    };
    authenticateUser = ({ email, password }) => {
        const authenticationDetails = new amazon_cognito_identity_js_1.AuthenticationDetails({
            Username: email,
            Password: password,
        });
        return new Promise((resolve, reject) => {
            this.cognitoUser(email).authenticateUser(authenticationDetails, {
                onSuccess: resolve,
                onFailure: reject,
                newPasswordRequired: () => {
                    resolve('new-password-required');
                },
            });
        });
    };
    getCurrentSessionToken = async () => {
        const currentUser = this.userPool.getCurrentUser();
        if (!currentUser) {
            return null;
        }
        const session = await new Promise((resolve, reject) => {
            currentUser.getSession((err, s) => {
                if (err || !s) {
                    reject(err);
                }
                else {
                    resolve(s);
                }
            });
        });
        const valid = this.isValid(session.getAccessToken().getExpiration());
        if (valid) {
            return session.getAccessToken().getJwtToken();
        }
        const updatedSession = await new Promise((resolve, reject) => {
            currentUser.refreshSession(session.getRefreshToken(), (error, value) => {
                if (error) {
                    reject(error);
                }
                else {
                    resolve(value);
                }
            });
        });
        return updatedSession.getAccessToken().getJwtToken();
    };
    isValid = (tokenExpiration) => {
        const now = Math.floor(new Date().getTime() / 1000);
        const adjusted = now + 15;
        return adjusted < tokenExpiration;
    };
    cognitoUser = (() => {
        let user;
        return (username) => {
            if (!user) {
                user = new amazon_cognito_identity_js_1.CognitoUser({
                    Username: username,
                    Pool: this.userPool,
                });
            }
            return user;
        };
    })();
}
exports.AWSAuthClient = AWSAuthClient;
//# sourceMappingURL=auth.js.map