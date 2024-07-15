import { CognitoUserSession } from 'amazon-cognito-identity-js';
type AuthenticateUserArgs = {
    email: string;
    password: string;
};
type ForgotPasswordSubmitArgs = {
    username: string;
    verificationCode: string;
    password: string;
};
type VerifyUserArgs = {
    username: string;
    code: string;
};
export declare class AWSAuthClient {
    private userPool;
    constructor(UserPoolId: string, ClientId: string);
    signOut: () => Promise<void>;
    verifyUser: ({ username, code }: VerifyUserArgs) => Promise<unknown>;
    forgotPassword: (username: string) => Promise<unknown>;
    forgotPasswordSubmit: ({ username, verificationCode, password, }: ForgotPasswordSubmitArgs) => Promise<unknown>;
    authenticateUser: ({ email, password }: AuthenticateUserArgs) => Promise<CognitoUserSession | "new-password-required">;
    getCurrentSessionToken: () => Promise<string | null>;
    private isValid;
    private cognitoUser;
}
export {};
