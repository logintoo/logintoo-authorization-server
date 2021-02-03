# Logintoo Authorization Server

This is an implementation of OAuth 2.0 Authorization Server ([RFC 6749](https://tools.ietf.org/html/rfc6749) with the [RFC 7636, PKCE](https://tools.ietf.org/html/rfc7636) extension) for **passwordless authentication**. The server generates a One-Time Password (OTP) for each login and emails it to a user. Try it out at [sample.logintoo.com](https://sample.logintoo.com).

## API

[API reference](https://app.swaggerhub.com/apis-docs/logintoo/logintoo-authorization-server/2020-11)

The **/aws-cdk** folder contains everything you need to deploy the Authorization Server API into AWS infrastructure using [AWS Cloud Development Kit](https://aws.amazon.com/cdk/) (AWS CDK). This stack defines the API to be deployed in AWS API Gateway, DynamoDB tables, and Lambda functions.

This API uses [SendGrid](https://sendgrid.com) to send emails with OTPs, so you need an SendGrid account.

Create a Customer managed key in AWS Key Management Service (KMS): Asymmetric, for Sign and verify, RSA_4096.

Copy **/aws-cdk/2020-11/auth-api/lib/Config.js.example** to **/aws-cdk/2020-11/auth-api/lib/Config.js** and customize parameters:

- **API_VERSION**: The API version. The current version is '*2020-11*'. If you change this, rename the corresponding sub-folder of the static website. Must be a URL-safe string.
- **PROFILE.\<account\>**, **PROFILE.\<account\>.\<region\>**: Specify the AWS account ID and the region where the stack is going to be deployed. You can create settings for multiple accounts/regions for different deployment environments (test, staging, prod, etc.).
- AWS Account/Region-specific parameters:
  - **API_DOMAIN.name**: API domain name.
  - **API_DOMAIN.certificateArn**: The AWS ARN of your Certificate for the API domain.
  - **KEY_ARN**: The AWS ARN of the key for sign JWTs with, the key is stored in AWS KMS.
  - **ISS**: The 'iss' (Issuer) claim of the Access Token, identifies this Authorization Server.
  - **SENDGRID_API_KEY**: SendGrid API key.
  - **SYS_EMAIL_FROM**: The FROM address for OTP emails. The domain or email address must be verified in SendGrid.
  - **CLIENTS_TABLE_NAME**, **CACHE_TABLE_NAME**, **NORMALIZED_EMAIL_INDEX_NAME**, **AUTH_CODE_INDEX_NAME**: DynamoDB tables and indexes names.

Dependencies: [jsonschema](https://github.com/tdegrunt/jsonschema) and [sendgrid-nodejs](https://github.com/sendgrid/sendgrid-nodejs/tree/main/packages/mail).
Install them into the **/aws-cdk/2020-11/auth-api/lambda/** folder:
```
npm install jsonschema
npm install @sendgrid/mail
```

The Clients DynamoDB table scheme. Each record represents an application that is registered on this server.
```
{
  "accessTokenExp": 600,
  "appDisplayName": "Application Name",
  "extendRefreshToken": true,
  "id": "00000000-0000-4000-A000-000000000000",
  "otpAttempts": 5,
  "otpEmailFrom": "app@example.com",
  "otpEmailLogoSrc": "https://example.com/logo.png",
  "otpEmailSubj": "Your Access Code",
  "otpLength": 5,
  "otpTimeout": 7,
  "redirectURIs": [
    "https://example.com/"
  ],
  "refreshTokenExp": 86400,
  "tokenAud": "api.example.com"
} 
```
- accessTokenExp: Access Token expiration time in seconds, from 60 to 86400 (24 hours). If not specified or out of the range the default value of 3600 (1 hour) will be used.
- appDisplayName: Application Name, used in OTP emails.
- extendRefreshToken: Whether extend the Refresh Token expiration time on each rotation or not.
- id: The application ID, should be an UUID v4.
- otpAttempts: Allowed number of OTP entry attempts, from 1 to 10. If not specified or out of the range the default value of 4 will be used.
- otpEmailFrom: The application owner or support team email address. Will appear in Reply-To header.
- otpEmailLogoSrc: URL of the application logo image.
- otpEmailSubj: Customized Subject of OTP emails.
- otpLength: OTP length, from 4 to 8. If not specified or out of the range the default value of 6 will be used.
- otpTimeout: OTP time-to-live in minutes, from 5 to 30, default is 10 minutes.
- redirectURIs: An array of Redirect URIs. Users will be redirected to one of this URIs after they have authenticated with this server. Must be an array even if there is only one URI.
- refreshTokenExp: Refresh Token expiration time in seconds, from 3600 (1 hour) to 2592000 (30 days), default is 604800 (7 days).
- tokenAud: Access Token aud (Audience) claim.

You need an [AWS](https://aws.amazon.com/) account to deploy the API.

## Web GUI

The **/html** folder contains the static website files.

Copy **/html/js/config.js.example** to **/html/js/config.js** and customize parameters:

- **apiURL**: Authorization Server API endpoint URL.


*The static website utilizes [jQuery](https://jquery.com) and [Materialize](https://materializecss.com).*
