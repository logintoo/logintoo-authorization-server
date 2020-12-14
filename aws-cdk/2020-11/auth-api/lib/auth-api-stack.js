'use strict';
const Config = require('./Config.js');

// This API version. It will be used as an API URI path, e.g. https://api.example.com/<API_VERSION>/auth.
const API_VERSION = '2020-11';

// API domain name and certificate Arn.
const API_DOMAIN_NAME = Config.API_DOMAIN_NAME;
const CERTIFICATE_ARN = Config.CERTIFICATE_ARN;

// The Arn of the key for sign JWTs with, the key is stored in AWS KMS.
const KEY_ARN = Config.KEY_ARN;

// JWT "iss" (issuer) claim.
const ISS = Config.ISS;

// SendGrid API key and template ID.
const SENDGRID_API_KEY = Config.SENDGRID_API_KEY;

// The FROM address for OTP emails. The domain must be verified in SendGrid.
const SYS_EMAIL_FROM = Config.SYS_EMAIL_FROM;

// DynamoDB tables and indexes names.
const CLIENTS_TABLE_NAME = Config.CLIENTS_TABLE_NAME + '-' + API_VERSION;
const CACHE_TABLE_NAME = Config.CACHE_TABLE_NAME + '-' + API_VERSION;
const NORMALIZED_EMAIL_INDEX_NAME = Config.NORMALIZED_EMAIL_INDEX_NAME;
const AUTH_CODE_INDEX_NAME = Config.AUTH_CODE_INDEX_NAME;

// Patterns to be used in the API Gateway models and in Lambda functions.
const CLIENT_ID_PATTERN = '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-4[0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$';

// The length of the code_challenge specified by RFC 7636, section 4.1. Use the same for other codes.
const CODE_CHALLENGE_PATTERN = '^[a-zA-Z0-9-_]{43,128}$';
const CODE_VERIFIER_PATTERN = '^[a-zA-Z0-9-_]{43,128}$';
const STATE_PATTERN = '^[a-zA-Z0-9-_]{43,128}$';
const CODE_PATTERN = '^[a-zA-Z0-9-_]{43,128}$';

// OTP pattern and length range values.
const OTP_PATTERN = '^[0-9]{4,8}$';
const OTP_LENGTH_RANGE = JSON.stringify({min: 4, max: 8, default: 6});

// Allowed Range for the number of OTP entry attempts.
const OTP_ATTEMPTS_RANGE = JSON.stringify({min: 1, max: 10, default: 4});
// OTP time-to-live.
const OTP_TIMEOUT_RANGE = JSON.stringify({min: 5, max: 30, default: 10}); //minutes

// Tokens expiration time.
const ACCESS_TOKEN_EXP_RANGE = JSON.stringify({min: 60, max: 86400, default: 3600}); //seconds
const REFRESH_TOKEN_EXP_RANGE = JSON.stringify({min: 3600, max: 2592000, default: 604800}); //seconds

// JWT: header, payload and signature divided by dots.
const TOKEN_PATTERN = '^[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+$';

const LANGUAGE_PATTERN = '^[a-zA-Z]{2}$';
const LOCALE_PATTERN = '^[a-zA-Z]{2}-[a-zA-Z]{2}$';

const cdk = require('@aws-cdk/core');
const kms = require('@aws-cdk/aws-kms');
const { LogintooDB } = require('./dynamodb');
const { LogintooOtp } = require('./otp-lambda');
const { LogintooToken } = require('./token-lambda');
const { LogintooApi } = require('./api');

class AuthApiStack extends cdk.Stack {
  /**
   *
   * @param {cdk.Construct} scope
   * @param {string} id
   * @param {cdk.StackProps=} props
   */
  constructor(scope, id, props) {
    super(scope, id, props);

    // Tag all resources.
    const tags = setTags();
    for (let tag of tags) {
      cdk.Tags.of(this).add(tag.key, tag.value);
    }

    const jwtKey = kms.Key.fromKeyArn(this, 'jwtKey', KEY_ARN);

    const dbs = new LogintooDB(this, 'dbs', {
      CACHE_TABLE_NAME: CACHE_TABLE_NAME,
      CLIENTS_TABLE_NAME: CLIENTS_TABLE_NAME,
      NORMALIZED_EMAIL_INDEX_NAME: NORMALIZED_EMAIL_INDEX_NAME,
      AUTH_CODE_INDEX_NAME: AUTH_CODE_INDEX_NAME
    });
    
    const otpLambda = new LogintooOtp(this, 'otpLambda', {
      API_VERSION: API_VERSION,
      CLIENT_ID_PATTERN: CLIENT_ID_PATTERN,
      CODE_CHALLENGE_PATTERN: CODE_CHALLENGE_PATTERN,
      LANGUAGE_PATTERN: LANGUAGE_PATTERN,
      LOCALE_PATTERN: LOCALE_PATTERN,
      OTP_ATTEMPTS_RANGE: OTP_ATTEMPTS_RANGE,
      OTP_LENGTH_RANGE: OTP_LENGTH_RANGE,
      OTP_PATTERN: OTP_PATTERN,
      OTP_TIMEOUT_RANGE: OTP_TIMEOUT_RANGE,
      STATE_PATTERN: STATE_PATTERN,
      NORMALIZED_EMAIL_INDEX_NAME: NORMALIZED_EMAIL_INDEX_NAME,
      SENDGRID_API_KEY: SENDGRID_API_KEY,
      SYS_EMAIL_FROM: SYS_EMAIL_FROM,
      cacheTable: dbs.cacheTable,
      clientsTable: dbs.clientsTable
    });
    
    const tokenLambda = new LogintooToken(this, 'tokenLambda', {
      ACCESS_TOKEN_EXP_RANGE: ACCESS_TOKEN_EXP_RANGE,
      API_VERSION: API_VERSION,
      AUTH_CODE_INDEX_NAME: AUTH_CODE_INDEX_NAME,
      CLIENT_ID_PATTERN: CLIENT_ID_PATTERN,
      CODE_PATTERN: CODE_PATTERN,
      CODE_VERIFIER_PATTERN: CODE_VERIFIER_PATTERN,
      ISS: ISS,
      REFRESH_TOKEN_EXP_RANGE: REFRESH_TOKEN_EXP_RANGE,
      TOKEN_PATTERN: TOKEN_PATTERN,
      cacheTable: dbs.cacheTable,
      clientsTable: dbs.clientsTable,
      jwtKey: jwtKey
    });
 
    new LogintooApi(this, 'api', {
      API_DOMAIN_NAME: API_DOMAIN_NAME,
      API_VERSION: API_VERSION,
      CERTIFICATE_ARN: CERTIFICATE_ARN,
      CLIENT_ID_PATTERN: CLIENT_ID_PATTERN,
      CODE_CHALLENGE_PATTERN: CODE_CHALLENGE_PATTERN,
      LANGUAGE_PATTERN: LANGUAGE_PATTERN,
      LOCALE_PATTERN: LOCALE_PATTERN,
      OTP_PATTERN: OTP_PATTERN,
      STATE_PATTERN: STATE_PATTERN,
      TOKEN_PATTERN: TOKEN_PATTERN,
      cacheTable: dbs.cacheTable,
      verifyOtp: otpLambda.verifyOtp,
      accessToken: tokenLambda.accessToken,
      deleteToken: tokenLambda.deleteToken,
      refreshToken: tokenLambda.refreshToken
    });

  }
}

function setTags() {
  const tags = [];

  // Full path to the working directory.
  const pwd = process.env.PWD;
  if (pwd) {
    tags.push({
      key: 'Working Directory',
      value: pwd
    });
  }

  // Use the owner tag for known accounts or the OS username.
  const awsAccount = process.env.CDK_DEFAULT_ACCOUNT;

  tags.push({
    key: 'Owner',
    value: (Config.KNOWN_AWS_ACCOUNTS[awsAccount]) ? Config.KNOWN_AWS_ACCOUNTS[awsAccount].ownerTag : process.env.USER
  });

  return tags;
}

module.exports = { AuthApiStack };
