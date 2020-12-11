'use strict';

/**
 * Listens to the cache table stream. Receives records in bunches of up to 10 (settings are in authorize-lambda.js).
 * Generates a one-time password and saves data in the cache table.
 */

const cacheTableName = process.env.CACHE_TABLE_NAME;
const normalizedEmailIndexName = process.env.NORMALIZED_EMAIL_INDEX_NAME;
const otpLengthRange = JSON.parse(process.env.OTP_LENGTH_RANGE);
const otpAttemptsRange = JSON.parse(process.env.OTP_ATTEMPTS_RANGE);
const otpTimeoutRange = JSON.parse(process.env.OTP_TIMEOUT_RANGE);

const AWS = require('aws-sdk');
const documentClient = new AWS.DynamoDB.DocumentClient({region: process.env.AWS_REGION});

const URL = require('url').URL;
const crypto = require('crypto');
const { ValidationError, DatabaseError } = require('./Error.js');
const Func = require('./Func.js');

exports.handler = async (event) => {
  for (const record of event.Records) {
    if (record.eventName == 'INSERT') {
      try {
        // Initialize and validate the auth request. Drop if the request is malformed.
        const req = init(record.dynamodb.NewImage);

        // Check if an OTP has already been sent for this email_normalized/code_challenge. If yes, then drop.
        const otpSent = await isOtpSent(req);
        if (otpSent) {
          throw new Error('OTP has already been sent. Nothing to do. Client ID: ' + req.client_id + ', Email: ' + req.email + ', Source IP: ' + req.sourceIp[0] + '.');
        }

        // Check if this is a registered client_id and redirect_uri, otherwise, drop.
        const clientApp = await Func.getClientApp(req.client_id);
        checkRedirectUri(clientApp, req);

        // Generate OTP. The length is either defined in the client settings or use the default value.
        const otp = generateOtp(clientApp);

        // Update record in the cache table.
        await saveOtp(otp, clientApp, req);
      }
      catch(error) {
        console.error(error);

        if (error instanceof DatabaseError && error.retryable) {
          return error;
        } 
      }
    }
  }
};

// Transform, validate, add normalized email.
function init(request) {
  // Transform the request object from {key: {S|N|L: value}} to {key: value}.
  // Ignore values that are not String, Number or List. For lists expect only one String element in the List.
  for (const key in request) {
    if (request[key].S) {
      request[key] = request[key].S.trim();
      continue;
    }
    if (request[key].N) {
      request[key] = request[key].N;
      continue;
    }
    if (request[key].L && request[key].L[0] && request[key].L[0].S) {
      request[key] = [request[key].L[0].S.trim()];
      continue;
    }
  }

  const schema = getValidationSchema();
  Func.validate(request, schema);
  
  request.email_normalized = Func.normalizeEmail(request.email);
  
  return request;
}

// Validation schema for the auth request parameters. The same validation schema as in the API.
function getValidationSchema() {
  const patterns = Func.getValidationPatterns();

  if (patterns.clientId === null
    || patterns.codeChallenge === null
    || patterns.state === null
    || patterns.language === null
    || patterns.locale === null) {

    throw new ValidationError('Pattern for validation schema is not defined.');
  }

  return {
    type: 'object',
    properties: {
      client_id: {type: 'string', pattern: patterns.clientId},
      code_challenge: {type: 'string', pattern: patterns.codeChallenge},
      code_challenge_method: {type: 'string', enum: ['S256']},
      email: {type: 'string', format: 'email'},
      redirect_uri: {type: 'string', format: 'uri'},
      response_type: {type: 'string', enum: ['code']},
      state: {type: 'string', pattern: patterns.state},
      language: {type: 'string', pattern: patterns.language},
      locale: {type: 'string', pattern: patterns.locale}
    },
    required: ['client_id', 'code_challenge', 'code_challenge_method', 'email', 'redirect_uri', 'response_type', 'state']
  };
}

// Check if an OTP has already been sent for this email_normalized/code_challenge recently.
async function isOtpSent(request) {
  try {
    const params = {
      TableName: cacheTableName,
      IndexName: normalizedEmailIndexName,
      KeyConditionExpression: '#email_normalized = :email_normalized AND #code_challenge = :code_challenge',
      ExpressionAttributeNames: {
        '#email_normalized': 'email_normalized',
        '#code_challenge': 'code_challenge'
      },
      ExpressionAttributeValues: {
        ':email_normalized': request.email_normalized,
        ':code_challenge': request.code_challenge
      }
    };

    const res = await documentClient.query(params).promise();

    return (res.Count > 0);
  }
  catch(error) {
    let message = 'Client ID: ' + request.client_id + ', Email: ' + request.email + ', Source IP: ' + request.sourceIp[0] + '.';
    throw new DatabaseError(message, error);
  }
}

// Check if this is a registered client_id and redirect_uri and return the item.
async function checkRedirectUri(clientApp, request) {
  const redirectURIs = clientApp.redirectURIs;

  const urls = Array.isArray(redirectURIs) ? redirectURIs : [];

  const redirectUri = new URL(request.redirect_uri);

  if (!urls.includes(redirectUri.toString())) {
    throw new Error('Redirect URI is not registered for this application. Client ID: ' + clientApp.id + ', Redirect URI: ' + request.redirect_uri + '.');
  }
}

// Generate OTP using the Fisher-Yates shuffle algorithm (https://en.wikipedia.org/wiki/Fisher–Yates_shuffle).
function generateOtp(clientApp) {
  let otpLength = clientApp.otpLength;

  if (!Number.isInteger(otpLength) || otpLength < otpLengthRange.min || otpLength > otpLengthRange.max) {
    otpLength = otpLengthRange.default;
  }

  const seed = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
  
  // Get random numbers.
  const rl = seed.length - 1;
  const random = new Uint8Array(rl);
  const bytes = crypto.randomBytes(rl);
  random.set(bytes);

  const pinArr = [];
  let roll;
  for (let i = rl, len = rl - otpLength; i > len; i--) {
    roll = random[i - 1] % i;

    pinArr.push(seed[roll]);
    seed[roll] = seed.pop();
  }

  return pinArr.join('');
}

// Update the request record with the OTP and timeout parameters.
async function saveOtp(otp, clientApp, request) {
  const {otpEmailFrom, otpEmailSubj, otpEmailLogoSrc, otpTimeout, otpAttempts, appDisplayName} = clientApp;
  const {id, email_normalized, code_challenge} = request;

  if (!Func.isEmailAddress(otpEmailFrom)) {
    throw new Error('Configuration error. No valid sender email address specified. Client ID: ' + clientApp.id + '.');
  }
  if (!appDisplayName) {
    appDisplayName = '';
  }

  if (!Number.isInteger(otpTimeout) || otpTimeout < otpTimeoutRange.min || otpTimeout > otpTimeoutRange.max) {
    otpTimeout = otpTimeoutRange.default;
  }
  if (!Number.isInteger(otpAttempts) || otpAttempts < otpAttemptsRange.min || otpAttempts > otpAttemptsRange.max) {
    otpAttempts = otpAttemptsRange.default;
  }

  try {
    const nowSeconds = Math.floor(Date.now() / 1000);

    const params = {
      TableName: cacheTableName,
      Key: {id: id},
      UpdateExpression: 'set\
        #email_normalized = :email_normalized,\
        #otp = :otp,\
        #otpTimeout = :otpTimeout,\
        #otpTimeoutTimestamp = :otpTimeoutTimestamp,\
        #otpAttempts = :otpAttempts,\
        #otpEmailFrom = :otpEmailFrom,\
        #otpEmailSubj = :otpEmailSubj,\
        #otpEmailLogoSrc = :otpEmailLogoSrc,\
        #appDisplayName = :appDisplayName\
      ',
      // The condition is to make sure the record exists. We don't want to add a new item.
      ConditionExpression: '#code_challenge = :code_challenge',
      ExpressionAttributeNames: {
        '#email_normalized': 'email_normalized',
        '#otp': 'otp',
        '#otpTimeout': 'otpTimeout',
        '#otpTimeoutTimestamp': 'otpTimeoutTimestamp',
        '#otpAttempts': 'otpAttempts',
        '#otpEmailFrom': 'otpEmailFrom',
        '#otpEmailSubj': 'otpEmailSubj',
        '#otpEmailLogoSrc': 'otpEmailLogoSrc',
        '#code_challenge': 'code_challenge',
        '#appDisplayName': 'appDisplayName'
      },
      ExpressionAttributeValues: {
        ':email_normalized': email_normalized,
        ':otp': otp,
        ':otpTimeout': otpTimeout,
        ':otpTimeoutTimestamp': nowSeconds + otpTimeout * 60,
        ':otpAttempts': otpAttempts,
        ':otpEmailFrom': otpEmailFrom,
        ':otpEmailSubj': otpEmailSubj,
        ':otpEmailLogoSrc': otpEmailLogoSrc,
        ':code_challenge': code_challenge,
        ':appDisplayName': appDisplayName
      }
    };

    await documentClient.update(params).promise();
  }
  catch(error) {
    let message = 'Could not save OTP. Client ID: ' + id + '.';
    throw new DatabaseError(message, error);
  }
}
