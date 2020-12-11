'use strict';

/**
 * Verifies OTP, generates the Authorization Code.
 * Trigger: /otp, POST.
 */

// Maximum Authorization Code lifetime. Hardcoded since the code exchange is fully automated.
const authorizationCodeTtl = 120; // seconds

const cacheTableName = process.env.CACHE_TABLE_NAME;
const normalizedEmailIndexName = process.env.NORMALIZED_EMAIL_INDEX_NAME;

const AWS = require('aws-sdk');
const documentClient = new AWS.DynamoDB.DocumentClient({region: process.env.AWS_REGION});

const URL = require('url').URL;
const crypto = require('crypto');
const { ValidationError, DatabaseError, NotFoundError, UnauthorizedError } = require('./Error.js');
const Func = require('./Func.js');

exports.handler = async (event) => {
  try {
    // Initialize and validate the request. Throw '400 Bad Request' if the request is malformed.
    const req = init(JSON.parse(event.body));
    
    // Get the record from the Cache table. Throw '403 Forbidden' if the OTP expired or other issues.
    const authRecord = await getAuthRecord(req);
    
    // Check the OTP. Throw '401 Unauthorized' and decrement number of remaining attempts if the wrong OTP submitted.
    await checkOtp(req, authRecord);
    
    // Generate the Authorization Code. 
    const authorizationCode = generateAuthCode(32);

    // Save the Authorization Code in the cache table along with expiration time. Set otpAttempts to 0.
    await saveAuthCode(req, authorizationCode, authRecord);

    // Return '302 Found' to instruct client to redirect to the specified URI with the Authorization Code.
    const output = buildOutput(authRecord, authorizationCode);
    return Func.httpStatusCode(302, {}, output);

  }
  catch(error) {
    console.error(error);
    
    // Status codes for the API response in case of error, '500 Internal Server Error' is default.
    let statusCode = 500;
    const responseCodes = [400, 401, 403, 500, 503];
    if (error.statusCode && responseCodes.indexOf(error.statusCode) > -1) {
      statusCode = error.statusCode;      
    }
    
    const outputError = Func.buildOutputError(statusCode, error);
    return Func.httpStatusCode(statusCode, outputError);
  }
};

// Initialize and validate the OTP request. Throw '400 Bad Request' if the request is malformed.
function init(request) {
  request.email = String(request.email).trim();
  request.otp = String(request.otp).trim();
  
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
    || patterns.otp === null) {
      
    throw new ValidationError('Pattern for validation schema is not defined.');
  }

  return {
    type: 'object',
    properties: {
      client_id: {type: 'string', pattern: patterns.clientId},
      code_challenge: {type: 'string', pattern: patterns.codeChallenge},
      email: {type: 'string', format: 'email'},
      otp: {type: 'string', pattern: patterns.opt}
    },
    required: ['client_id', 'code_challenge', 'email', 'otp']
  };
}

// Get the record from the Cache table.
async function getAuthRecord(request) {
  try {
    const {email_normalized, code_challenge, client_id, email} = request;

    const params = {
      TableName: cacheTableName,
      IndexName: normalizedEmailIndexName,
      KeyConditionExpression: '#email_normalized = :email_normalized AND #code_challenge = :code_challenge',
      FilterExpression: '#email = :email AND #client_id = :client_id AND #otpAttempts > :zero AND #otpTimeoutTimestamp > :now',
      ExpressionAttributeNames:{
        '#email_normalized': 'email_normalized',
        '#code_challenge': 'code_challenge',
        '#client_id': 'client_id',
        '#email': 'email',
        '#otpAttempts': 'otpAttempts',
        '#otpTimeoutTimestamp': 'otpTimeoutTimestamp'
      },
      ExpressionAttributeValues: {
        ':email_normalized': email_normalized,
        ':code_challenge': code_challenge,
        ':client_id': client_id,
        ':email': email,
        ':zero': 0,
        ':now': Math.floor(Date.now() / 1000) // Current time in seconds.
      }
    };

    const res = await documentClient.query(params).promise();

    if (res.Count != 1) {
      // The OTP expired, or the number of attempts exceeded, or no record in the Cache table at all.
      throw new NotFoundError('Could not found a record in the cache table. Client ID: ' + client_id + '. Email: ' + email + '.');
    }

    return res.Items[0];
  }
  catch(error) {
    if (error instanceof NotFoundError) {
      throw error;
    }
    else {
      let message = 'Could not get a record from the Cache table';
      throw new DatabaseError(message, error);
    }
  }
}

// Check the OTP.
async function checkOtp(request, authRecord) {
  const requestOtp = request.otp;
  const storedOtp = authRecord.otp;
  const recordId = authRecord.id;

  if (requestOtp != storedOtp) {
    // Wrong OTP submitted. Decrement otpAttempts value.
    await decrementAttemptsCounter(recordId);
    
    throw new UnauthorizedError('Wrong OTP. Client ID: ' + request.client_id + '. Email: ' + authRecord.email + '.');
  }
}

// Decrement number of remaining OTP entry attempts.
async function decrementAttemptsCounter(id) {
  try {
    const params = {
      TableName: cacheTableName,
      Key: {id: id},
      UpdateExpression: 'SET #otpAttempts = #otpAttempts - :delta',
      ExpressionAttributeNames: {
        '#otpAttempts': 'otpAttempts'
      },
      ExpressionAttributeValues: {
        ':delta': 1,
      }
    };
    
    return documentClient.update(params).promise();
  }
  catch(error) {
    console.error(error);
  }
}

// Generate a cryptographically strong random URL-safe string.
function generateAuthCode(numberOfBytes) {
  const randomBytes = crypto.randomBytes(numberOfBytes);
  return Func.base64UrlEncode(randomBytes);
}

// Save the Authorization Code in the cache table along with expiration time. Set otpAttempts to 0.
function saveAuthCode(request, authorizationCode, authRecord) {
  try {
    const nowSeconds = Math.floor(Date.now() / 1000);
    const id = authRecord.id;
    
    const params = {
      TableName: cacheTableName,
      Key: {id: id},
      UpdateExpression: 'set \
        #authorizationCode = :ac, \
        #authCodeTimeout = :acttl, \
        #otpAttempts = :zero, \
        #allowAuthCode = :true \
      ',
      ExpressionAttributeNames: {
        '#authorizationCode': 'authorizationCode',
        '#authCodeTimeout': 'authCodeTimeout',
        '#otpAttempts': 'otpAttempts',
        '#allowAuthCode': 'allowAuthCode'
      },
      ExpressionAttributeValues: {
        ':ac': authorizationCode,
        ':acttl': nowSeconds + authorizationCodeTtl,
        ':zero': 0,
        ':true': true
      }
    };
    
    return documentClient.update(params).promise();
  }
  catch(error) {
    let message = 'Client ID: ' + request.client_id + ', Email: ' + request.email + '.';
    throw new DatabaseError(message, error);
  }
}

// Format successful output data.
function buildOutput(authRecord, authorizationCode) {
  const state = authRecord.state;
  const redirect_uri = authRecord.redirect_uri;
  
  const language = authRecord.language;
  const locale = authRecord.locale;
  
  const location = new URL(redirect_uri);
  location.searchParams.set('code', authorizationCode);
  location.searchParams.set('state', state);
  if (language) {
    location.searchParams.set('language', language);
  }
  if (locale) {
    location.searchParams.set('locale', locale);
  }
  
  return {
    Location: location.toString()
  };
}
