'use strict';

/**
 * Validates the access token request and issues access and refresh tokens.
 * Trigger: /token, POST.
 */

const cacheTableName = process.env.CACHE_TABLE_NAME;
const authorizationCodeIndex = process.env.AUTH_CODE_INDEX_NAME;

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

    // Get the record from the Cache table. Throw '403 Forbidden' if the Authorization code expired or other issues.
    const authRecord = await getAuthIndex(req);
    
    // Calculate the Code Challenge from the received Code Verifier and compare it with the stored value.
    checkCodeChallenge(req, authRecord);
    
    // Read the Client App record from the database. Throw '403 Forbidden' if not found.
    const clientApp = await Func.getClientApp(req.client_id);

    // Calculate tokens expiration time.
    const expTimes = Func.calculateExpTime(clientApp);
    
    // Issue the JWT access token. On error throw 'Token creation error'.
    const accessToken = await Func.createJwt(authRecord, clientApp, expTimes, 'access');
    // Issue the JWT refresh token. On error throw 'Token creation error'.
    const refreshToken = await Func.createJwt(authRecord, clientApp, expTimes, 'refresh');

    // Update TTL of the Cache table record, disable the authorization code to prevent using it more than once, save the refresh token ID.
    await Func.updateAuthRecord(authRecord, expTimes, refreshToken.payload.jti);
    
    // Return the access and refresh tokens with '200 OK'.
    const output = Func.buildOutput(accessToken.jwt, refreshToken.jwt, authRecord, expTimes);
    return Func.httpStatusCode(200, output);
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

// Initialize and validate the token request. Throw '400 Bad Request' if the request is malformed.
function init(request) {
  const schema = getValidationSchema();
  Func.validate(request, schema);
  
  return request;
}

// Validation schema for the token request parameters. The same validation schema as in the API.
function getValidationSchema() {
  const patterns = Func.getValidationPatterns();

  if (patterns.clientId === null
    || patterns.codeVerifier === null
    || patterns.code === null) {
      
    throw new ValidationError('Pattern for validation schema is not defined.');
  }

  return {
    type: 'object',
    properties: {
      client_id: {type: 'string', pattern: patterns.clientId},
      code_verifier: {type: 'string', pattern: patterns.codeVerifier},
      code: {type: 'string', pattern: patterns.code},
      redirect_uri: {type: 'string', format: 'uri'},
      grant_type: {type: 'string', enum: ['authorization_code']}
    },
    required: ['grant_type', 'code', 'redirect_uri', 'client_id', 'code_verifier']
  };
}

// Get the record from the Cache table.
async function getAuthIndex(request) {
  try {
    const {code, redirect_uri, client_id, email} = request;

    const redirectUri = new URL(redirect_uri);

    const params = {
      TableName: cacheTableName,
      IndexName: authorizationCodeIndex,
      KeyConditionExpression: '#authorizationCode = :code',
      FilterExpression: ' \
        #client_id = :client_id \
        AND #redirect_uri = :redirect_uri \
        AND #authCodeTimeout > :now \
        AND #allowAuthCode = :true \
      ',
      ExpressionAttributeNames:{
        '#authorizationCode': 'authorizationCode',
        '#client_id': 'client_id',
        '#redirect_uri': 'redirect_uri',
        '#authCodeTimeout': 'authCodeTimeout',
        '#allowAuthCode': 'allowAuthCode'
      },
      ExpressionAttributeValues: {
        ':code': code,
        ':client_id': client_id,
        ':redirect_uri': redirectUri.toString(),
        ':true': true,
        ':now': Math.floor(Date.now() / 1000) // Current time in seconds.
      }
    };
  
    const res = await documentClient.query(params).promise();

    if (res.Count != 1) {
      // The Authorization Code expired or no record found.
      throw new NotFoundError('Could not found a record in the cache table. Client ID: ' + client_id + '. Email: ' + email + '. Redirect URI: ' + redirectUri.toString() + '.');
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

// Calculate the Code Challenge from the received Code Verifier and compare it with the stored value.
function checkCodeChallenge(request, authRecord) {
  const code_verifier = request.code_verifier;
  const code_challenge = authRecord.code_challenge;
    
  if (authRecord.code_challenge_method != 'S256') {
    throw new ValidationError('Bad code challenge method, must be S256: ' + authRecord.code_challenge_method + '. Client ID: ' + request.client_id);
  }
  
  if (code_challenge != encodeVerifier(code_verifier)) {
    throw new UnauthorizedError('Bad code verifier: ' + code_verifier + '. Client ID: ' + request.client_id);
  }
}

// Calculate the Code Challenge from the received Code Verifier.
function encodeVerifier(verifier) {
  return crypto.createHash('sha256')
    .update(verifier)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}
