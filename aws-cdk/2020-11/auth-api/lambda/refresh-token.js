'use strict';

/**
 * Validates the refresh token request, issues access token and rotates refresh token.
 * Trigger: /token, PATCH.
 */

const cacheTableName = process.env.CACHE_TABLE_NAME;

const AWS = require('aws-sdk');
const documentClient = new AWS.DynamoDB.DocumentClient({region: process.env.AWS_REGION});

const { ValidationError, DatabaseError, NotFoundError } = require('./Error.js');
const Func = require('./Func.js');

exports.handler = async (event) => {
  try {
    // Initialize and validate the request. Throw '400 Bad Request' if the request is malformed.
    const req = init(JSON.parse(event.body));
        
    // Verify refresh token and get token data. Throw '400 Bad Request' or '401 Unauthorized' if any issues.
    const refreshTokenPayload = await Func.verifyRefreshToken(req.refresh_token);

    // Get the record from the Cache table. Throw '403 Forbidden' if not found.
    const authRecord = await getAuthRecord(refreshTokenPayload, event);

    // Read the Client App record from the database. Throw '403 Forbidden' if not found.
    const clientApp = await Func.getClientApp(refreshTokenPayload.client_id);
    
    // Calculate tokens expiration time.
    const expTimes = Func.calculateExpTime(clientApp, refreshTokenPayload);
    
    // Issue the JWT access token. On error throw 'Token creation error'.
    const accessToken = await Func.createJwt(authRecord, clientApp, expTimes, 'access');
    // Issue the JWT refresh token. On error throw 'Token creation error'.
    const refreshToken = await Func.createJwt(authRecord, clientApp, expTimes, 'refresh');

    // Update TTL of the Cache table record, update the refresh token ID.
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

// Initialize and validate the request. Throw '400 Bad Request' if the request is malformed.
function init(request) {
  const schema = getValidationSchema();
  Func.validate(request, schema);
  
  return request;
}

// Validation schema for the token request parameters. The same validation schema as in the API.
function getValidationSchema() {
  const patterns = Func.getValidationPatterns();

  if (patterns.token === null) {
    throw new ValidationError('Pattern for validation schema is not defined.');
  }

  return {
    type: 'object',
    properties: {
      grant_type: {type: 'string', enum: ['refresh_token']},
      refresh_token: {type: 'string', pattern: patterns.token}
    },
    required: ['grant_type', 'refresh_token']
  };
}

// Get the record from the Cache table.
async function getAuthRecord(refreshTokenPayload, event) {
  try {
    const {sub, client_id, auth_record_id, jti} = refreshTokenPayload;
    const sourceIp = (event.headers['CF-Connecting-IP']) ? event.headers['CF-Connecting-IP'] : event.requestContext.identity.sourceIp;
    const userAgent = event.requestContext.identity.userAgent;

    const params = {
      TableName: cacheTableName,
      KeyConditionExpression: '#id = :auth_record_id',
      FilterExpression: ' \
        #client_id = :client_id \
        AND #email = :sub \
        AND #refresh_jti = :jti \
      ',
      ExpressionAttributeNames:{
        '#id': 'id',
        '#client_id': 'client_id',
        '#email': 'email',
        '#refresh_jti': 'refresh_jti'
      },
      ExpressionAttributeValues: {
        ':auth_record_id': auth_record_id,
        ':client_id': client_id,
        ':sub': sub,
        ':jti': jti
      }
    };
  
    const res = await documentClient.query(params).promise();

    if (res.Count != 1) {
      // Record not found (or more than one record found which should never happen).
      // This may indicate that the refresh token is compromised.
      const notFoundData = {
        auth_record_id: auth_record_id,
        client_id: client_id,
        email: sub,
        jti: jti,
        sourceIp: sourceIp,
        userAgent: userAgent
      };
      console.warn('SECURITY: Valid refresh token presented but could not find a record in the cache table.', JSON.stringify(notFoundData));
      throw new NotFoundError('Access Denied');
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
