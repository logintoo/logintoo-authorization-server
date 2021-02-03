'use strict';

/**
 * Validates logout request, erases the corresponding record in the Cache Table.
 * Trigger: /token, DELETE.
 */

const cacheTableName = process.env.CACHE_TABLE_NAME;

const AWS = require('aws-sdk');
const documentClient = new AWS.DynamoDB.DocumentClient({region: process.env.AWS_REGION});

const Func = require('./Func.js');
const { ValidationError } = require('./Error.js');

exports.handler = async (event) => {
  try {
    // Initialize and validate the request. Throw '400 Bad Request' if the request is malformed.
    const req = init(JSON.parse(event.body));
    
    // Verify refresh token and get token data. Throw '400 Bad Request' or '401 Unauthorized' if any issues.
    const refreshTokenPayload = await Func.verifyRefreshToken(req.refresh_token);

    // Delete record from the Cache table.
    await deleteAuthRecord(refreshTokenPayload, event);

    // Return '200 OK'.
    const output = {
      statusMessage: '200 OK'
    };
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
      refresh_token: {type: 'string', pattern: patterns.token}
    },
    required: ['refresh_token']
  };
}

// Delete record from the Cache table.
async function deleteAuthRecord(refreshTokenPayload, event) {
  const {sub, client_id, auth_record_id, jti} = refreshTokenPayload;
  const sourceIp = (event.headers['CF-Connecting-IP']) ? event.headers['CF-Connecting-IP'] : event.requestContext.identity.sourceIp;
  const userAgent = event.requestContext.identity.userAgent;

  try {
    const params = {
      TableName: cacheTableName,
      Key: {
        id: auth_record_id
      },
      ConditionExpression: ' \
        #client_id = :client_id \
        AND #email = :sub \
        AND #refresh_jti = :jti \
      ',
      ExpressionAttributeNames:{
        '#client_id': 'client_id',
        '#email': 'email',
        '#refresh_jti': 'refresh_jti'
      },
      ExpressionAttributeValues: {
        ':client_id': client_id,
        ':sub': sub,
        ':jti': jti
      }
    };
  
    const res = await documentClient.delete(params).promise();

    return res;
  }
  catch(error) {
    console.error(error);
    
    if (error.statusCode == 400) {
      // Record was not found, that may indicate that the refresh token is compromised.
      const notFoundData = {
        auth_record_id: auth_record_id,
        client_id: client_id,
        email: sub,
        jti: jti,
        sourceIp: sourceIp,
        userAgent: userAgent
      };
      console.warn('SECURITY: Valid refresh token presented but could not find a record in the cache table.', JSON.stringify(notFoundData));
    }
  }
}
