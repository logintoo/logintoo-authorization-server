const cacheTableName = process.env.CACHE_TABLE_NAME;
const clientsTableName = process.env.CLIENTS_TABLE_NAME;
const accessTokenExpRange = process.env.ACCESS_TOKEN_EXP_RANGE ? JSON.parse(process.env.ACCESS_TOKEN_EXP_RANGE) : null;
const refreshTokenExpRange = process.env.REFRESH_TOKEN_EXP_RANGE ? JSON.parse(process.env.REFRESH_TOKEN_EXP_RANGE) : null;
const jwtIss = process.env.ISS;
const keyArn = process.env.KEY_ARN;
const keyId = process.env.KEY_ID;

const AWS = require('aws-sdk');
const documentClient = new AWS.DynamoDB.DocumentClient({region: process.env.AWS_REGION});
const kms = new AWS.KMS({region: process.env.AWS_REGION});

const Validator = require('jsonschema').Validator;
const v = new Validator();
const crypto = require('crypto');
const { ValidationError, DatabaseError, NotFoundError, UnauthorizedError } = require('./Error.js');

module.exports = {
  // Validation patterns.
  getValidationPatterns: function() {
    return {
      clientId: process.env.CLIENT_ID_PATTERN || null,
      code: process.env.CODE_PATTERN || null,
      codeChallenge: process.env.CODE_CHALLENGE_PATTERN || null,
      codeVerifier: process.env.CODE_VERIFIER_PATTERN || null,
      state: process.env.STATE_PATTERN || null,
      language: process.env.LANGUAGE_PATTERN || null,
      locale: process.env.LOCALE_PATTERN || null,
      otp: process.env.OTP_PATTERN || null,
      token: process.env.TOKEN_PATTERN || null
    };
  },
  // Validate request.
  validate: function(request, schema) {
    const result = v.validate(request, schema, {throwAll: true});

    if (!result.valid) {
      let message = '';
      for (let i = 0, len = result.errors.length; i < len; i++) {
        message += result.errors[i].message;

        if (i < len - 1) {
          message += ' | ';
        }
      }

      throw new ValidationError(message,  result.instance);
    }
  },
  // Validate the email.
  isEmailAddress: function(email) {
    return email.match(/^[a-z0-9.!#$%&’*+/=?^_`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)*$/i);
  },
  // Build normalized email: remove +part from all addresses and dots from gmail.com/googlemail.com addresses.
  normalizeEmail: function(email) {
    if (email.indexOf('+') > -1) {
      // Remove leading '+' signs if any.
      email = email.replace(/^\++/, '');
      // Remove +part from the email address.
      email = email.replace(/\+[a-z0-9.!#$%&’*+/=?^_`{|}~-]+@/i, '@');
    }

    // Remove dots from Gmail addresses (https://support.google.com/mail/answer/7436150).
    let parts = email.split('@');
    if (parts[1] == 'gmail.com' || parts[1] == 'googlemail.com') {
      let partsUser = parts[0].replace(/\./g, '');

      email = partsUser + '@' + parts[1];
    }

    return email;
  },
  // Get a Base64 URL-safe string.
  base64UrlEncode: function(data) {
    let output = '';

    if (typeof data == 'object' && Buffer.isBuffer(data)) {
      output = data.toString('base64');
    }
    else {
      const str = (typeof data == 'number') ? data.toString() : data;
      output = Buffer.from(str).toString('base64');
    }

    return output
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  },
  // Decode Base64 URL string.
  base64UrlDecode: function(str) {
    const strBase64 = (str + '==='.slice((str.length + 3) % 4))
      .replace(/-/g, '+')
      .replace(/_/g, '/');
    return Buffer.from(strBase64, 'base64');
  },
  // Read the Client App record from the database.
  getClientApp: async function(client_id) {
    try {
      const params = {
        TableName: clientsTableName,
        KeyConditionExpression: '#id = :id',
        ExpressionAttributeNames:{
          '#id': 'id'
        },
        ExpressionAttributeValues: {
          ':id': client_id
        }
      };
      
      const res = await documentClient.query(params).promise();
      
      if (res.Count > 1) {
        throw new NotFoundError('More than 1 record with the same Client ID found which should never happen. Client ID: ' + client_id);
      }
      if (res.Count != 1) {
        throw new NotFoundError('Client ID not found. Client ID: ' + client_id);
      }

      return res.Items[0];
    }
    catch(error) {
      if (error instanceof NotFoundError) {
        throw error;
      }
      else {
        let message = 'Client ID: ' + client_id;
        throw new DatabaseError(message, error);
      }
    }
  },
  // Calculate tokens expiration time.
  calculateExpTime: function(clientApp, refreshTokenPayload) {
    let clientAccessExp = clientApp.accessTokenExp;
    if (!Number.isInteger(clientAccessExp) || clientAccessExp < accessTokenExpRange.min || clientAccessExp > accessTokenExpRange.max) {
      clientAccessExp = accessTokenExpRange.default;
    }

    let clientRefreshExp = clientApp.refreshTokenExp;
    if (!Number.isInteger(clientRefreshExp) || clientRefreshExp < refreshTokenExpRange.min || clientRefreshExp > refreshTokenExpRange.max) {
      clientRefreshExp = refreshTokenExpRange.default;
    }

    const extendRefreshToken = clientApp.extendRefreshToken;

    const now = Math.floor(Date.now() / 1000); // Current time in seconds.
    
    let refreshTokenExp = now + clientRefreshExp;
    if (refreshTokenPayload && !extendRefreshToken) {
      refreshTokenExp = refreshTokenPayload.exp;
    }

    return {
      accessToken: {
        iat: now,
        exp: now + clientAccessExp,
        clientAccessExp: clientAccessExp
      },
      refreshToken: {
        iat: now,
        exp: refreshTokenExp,
        clientRefreshExp: clientRefreshExp
      }
    };
  },
  // Generate a JWT token.
  createJwt: async function(authRecord, clientApp, expTimes, tokenType) {
    if (tokenType != 'access' && tokenType != 'refresh') throw new Error('Wrong token type:', tokenType);

    // Generate token ID.
    const randomBytes = crypto.randomBytes(32);
    const jti = this.base64UrlEncode(randomBytes);

    const jwtHeader = {
      alg: 'RS256',
      kid: keyId,
      typ: 'JWT'
    };
    const jwtHeaderBase64 = this.base64UrlEncode(JSON.stringify(jwtHeader));

    let jwtPayload;

    if (tokenType == 'access') {
      jwtPayload = {
        iss: jwtIss,
        sub: authRecord.email,
        aud: clientApp.tokenAud,
        iat: expTimes.accessToken.iat,
        exp: expTimes.accessToken.exp,
        jti: jti,
        email: authRecord.email,
        email_verified: true,
        email_normalized: authRecord.email_normalized,
        hd: authRecord.email_normalized.split('@')[1]
      };
    
      if (authRecord.language) {
        jwtPayload.language = authRecord.language;
      }
      if (authRecord.locale) {
        jwtPayload.locale = authRecord.locale;
      }
    }

    if (tokenType == 'refresh') {
      jwtPayload = {
        iss: jwtIss,
        sub: authRecord.email,
        iat: expTimes.refreshToken.iat,
        exp: expTimes.refreshToken.exp,
        client_id: clientApp.id,
        auth_record_id: authRecord.id,
        jti: jti
      };
    }

    const jwtPayloadBase64 = this.base64UrlEncode(JSON.stringify(jwtPayload));
    
    let jwt = jwtHeaderBase64 + '.' + jwtPayloadBase64;
    
    try {
      const signParams = {
        KeyId: keyArn,
        Message: jwt,
        MessageType: 'RAW',
        SigningAlgorithm: 'RSASSA_PKCS1_V1_5_SHA_256'
      };
      const sign = await kms.sign(signParams).promise();

      const signature = this.base64UrlEncode(sign.Signature);
      
      jwt += '.' + signature;
      
      return {
        jwt: jwt,
        payload: jwtPayload
      };
    }
    catch(error) {
      console.error(error);
      throw new Error('Token creation error');
    }
  },
  // Verify refresh token and get token data.
  verifyRefreshToken: async function(token) {
    const tokenParts = token.split('.');

    let jwtHeader;
    let jwtPayload;
    try {
      jwtHeader = JSON.parse(this.base64UrlDecode(tokenParts[0]).toString('ascii'));
      jwtPayload = JSON.parse(this.base64UrlDecode(tokenParts[1]).toString('ascii'));
    }
    catch(error) {
      console.error(error);
      console.log('Wrong header or payload format. Token: ' + token);
      throw new ValidationError('Wrong refresh token header or payload format.');
    }

    const signedMessage = tokenParts[0] + '.' + tokenParts[1];
    const jwtSignature = this.base64UrlDecode(tokenParts[2]);
    const alg = 'RSASSA_PKCS1_V1_5_SHA_256';
  
    // Reject if the token has expired.
    const now = Math.floor(Date.now() / 1000); // Current time in seconds.
    if (!jwtPayload.exp || now > jwtPayload.exp) {
      console.log('Token expired. Now: ' + now + '. Exp: ' + jwtPayload.exp);
      throw new UnauthorizedError('Token Expired');
    }
    if (!jwtPayload.iat || now < jwtPayload.iat) {
      console.log('IAT must be before the current time. Now: ' + now + '. Iat: ' + jwtPayload.iat);
      throw new UnauthorizedError('Unauthorized');
    }
  
    // Reject if issuer don't match.
    if (jwtPayload.iss != jwtIss) {
      console.log('Bad ISS. Email: ' + jwtPayload.email + '. Iss: ' + jwtPayload.iss);
      throw new UnauthorizedError('Unauthorized');
    }

    // Reject if the key ID is not specified.
    if (!jwtHeader.kid) {
      console.log('Key ID is not specified.');
      throw new ValidationError('Key ID is not specified');
    }

    const params = {
      KeyId: jwtHeader.kid,
      Message: signedMessage,
      Signature: jwtSignature,
      SigningAlgorithm: alg,
      MessageType: 'RAW'
    };

    try {
      await kms.verify(params).promise();
      
      return jwtPayload;
    }
    catch(error) {
      console.log(error);
      throw new UnauthorizedError('Invalid refresh token signature.');
    }
  },
  // Update TTL of the Cache table record and disable the authorization code to prevent using it more than once.
  updateAuthRecord: async function(authRecord, expTimes, refresh_jti) {
    const {id, code_challenge} = authRecord;
    const ttl = expTimes.refreshToken.exp;

    try {
      const params = {
        TableName: cacheTableName,
        Key: {id: id},
        UpdateExpression: 'set \
          #ttl = :ttl, \
          #allowAuthCode = :false, \
          #refresh_jti = :refresh_jti, \
          #state = :empty \
        ',
        // The condition is to make sure the record exists. We don't want to add a new item.
        ConditionExpression: '#code_challenge = :code_challenge',
        ExpressionAttributeNames: {
          '#ttl': 'ttl',
          '#allowAuthCode': 'allowAuthCode',
          '#code_challenge': 'code_challenge',
          '#refresh_jti': 'refresh_jti',
          '#state': 'state'
        },
        ExpressionAttributeValues: {
          ':ttl': ttl,
          ':false': false,
          ':code_challenge': code_challenge,
          ':refresh_jti': refresh_jti,
          ':empty': ''
        }
      };
    
      await documentClient.update(params).promise();

    }
    catch(error) {
      console.error(error);
      console.error('Could not update record in the Cache table. Client ID: ' + authRecord.client_id + '. Email: ' + authRecord.email + '.');
    }
  },
  // Format successful output data.
  buildOutput: function(accessJwt, refreshJwt, authRecord, expTimes) {
    const state = authRecord.state;

    const language = authRecord.language;
    const locale = authRecord.locale;
    
    const output = {
      statusMessage: '200 OK',
      access_token: accessJwt,
      token_type: 'Bearer',
      expires_in: expTimes.accessToken.clientAccessExp,
      refresh_token: refreshJwt,
      exp: expTimes.accessToken.exp,
      rt_exp: expTimes.refreshToken.exp,
      state: state
    };
    
    if (language) {
      output.language = language;
    }
    if (locale) {
      output.locale = locale;
    }   

    return output;
  },
  // Form the API Gateway response with HTTP status code.
  httpStatusCode: function(code, output, headersExtra) {
    let body = JSON.stringify({statusMessage: output});
    
    if (typeof output === 'object') {
      body = JSON.stringify(output);
    }

    let headers = {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'no-store',
      'Pragma': 'no-cache',
      'Referrer-Policy': 'no-referrer'
    };

    if (typeof headersExtra === 'object') {
      headers = {...headers, ...headersExtra};
    }

    return {
      statusCode: code,
      body: body,
      headers: headers
    };  
  },
  // Format error output data.
  buildOutputError: function(statusCode, error) {
    let output = {};

    switch (statusCode) {
      case 400:
        output = {
          statusMessage: '400 Bad Request',
          error: 'invalid_request',
          error_description: error.message || ''
        };      
        break;

      case 401:
        output = {
          statusMessage: '401 Unauthorized',
          error: 'unauthorized_client',
          error_description: error.message || ''
        };      
        break;

      case 403:
        output = {
          statusMessage: '403 Forbidden',
          error: 'access_denied',
          error_description: error.message || ''
        };      
        break;

      case 503:
        output = {
          statusMessage: '503 Service Unavailable',
          error: 'temporarily_unavailable',
          error_description: error.message || ''
        };      
        break;

      default:
        output = {
          statusMessage: '500 Internal Server Error',
          error: 'server_error',
          error_description: error.message || ''
        };
    }
    
    return output;
  }
};
