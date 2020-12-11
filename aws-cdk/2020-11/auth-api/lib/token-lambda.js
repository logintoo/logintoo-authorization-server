const cdk = require('@aws-cdk/core');
const lambda = require('@aws-cdk/aws-lambda');

class LogintooToken extends cdk.Construct {
  constructor(scope, id, props) {
    super(scope, id, props);

    // Issue access and refresh tokens.
    const accessTokenLambda = new lambda.Function(this, 'accessTokenLambda', {
      functionName: 'logintoo-access-token-' + props.API_VERSION,
      code: new lambda.AssetCode('lambda'),
      handler: 'access-token.handler',
      runtime: lambda.Runtime.NODEJS_12_X,
      description: 'Validates the access token request and issues access and refresh tokens. API version ' + props.API_VERSION + '.',
      memorySize: 128,
      timeout: cdk.Duration.seconds(10),
      environment: {
        ACCESS_TOKEN_EXP_RANGE: props.ACCESS_TOKEN_EXP_RANGE,
        CLIENT_ID_PATTERN: props.CLIENT_ID_PATTERN,
        CODE_PATTERN: props.CODE_PATTERN,
        CODE_VERIFIER_PATTERN: props.CODE_VERIFIER_PATTERN,
        CACHE_TABLE_NAME: props.cacheTable.tableName,
        AUTH_CODE_INDEX_NAME: props.AUTH_CODE_INDEX_NAME,
        CLIENTS_TABLE_NAME: props.clientsTable.tableName,
        ISS: props.ISS,
        REFRESH_TOKEN_EXP_RANGE: props.REFRESH_TOKEN_EXP_RANGE,
        KEY_ARN: props.jwtKey.keyArn,
        KEY_ID: props.jwtKey.keyId
      }
    });

    // Refresh access token and rotate refresh token.
    const refreshTokenLambda = new lambda.Function(this, 'refreshTokenLambda', {
      functionName: 'logintoo-refresh-token-' + props.API_VERSION,
      code: new lambda.AssetCode('lambda'),
      handler: 'refresh-token.handler',
      runtime: lambda.Runtime.NODEJS_12_X,
      description: 'Validates the refresh token request, issues access token and rotates refresh token. API version ' + props.API_VERSION + '.',
      memorySize: 128,
      timeout: cdk.Duration.seconds(10),
      environment: {
        ACCESS_TOKEN_EXP_RANGE: props.ACCESS_TOKEN_EXP_RANGE,
        CACHE_TABLE_NAME: props.cacheTable.tableName,
        CLIENTS_TABLE_NAME: props.clientsTable.tableName,
        ISS: props.ISS,
        KEY_ARN: props.jwtKey.keyArn,
        KEY_ID: props.jwtKey.keyId,
        REFRESH_TOKEN_EXP_RANGE: props.REFRESH_TOKEN_EXP_RANGE,
        TOKEN_PATTERN: props.TOKEN_PATTERN
      }
    });

    // Delete record in the Cache Table, log out.
    const deleteTokenLambda = new lambda.Function(this, 'deleteTokenLambda', {
      functionName: 'logintoo-delete-token-' + props.API_VERSION,
      code: new lambda.AssetCode('lambda'),
      handler: 'delete-token.handler',
      runtime: lambda.Runtime.NODEJS_12_X,
      description: 'Validates logout request, erases the corresponding record in the Cache Table. API version ' + props.API_VERSION + '.',
      memorySize: 128,
      timeout: cdk.Duration.seconds(10),
      environment: {
        CACHE_TABLE_NAME: props.cacheTable.tableName,
        ISS: props.ISS,
        KEY_ARN: props.jwtKey.keyArn,
        KEY_ID: props.jwtKey.keyId,
        TOKEN_PATTERN: props.TOKEN_PATTERN
      }
    });

    // Add permissions to the Lambda functions.
    props.cacheTable.grantReadWriteData(accessTokenLambda);
    props.clientsTable.grantReadData(accessTokenLambda);
    props.jwtKey.grant(accessTokenLambda, 'kms:Sign');

    props.cacheTable.grantReadWriteData(refreshTokenLambda);
    props.clientsTable.grantReadData(refreshTokenLambda);
    props.jwtKey.grant(refreshTokenLambda, 'kms:Sign');
    props.jwtKey.grant(refreshTokenLambda, 'kms:Verify');

    props.cacheTable.grantReadWriteData(deleteTokenLambda);
    props.jwtKey.grant(deleteTokenLambda, 'kms:Verify');

    this.accessToken = accessTokenLambda;
    this.refreshToken = refreshTokenLambda;
    this.deleteToken = deleteTokenLambda;
  }
}

module.exports = { LogintooToken };
