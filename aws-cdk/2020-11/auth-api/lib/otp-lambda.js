const cdk = require('@aws-cdk/core');
const lambda = require('@aws-cdk/aws-lambda');
const { DynamoEventSource } = require('@aws-cdk/aws-lambda-event-sources');

class LogintooOtp extends cdk.Construct {
  constructor(scope, id, props) {
    super(scope, id, props);
    
    // Generate OTP function.
    const generateOtpLambda = new lambda.Function(this, 'generateOtpLambda', {
      functionName: 'logintoo-generate-otp-' + props.API_VERSION,
      code: new lambda.AssetCode('lambda'),
      handler: 'generate-otp.handler',
      runtime: lambda.Runtime.NODEJS_12_X,
      description: 'Generates a one-time password and saves data in the cache table. API version ' + props.API_VERSION + '.',
      memorySize: 128,
      timeout: cdk.Duration.seconds(10),
      environment: {
        CACHE_TABLE_NAME: props.cacheTable.tableName,
        CLIENT_ID_PATTERN: props.CLIENT_ID_PATTERN,
        CLIENTS_TABLE_NAME: props.clientsTable.tableName,
        CODE_CHALLENGE_PATTERN: props.CODE_CHALLENGE_PATTERN,
        LANGUAGE_PATTERN: props.LANGUAGE_PATTERN,
        LOCALE_PATTERN: props.LOCALE_PATTERN,
        NORMALIZED_EMAIL_INDEX_NAME: props.NORMALIZED_EMAIL_INDEX_NAME,
        OTP_ATTEMPTS_RANGE: props.OTP_ATTEMPTS_RANGE,
        OTP_LENGTH_RANGE: props.OTP_LENGTH_RANGE,
        OTP_PATTERN: props.OTP_PATTERN,
        OTP_TIMEOUT_RANGE: props.OTP_TIMEOUT_RANGE,
        STATE_PATTERN: props.STATE_PATTERN
      }
    });
  
    generateOtpLambda.addEventSource(new DynamoEventSource(props.cacheTable, {
      startingPosition: lambda.StartingPosition.TRIM_HORIZON,
      batchSize: 10,
      bisectBatchOnError: true,
      maxBatchingWindow: cdk.Duration.seconds(10),
      maxRecordAge: cdk.Duration.minutes(30),
      parallelizationFactor: 1,
      retryAttempts: 10
    }));
    
    // Add permission to the Lambda function.
    props.cacheTable.grantReadWriteData(generateOtpLambda);
    props.clientsTable.grantReadData(generateOtpLambda);

    // Send OTP Function.
    const sendOtpLambda = new lambda.Function(this, 'sendOtpLambda', {
      functionName: 'logintoo-send-otp-' + props.API_VERSION,
      code: new lambda.AssetCode('lambda'),
      handler: 'send-otp.handler',
      runtime: lambda.Runtime.NODEJS_12_X,
      description: 'Listens to the cache table stream and emails the OTP to a user. API version ' + props.API_VERSION + '.',
      memorySize: 128,
      timeout: cdk.Duration.seconds(10),
      environment: {
        SENDGRID_API_KEY: props.SENDGRID_API_KEY,
        SYS_EMAIL_FROM: props.SYS_EMAIL_FROM
      }
    });

    sendOtpLambda.addEventSource(new DynamoEventSource(props.cacheTable, {
      startingPosition: lambda.StartingPosition.TRIM_HORIZON,
      batchSize: 10,
      bisectBatchOnError: true,
      maxBatchingWindow: cdk.Duration.seconds(10),
      maxRecordAge: cdk.Duration.minutes(30),
      parallelizationFactor: 1,
      retryAttempts: 10
    }));

    // Verify OTP Function.
    const verifyOtpLambda = new lambda.Function(this, 'verifyOtpLambda', {
      functionName: 'logintoo-verify-otp-' + props.API_VERSION,
      code: new lambda.AssetCode('lambda'),
      handler: 'verify-otp.handler',
      runtime: lambda.Runtime.NODEJS_12_X,
      description: 'Verifies OTP, generates the Authorization Code. API version ' + props.API_VERSION + '.',
      memorySize: 128,
      timeout: cdk.Duration.seconds(10),
      environment: {
        CLIENT_ID_PATTERN: props.CLIENT_ID_PATTERN,
        CODE_CHALLENGE_PATTERN: props.CODE_CHALLENGE_PATTERN,
        OTP_PATTERN: props.OTP_PATTERN,
        CACHE_TABLE_NAME: props.cacheTable.tableName,
        NORMALIZED_EMAIL_INDEX_NAME: props.NORMALIZED_EMAIL_INDEX_NAME
      }
    });

    // Add permissions to the Lambda function.
    props.cacheTable.grantReadWriteData(verifyOtpLambda);

    this.generateOtp = generateOtpLambda;
    this.sendOtp = sendOtpLambda;
    this.verifyOtp = verifyOtpLambda;

  }
}

module.exports = { LogintooOtp };
