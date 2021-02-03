const cdk = require('@aws-cdk/core');
const apigw = require('@aws-cdk/aws-apigateway');
const iam = require('@aws-cdk/aws-iam');
const { Certificate } = require('@aws-cdk/aws-certificatemanager');

class LogintooApi extends cdk.Construct {
  constructor(scope, id, props) {
    super(scope, id, props);
    
    // API Gateway.
    const api = new apigw.RestApi(this, 'logintoo-' + props.API_VERSION, {
      description: 'Logintoo Auth and Token endpoints. Version ' + props.API_VERSION + '.'
    });

    const domain = new apigw.DomainName(this, 'custom-domain', {
      domainName: props.API_DOMAIN_NAME,
      certificate: Certificate.fromCertificateArn(this, 'certificate', props.CERTIFICATE_ARN),
      endpointType: apigw.EndpointType.EDGE,
      securityPolicy: apigw.SecurityPolicy.TLS_1_2
    });
    domain.addBasePathMapping(api, {
      basePath: props.API_VERSION
    });

    api.addGatewayResponse('bad_request_body', {
      type: apigw.ResponseType.BAD_REQUEST_BODY,
      statusCode: '400',
      responseHeaders: {
        'Access-Control-Allow-Origin': "'*'",
        'Cache-Control': "'no-store'",
        'Pragma': "'no-cache'",
        'Referrer-Policy': "'no-referrer'"
      },
      templates: {
        'application/json': '{ "message": $context.error.messageString, "error": "invalid_request"}'
      }
    });

    const authorizeResource = api.root.addResource('auth');
    const otpResource = api.root.addResource('otp');
    const tokenResource = api.root.addResource('token');

    // Models to validate input. Checks if all the required parameters are present in the request.
    // Request can also contain arbitrary parameters, they will be forwarded with no changes.
    const authorizeModel = new apigw.Model(this, 'authorize', {
      restApi: api,
      schema: {
        type: apigw.JsonSchemaType.OBJECT,
        properties: {
          client_id: {type: apigw.JsonSchemaType.STRING, pattern: props.CLIENT_ID_PATTERN},
          code_challenge: {type: apigw.JsonSchemaType.STRING, pattern: props.CODE_CHALLENGE_PATTERN},
          code_challenge_method: {type: apigw.JsonSchemaType.STRING, enum: ['S256']},
          email: {type: apigw.JsonSchemaType.STRING, format: 'email'},
          redirect_uri: {type: apigw.JsonSchemaType.STRING, format: 'uri'},
          response_type: {type: apigw.JsonSchemaType.STRING, enum: ['code']},
          state: {type: apigw.JsonSchemaType.STRING, pattern: props.STATE_PATTERN},
          language: {type: apigw.JsonSchemaType.STRING, pattern: props.LANGUAGE_PATTERN},
          locale: {type: apigw.JsonSchemaType.STRING, pattern: props.LOCALE_PATTERN}
        },
        required: ['client_id', 'code_challenge', 'code_challenge_method', 'email', 'redirect_uri', 'response_type', 'state'],
        title: 'Authorize Schema'
      },
      contentType: 'application/json'
    });
    const otpModel = new apigw.Model(this, 'otp', {
      restApi: api,
      schema: {
        type: apigw.JsonSchemaType.OBJECT,
        properties: {
          client_id: {type: apigw.JsonSchemaType.STRING, pattern: props.CLIENT_ID_PATTERN},
          code_challenge: {type: apigw.JsonSchemaType.STRING, pattern: props.CODE_CHALLENGE_PATTERN},
          email: {type: apigw.JsonSchemaType.STRING, format: 'email'},
          otp: {type: apigw.JsonSchemaType.STRING, pattern: props.OPT_PATTERN}
        },
        required: ['client_id', 'code_challenge', 'email', 'otp'],
        title: 'OTP Schema'
      },
      contentType: 'application/json'
    });
    const accessTokenModel = new apigw.Model(this, 'accessToken', {
      restApi: api,
      schema: {
        type: apigw.JsonSchemaType.OBJECT,
        properties: {
          grant_type: {type: apigw.JsonSchemaType.STRING, enum: ['authorization_code']},
          code: {type: apigw.JsonSchemaType.STRING, pattern: props.CODE_PATTERN},
          redirect_uri: {type: apigw.JsonSchemaType.STRING, format: 'uri'},
          client_id: {type: apigw.JsonSchemaType.STRING, pattern: props.CLIENT_ID_PATTERN},
          code_verifier: {type: apigw.JsonSchemaType.STRING, pattern: props.CODE_VERIFIER_PATTERN}
        },
        required: ['grant_type', 'code', 'redirect_uri', 'client_id', 'code_verifier'],
        title: 'Access Token Schema'
      },
      contentType: 'application/json'
    });
    const refreshTokenModel = new apigw.Model(this, 'refreshToken', {
      restApi: api,
      schema: {
        type: apigw.JsonSchemaType.OBJECT,
        properties: {
          grant_type: {type: apigw.JsonSchemaType.STRING, enum: ['refresh_token']},
          refresh_token: {type: apigw.JsonSchemaType.STRING, pattern: props.TOKEN_PATTERN}
        },
        required: ['grant_type', 'refresh_token'],
        title: 'Refresh Token Schema'
      },
      contentType: 'application/json'
    });
    const deleteTokenModel = new apigw.Model(this, 'deleteToken', {
      restApi: api,
      schema: {
        type: apigw.JsonSchemaType.OBJECT,
        properties: {
          refresh_token: {type: apigw.JsonSchemaType.STRING, pattern: props.TOKEN_PATTERN}
        },
        required: ['refresh_token'],
        title: 'Delete Token Schema'
      },
      contentType: 'application/json'
    });

    const authorizeValidator = new apigw.RequestValidator(this, 'authorizeBody', {
      restApi: api,
      validateRequestBody: true
    });
    const otpValidator = new apigw.RequestValidator(this, 'otpBody', {
      restApi: api,
      validateRequestBody: true
    });
    const accessTokenValidator = new apigw.RequestValidator(this, 'accessTokenBody', {
      restApi: api,
      validateRequestBody: true
    });
    const refreshTokenValidator = new apigw.RequestValidator(this, 'refreshTokenBody', {
      restApi: api,
      validateRequestBody: true
    });
    const deleteTokenValidator = new apigw.RequestValidator(this, 'deleteTokenBody', {
      restApi: api,
      validateRequestBody: true
    });

    const authorizeRolePolicy = new iam.Policy(this, 'authorizeRolePolicy', {
      statements: [
        new iam.PolicyStatement({
          actions: ['dynamodb:PutItem'],
          effect: iam.Effect.ALLOW,
          resources: [props.cacheTable.tableArn]
        })
      ]
    });
    const authorizeRole = new iam.Role(this, 'authorizeRole', {
      assumedBy: new iam.ServicePrincipal('apigateway.amazonaws.com'),
      inlinePolicies: {'allowDBput': authorizeRolePolicy.document}
    });
    
    const authorizeIntegration = new apigw.AwsIntegration({
      service: 'dynamodb',
      action: 'PutItem',
      integrationHttpMethod: 'POST',
      options: {
        credentialsRole: authorizeRole,
        integrationResponses: [
          {
            statusCode: '200',
            responseParameters: {
              'method.response.header.Access-Control-Allow-Origin': "'*'",
              'method.response.header.Cache-Control': "'no-store'",
              'method.response.header.Pragma': "'no-cache'",
              'method.response.header.Referrer-Policy': "'no-referrer'"
            },
            responseTemplates: {
              'application/json': JSON.stringify({statusCode: 200, statusMessage: '200 OK'})
            }
          },
          {
            statusCode: '400',
            selectionPattern: '4\\d{2}',
            responseParameters: {
              'method.response.header.Access-Control-Allow-Origin': "'*'",
              'method.response.header.Cache-Control': "'no-store'",
              'method.response.header.Pragma': "'no-cache'",
              'method.response.header.Referrer-Policy': "'no-referrer'"
            },
            responseTemplates: {
              'application/json': JSON.stringify({
                statusCode: 400,
                statusMessage: '400 Bad Request',
                endpointResponse: '$input.json(\'$\')'
              })
            }
          },
          {
            statusCode: '500',
            selectionPattern: '5\\d{2}',
            responseParameters: {
              'method.response.header.Access-Control-Allow-Origin': "'*'",
              'method.response.header.Cache-Control': "'no-store'",
              'method.response.header.Pragma': "'no-cache'",
              'method.response.header.Referrer-Policy': "'no-referrer'"
            },
            responseTemplates: {
              'application/json': JSON.stringify({statusCode: 500, statusMessage: '500 Internal Server Error'})
            }
          }
        ],
        passthroughBehavior: apigw.PassthroughBehavior.WHEN_NO_TEMPLATES,
        requestTemplates:{
          'application/json': ' \
          #set($ttl = $context.requestTimeEpoch / 1000 + ' + props.CACHE_TTL + ')\n \
          #set($body = $util.parseJson($input.body))\n \
          {\n \
            \"TableName\": \"' + props.cacheTable.tableName + '\",\n \
            \"Item\": {\n \
              \"id\": {\"S\": \"$context.requestId\"},\n \
              \"ttl\": {\"N\": \"$ttl\"},\n \
              \"body\": {\"S\": \"$util.escapeJavaScript($input.json(\'$\'))\"},\n \
              \n \
              \"userAgent\": {\"L\": [{\"S\": \"$context.identity.userAgent\"}]},\n \
              \n \
              #if ($body.get(\'language\') != \'\') \"language\": {\"S\": \"$body.get(\'language\')\"}, #end\n \
              #if ($body.get(\'locale\') != \'\') \"locale\": {\"S\": \"$body.get(\'locale\')\"}, #end\n \
              \n \
              #if ($input.params(\'CF-Connecting-IP\') != \'\')\n \
                \"sourceIp\": {\"L\": [{\"S\": \"$input.params(\'CF-Connecting-IP\')\"}]},\n \
              #else\n \
                \"sourceIp\": {\"L\": [{\"S\": \"$context.identity.sourceIp\"}]},\n \
              #end\n \
              \n \
              #if ($input.params(\'CF-IPCountry\') != \'\')\n \
                \"country\": {\"S\": \"$input.params(\'CF-IPCountry\')\"},\n \
              #else\n \
                \"country\": {\"S\": \"$input.params(\'CloudFront-Viewer-Country\')\"},\n \
              #end\n \
              \n \
              \"client_id\": {\"S\": \"$body.get(\'client_id\')\"},\n \
              \"code_challenge\": {\"S\": \"$body.get(\'code_challenge\')\"},\n \
              \"code_challenge_method\": {\"S\": \"$body.get(\'code_challenge_method\')\"},\n \
              \"email\": {\"S\": \"$body.get(\'email\')\"},\n \
              \"redirect_uri\": {\"S\": \"$body.get(\'redirect_uri\')\"},\n \
              \"response_type\": {\"S\": \"$body.get(\'response_type\')\"},\n \
              \"state\": {\"S\": \"$body.get(\'state\')\"}\n \
            },\n \
            \"ReturnValues\": \"NONE\"\n \
          }'
        }
      }
    });
    const otpIntegration = new apigw.LambdaIntegration(props.verifyOtp);
    const accessTokenIntegration = new apigw.LambdaIntegration(props.accessToken);
    const refreshTokenIntegration = new apigw.LambdaIntegration(props.refreshToken);
    const deleteTokenIntegration = new apigw.LambdaIntegration(props.deleteToken);

    authorizeResource.addMethod('POST', authorizeIntegration, {
      methodResponses: [
        {
          statusCode: '200',
          responseParameters: {
            'method.response.header.Access-Control-Allow-Origin': true,
            'method.response.header.Cache-Control': true,
            'method.response.header.Pragma': true,
            'method.response.header.Referrer-Policy': true
          }
        },
        {
          statusCode: '400',
          responseParameters: {
            'method.response.header.Access-Control-Allow-Origin': true,
            'method.response.header.Cache-Control': true,
            'method.response.header.Pragma': true,
            'method.response.header.Referrer-Policy': true
          }
        },
        {
          statusCode: '500',
          responseParameters: {
            'method.response.header.Access-Control-Allow-Origin': true,
            'method.response.header.Cache-Control': true,
            'method.response.header.Pragma': true,
            'method.response.header.Referrer-Policy': true
          }
        }
      ],
      requestModels: {
        'application/json': authorizeModel
      },
      requestValidator: authorizeValidator
    });
    otpResource.addMethod('POST', otpIntegration, {
      methodResponses: [
        {
          statusCode: '200',
          responseParameters: {
            'method.response.header.Access-Control-Allow-Origin': true,
            'method.response.header.Cache-Control': true,
            'method.response.header.Pragma': true,
            'method.response.header.Referrer-Policy': true
          }
        },
        {
          statusCode: '400',
          responseParameters: {
            'method.response.header.Access-Control-Allow-Origin': true,
            'method.response.header.Cache-Control': true,
            'method.response.header.Pragma': true,
            'method.response.header.Referrer-Policy': true
          }
        },
        {
          statusCode: '401',
          responseParameters: {
            'method.response.header.Access-Control-Allow-Origin': true,
            'method.response.header.Cache-Control': true,
            'method.response.header.Pragma': true,
            'method.response.header.Referrer-Policy': true
          }
        },
        {
          statusCode: '403',
          responseParameters: {
            'method.response.header.Access-Control-Allow-Origin': true,
            'method.response.header.Cache-Control': true,
            'method.response.header.Pragma': true,
            'method.response.header.Referrer-Policy': true
          }
        },
        {
          statusCode: '500',
          responseParameters: {
            'method.response.header.Access-Control-Allow-Origin': true,
            'method.response.header.Cache-Control': true,
            'method.response.header.Pragma': true,
            'method.response.header.Referrer-Policy': true
          }
        },
        {
          statusCode: '503',
          responseParameters: {
            'method.response.header.Access-Control-Allow-Origin': true,
            'method.response.header.Cache-Control': true,
            'method.response.header.Pragma': true,
            'method.response.header.Referrer-Policy': true
          }
        }
      ],
      requestModels: {
        'application/json': otpModel
      },
      requestValidator: otpValidator
    });
    tokenResource.addMethod('POST', accessTokenIntegration, {
      methodResponses: [
        {
          statusCode: '200',
          responseParameters: {
            'method.response.header.Access-Control-Allow-Origin': true,
            'method.response.header.Cache-Control': true,
            'method.response.header.Pragma': true,
            'method.response.header.Referrer-Policy': true
          }
        },
        {
          statusCode: '400',
          responseParameters: {
            'method.response.header.Access-Control-Allow-Origin': true,
            'method.response.header.Cache-Control': true,
            'method.response.header.Pragma': true,
            'method.response.header.Referrer-Policy': true
          }
        },
        {
          statusCode: '401',
          responseParameters: {
            'method.response.header.Access-Control-Allow-Origin': true,
            'method.response.header.Cache-Control': true,
            'method.response.header.Pragma': true,
            'method.response.header.Referrer-Policy': true
          }
        },
        {
          statusCode: '403',
          responseParameters: {
            'method.response.header.Access-Control-Allow-Origin': true,
            'method.response.header.Cache-Control': true,
            'method.response.header.Pragma': true,
            'method.response.header.Referrer-Policy': true
          }
        },
        {
          statusCode: '500',
          responseParameters: {
            'method.response.header.Access-Control-Allow-Origin': true,
            'method.response.header.Cache-Control': true,
            'method.response.header.Pragma': true,
            'method.response.header.Referrer-Policy': true
          }
        },
        {
          statusCode: '503',
          responseParameters: {
            'method.response.header.Access-Control-Allow-Origin': true,
            'method.response.header.Cache-Control': true,
            'method.response.header.Pragma': true,
            'method.response.header.Referrer-Policy': true
          }
        }
      ],
      requestModels: {
        'application/json': accessTokenModel
      },
      requestValidator: accessTokenValidator
    });
    tokenResource.addMethod('PATCH', refreshTokenIntegration, {
      methodResponses: [
        {
          statusCode: '200',
          responseParameters: {
            'method.response.header.Access-Control-Allow-Origin': true,
            'method.response.header.Cache-Control': true,
            'method.response.header.Pragma': true,
            'method.response.header.Referrer-Policy': true
          }
        },
        {
          statusCode: '400',
          responseParameters: {
            'method.response.header.Access-Control-Allow-Origin': true,
            'method.response.header.Cache-Control': true,
            'method.response.header.Pragma': true,
            'method.response.header.Referrer-Policy': true
          }
        },
        {
          statusCode: '401',
          responseParameters: {
            'method.response.header.Access-Control-Allow-Origin': true,
            'method.response.header.Cache-Control': true,
            'method.response.header.Pragma': true,
            'method.response.header.Referrer-Policy': true
          }
        },
        {
          statusCode: '403',
          responseParameters: {
            'method.response.header.Access-Control-Allow-Origin': true,
            'method.response.header.Cache-Control': true,
            'method.response.header.Pragma': true,
            'method.response.header.Referrer-Policy': true
          }
        },
        {
          statusCode: '500',
          responseParameters: {
            'method.response.header.Access-Control-Allow-Origin': true,
            'method.response.header.Cache-Control': true,
            'method.response.header.Pragma': true,
            'method.response.header.Referrer-Policy': true
          }
        },
        {
          statusCode: '503',
          responseParameters: {
            'method.response.header.Access-Control-Allow-Origin': true,
            'method.response.header.Cache-Control': true,
            'method.response.header.Pragma': true,
            'method.response.header.Referrer-Policy': true
          }
        }
      ],
      requestModels: {
        'application/json': refreshTokenModel
      },
      requestValidator: refreshTokenValidator
    });
    tokenResource.addMethod('DELETE', deleteTokenIntegration, {
      methodResponses: [
        {
          statusCode: '200',
          responseParameters: {
            'method.response.header.Access-Control-Allow-Origin': true,
            'method.response.header.Cache-Control': true,
            'method.response.header.Pragma': true,
            'method.response.header.Referrer-Policy': true
          }
        },
        {
          statusCode: '400',
          responseParameters: {
            'method.response.header.Access-Control-Allow-Origin': true,
            'method.response.header.Cache-Control': true,
            'method.response.header.Pragma': true,
            'method.response.header.Referrer-Policy': true
          }
        },
        {
          statusCode: '401',
          responseParameters: {
            'method.response.header.Access-Control-Allow-Origin': true,
            'method.response.header.Cache-Control': true,
            'method.response.header.Pragma': true,
            'method.response.header.Referrer-Policy': true
          }
        },
        {
          statusCode: '403',
          responseParameters: {
            'method.response.header.Access-Control-Allow-Origin': true,
            'method.response.header.Cache-Control': true,
            'method.response.header.Pragma': true,
            'method.response.header.Referrer-Policy': true
          }
        },
        {
          statusCode: '500',
          responseParameters: {
            'method.response.header.Access-Control-Allow-Origin': true,
            'method.response.header.Cache-Control': true,
            'method.response.header.Pragma': true,
            'method.response.header.Referrer-Policy': true
          }
        },
        {
          statusCode: '503',
          responseParameters: {
            'method.response.header.Access-Control-Allow-Origin': true,
            'method.response.header.Cache-Control': true,
            'method.response.header.Pragma': true,
            'method.response.header.Referrer-Policy': true
          }
        }
      ],
      requestModels: {
        'application/json': deleteTokenModel
      },
      requestValidator: deleteTokenValidator
    });

    // Add the CORS preflight OPTIONS method.
    authorizeResource.addCorsPreflight({
      allowOrigins: ['*'],
      allowMethods: ['POST']
    });
    otpResource.addCorsPreflight({
      allowOrigins: ['*'],
      allowMethods: ['POST']
    });
    tokenResource.addCorsPreflight({
      allowOrigins: ['*'],
      allowMethods: ['POST', 'PATCH', 'DELETE']
    });
  }
}

module.exports = { LogintooApi };
