#!/usr/bin/env node

const cdk = require('@aws-cdk/core');
const { AuthApiStack } = require('../lib/auth-api-stack');

const app = new cdk.App();
new AuthApiStack(app, 'AuthApiStack');
