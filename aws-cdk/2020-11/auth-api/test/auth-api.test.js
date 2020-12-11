const { expect, matchTemplate, MatchStyle } = require('@aws-cdk/assert');
const cdk = require('@aws-cdk/core');
const AuthApi = require('../lib/auth-api-stack');

test('Empty Stack', () => {
    const app = new cdk.App();
    // WHEN
    const stack = new AuthApi.AuthApiStack(app, 'MyTestStack');
    // THEN
    expect(stack).to(matchTemplate({
      "Resources": {}
    }, MatchStyle.EXACT))
});
