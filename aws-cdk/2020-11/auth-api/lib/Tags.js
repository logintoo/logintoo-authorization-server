const Config = require('./Config.js');
const cdk = require('@aws-cdk/core');

module.exports = {
  set: function(scope) {
    const tags = [];

    // Full path to the working directory.
    const pwd = process.env.PWD;
    if (pwd) {
      tags.push({
        key: 'Working Directory',
        value: pwd
      });
    }
  
    // Use the owner tag for known accounts or the OS username.
    const awsAccount = process.env.CDK_DEFAULT_ACCOUNT;
  
    tags.push({
      key: 'Owner',
      value: (Config.PROFILE[awsAccount].tags) ? Config.PROFILE[awsAccount].tags.owner : process.env.USER
    });

    // Tag all resources.
    for (let tag of tags) {
      cdk.Tags.of(scope).add(tag.key, tag.value);
    }
  }
};
