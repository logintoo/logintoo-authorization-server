const cdk = require('@aws-cdk/core');
const db = require('@aws-cdk/aws-dynamodb');

class LogintooDB extends cdk.Construct {
  constructor(scope, id, props) {
    super(scope, id, props);

    const clientsTable = new db.Table(this, 'clients', {
      tableName: props.CLIENTS_TABLE_NAME,
      partitionKey: {
        name: 'id',
        type: db.AttributeType.STRING
      },
      billingMode: db.BillingMode.PAY_PER_REQUEST,
      pointInTimeRecovery: true
    });

    const cacheTable = new db.Table(this, 'cache', {
      tableName: props.CACHE_TABLE_NAME,
      partitionKey: {
        name: 'id',
        type: db.AttributeType.STRING
      },
      billingMode: db.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: 'ttl',
      stream: db.StreamViewType.NEW_AND_OLD_IMAGES
    });
    
    cacheTable.addGlobalSecondaryIndex({
      indexName: props.NORMALIZED_EMAIL_INDEX_NAME,
      partitionKey: {
        name: 'email_normalized',
        type: db.AttributeType.STRING
      },
      sortKey: {
        name: 'code_challenge',
        type: db.AttributeType.STRING
      },
      projectionType: db.ProjectionType.ALL
    });
    cacheTable.addGlobalSecondaryIndex({
        indexName: props.AUTH_CODE_INDEX_NAME,
        partitionKey: {
          name: 'authorizationCode',
          type: db.AttributeType.STRING
        },
        projectionType: db.ProjectionType.ALL
    });
        
    this.clientsTable = clientsTable;
    this.cacheTable = cacheTable;

  }
}

module.exports = { LogintooDB };
