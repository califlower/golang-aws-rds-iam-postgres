# How to connect to RDS Postgres using IAM Authentication in Golang (Valid as of 3/10/2020)

https://gist.github.com/quiver/509e1a6e6b54a0148527553502e9f55d#file-iam_auth_psql-sh 
This link was an incredible help, this document serves to tie most of it together and add in some other possibly relevant tips for 

Setup an EC2 that you can ssh in to test your work out. We will start by connecting using the aws cli, as once you have gotten that working, getting Go to work is semi trivial with some gotchas.
### Issue

If you are using AWS IAM credentials, then AWS's tutorial works fine. You should be able to do

```
$ RDSHOST=xxx.yyy.us-east-1.rds.amazonaws.com
$ USERNAME=jane_doe
$ export PGPASSWORD="$( aws rds generate-db-auth-token --hostname $RDSHOST --port 5432 --username $USERNAME )"
$ psql "host=$RDSHOST dbname=$DBNAME user=$USERNAME"
```
and the password generated should work. 

The problem happens when you aren't using IAM credentials, but instead you are using IAM Roles (most enterprise environments are probably using roles). Using the password generated will cause a `PAM Authentication Failed Error` which is unhelpful at best. 

To fix this, you have to explicitely assume the the role that contains the the IAM policy allowing the RDS connection.

### Solution

You can follow this script by Github user quiver
```
#! /bin/bash
# helper script to connect to Amazon RDS PostgreSQL with IAM credentials
# https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html

REGION=us-east-1
AWS_ACCOUNT_ID=123456789012
ROLE=EC2WebRole
ROLE_SESSION_NAME=ROLE_SESSION_NAME
DURATION=900

RDSHOST=xxx.yyy.us-east-1.rds.amazonaws.com
USERNAME=jane_doe
DBNAME=dbname

# explicitly assume role
result="$(aws sts assume-role \
  --role-arn arn:aws:iam::$AWS_ACCOUNT_ID:role/$ROLE \
  --role-session-name $ROLE_SESSION_NAME \
  --duration-seconds $DURATION \
  --region $REGION)"

export AWS_ACCESS_KEY_ID=`echo ${result} | jq -r '.Credentials.AccessKeyId'`
export AWS_SECRET_ACCESS_KEY=`echo ${result} | jq -r '.Credentials.SecretAccessKey'`
export AWS_SESSION_TOKEN=`echo ${result} | jq -r '.Credentials.SessionToken'`

# connect to PostgreSQL via IAM DB auth
export PGPASSWORD="$( aws rds generate-db-auth-token  \
  --hostname $RDSHOST \
  --port 5432 \
  --username $USERNAME \
  --region $REGION)"

psql "host=$RDSHOST dbname=$DBNAME user=$USERNAME"
```

#### Possible Error Scenarios
Where things get annoying is in an enterprise environments, 

`aws sts assume-role` may fail to find either your instance metadata/the assume with an error along the lines of  `credentials not found. Use aws configure`

In this case, you have to make sure that you have No PROXY Set to the sts endpoint

```
export NO_PROXY=169.254.169.254
``` 

You may also want to add other endpoints such as 
```
export NO_PROXY=s3.amazonaws.com,localhost,127.0.0.1,169.254.169.254,10.0.0.0/8"
```

The other possibly failure appears to be if your other proxies are not set.

Make sure you export the following environment variables with your proper proxies.
```
export https_proxy=<your enterprise aws proxy>
export http_proxy=<your enterprise aws proxy>
export HTTPS_PROXY=<your enterprise aws proxy>
export HTTP_PROXY=<your enterprise aws proxy>
```


###
The documentation for the go code is out of date, and all the tutorials are absolutely unhelpful in this regard.




Once you get it all setup, there are some more gotchas. The AWS SDK Will not renew your token once it expires, so after 15 minutes your app will stop working.


Thanks to Alex on this particular issue here for helping me out with this
https://github.com/aws/aws-sdk-go/issues/3043#issuecomment-581931580

```
type iamDb struct {
	Config
	awsSession *session.Session
}

// driver.Connector Interface
func (config *iamDb) Connect(ctx context.Context) (driver.Conn, error) {
	awsRegion := *config.awsSession.Config.Region
	awsCreds := config.awsSession.Config.Credentials
	dbEndpoint := fmt.Sprintf("%s:%d", config.Host, config.Port)

	authToken, err := rdsutils.BuildAuthToken(dbEndpoint, awsRegion, config.Username, awsCreds)
	if err != nil {
		return nil, err
	}

	psqlUrl, err := url.Parse("postgres://")
	if err != nil {
		return nil, err
	}

	psqlUrl.Host = dbEndpoint
	psqlUrl.User = url.UserPassword(config.Username, authToken)
	psqlUrl.Path = config.Dbname

	q := psqlUrl.Query()
	q.Add("sslmode", config.SslMode)
	q.Add("sslrootcert", config.SslRootCert)

	psqlUrl.RawQuery = q.Encode()

	pgxDriver := &stdlib.Driver{}
	connector, err := pgxDriver.OpenConnector(psqlUrl.String())
	if err != nil {
		return nil, err
	}
	return connector.Connect(ctx)
}

func (config *iamDb) Driver() driver.Driver {
	return config
}

var DriverNotSupportedErr = errors.New("driver open method not supported")

// driver.Driver interface
func (config *iamDb) Open(name string) (driver.Conn, error) {
	return nil, DriverNotSupportedErr
}

func newConnectionPoolWithIam(awsSession *session.Session, config Config) *sqlx.DB {
	db := sql.OpenDB(&iamDb{config, awsSession})
	return sqlx.NewDb(db, "pgx")
}
```

Essentially you provide a custom `Connect` function that fullfills your drivers interface. This will then cause the driver to generate a new DB Auth token upon generating a new connection. 

##### Note : sqlx.NewDb and sql.OpenDB don't ping the connection to see if it works. Make sure you tack in a db.Ping() if you want to truly test that a connection was opened (for example on first run of your app) otherwise you will think things have worked when they havent

IAM passwords last only 15 minutes, but an open connection will not be terminated once it reaches 15 minutes. After 15 minutes, subsequent new connections to the DB will require a new password.








