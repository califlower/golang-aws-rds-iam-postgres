# How to connect to RDS Postgres using IAM Authentication in Golang (Valid as of 3/10/2020)

[User: Quiver Postgres IAM Gist](https://gist.github.com/quiver/509e1a6e6b54a0148527553502e9f55d#file-iam_auth_psql-sh) 

This link was an incredible help, this document serves to tie most of it together and add in some other possibly relevant tips for people struggling to setup IAM authentication for postgres in an enterprise environment.

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

You will also need an IAM policy
```
{
   "Version": "2012-10-17",
   "Statement": [
      {
         "Effect": "Allow",
         "Action": [
             "rds-db:connect"
         ],
         "Resource": [
             "arn:aws:rds-db:region:account-id:dbuser:dbi-resource-id/database-user-name"
         ]
      }
   ]
```

Your instance will also have to have a role with this policy attached. Your instance will also need to have a role, with a policy allowing sts assume role to assume your own instance's role.


#### Possible Error Scenarios
Where things get annoying is in an enterprise environments, 

`aws sts assume-role` may fail to find either your instance metadata/the assume with an error along the lines of  `credentials not found. Use aws configure`

In this case, you have to make sure that you have NO PROXY Set to the sts endpoint. You can also typically append --debug to the end of aws commands to see what is failing.

```
export NO_PROXY=169.254.169.254
``` 

You may also want to add other endpoints such as 
```
export NO_PROXY=s3.amazonaws.com,localhost,127.0.0.1,169.254.169.254,10.0.0.0/8"
```

The other possibly failure appears to be if your other proxies are not set. These errors usually manifest app side, when your app tries to connect to certain things.

Make sure you export the following environment variables with your proper proxies.
```
export https_proxy=<your enterprise aws proxy>
export http_proxy=<your enterprise aws proxy>
export HTTPS_PROXY=<your enterprise aws proxy>
export HTTP_PROXY=<your enterprise aws proxy>
```


### Setting up your Golang code
The documentation for the go code is out of date, and all the tutorials are absolutely unhelpful in this regard.



Once you get it all setup, there are some more gotchas. The AWS SDK Will not renew your token once it expires, so after 15 minutes your app will stop working.


Thanks to Alex on this particular issue here for helping me out with this [AWS SDK Issue 3043](https://github.com/aws/aws-sdk-go/issues/3043#issuecomment-581931580)

Unfortunately, even this is a little bit old. With AWS-SDK, the code to generate an auth token is no longer identical. They introduced some breaking changes. Here is the code sample linked

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

In our application, we added a few different additions that some people may find helpul. I will address them below.


##### Note : sqlx.NewDb and sql.OpenDB don't ping the connection to see if it works. Make sure you tack in a db.Ping() if you want to truly test that a connection was opened (for example on first run of your app) otherwise you will think things have worked when they havent

IAM passwords last only 15 minutes, but an open connection will not be terminated once it reaches 15 minutes. After 15 minutes, subsequent new connections to the DB will require a new password.

### Working with CNAMEs

Unfortunately, IAM authentication doesn't seem to work with CNAME's. Perhaps it only works with route53 cnames, but who knows. Amazon recently released RDSProxy which works with IAM authenticaton. Unfortunately, it's not postgres ready.

What I added to my code was the following.

```
cnameUntrimmed, err := lookup(ia.DatabaseHost)

if err != nil {
	log.Error(ctx, fmt.Sprintf("could not lookup cname during iam auth: %v", err))
	return "", xerrors.Errorf("could not lookup cname during iam auth: %w", err)
}
//Trim the trailing dot from the cname
cname := strings.TrimRight(cnameUntrimmed, ".")
splitCname := strings.Split(cname, ".")

if len(splitCname) != 6 {
		return "", xerrors.New(fmt.Sprintf("cname not in AWS format, cname:%s ", cname))
}

region := splitCname[2]
log.Info(ctx, fmt.Sprintf("opening connection to cname=%s, region=%s", cname, region))

authToken, err := ia.AuthTokenGenerator.GetAuthToken(ctx, region, cname, ia.DatabasePort, ia.DatabaseUser, ia.AmazonResourceName)
```

Essentially every connection now has to do a CNAME lookup. Up to you to decide if the overhead is worth it.

### Full Code Sample from a production application. Some potentially sensitive things were removed
```
package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/external"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/aws/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/rds/rdsutils"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/jackc/pgx/v4/stdlib"
	"github.com/jmoiron/sqlx"
	"golang.org/x/xerrors"
)

type IAMAuth struct {
	DatabaseUser string
	DatabaseHost string
	DatabasePort string
	DatabaseName string
	AmazonResourceName string
	AuthTokenGenerator Generator
}

type iamDB struct {
	IAMAuth
}

type IAMAuthGenerator struct{}

type Generator interface {
	GetAuthToken(ctx context.Context, region, cname, port, user, arn string) (string, error)
}

//If not set, database can hang for an extremely long time trying to open a new connection
const databaseConnectionTimeoutMilliseconds = 5000


func (iam *IAMAuthGenerator) GetAuthToken(ctx context.Context, region, cname, port, user, arn string) (string, error) {
	cfg, err := external.LoadDefaultAWSConfig()

	if err != nil {
		return "", xerrors.Errorf("could not connect to db using iam auth: %w", err)
	}

	cfg.Region = region
	credProvider := stscreds.NewAssumeRoleProvider(sts.New(cfg), arn)

	signer := v4.NewSigner(credProvider)

	ctxWithTimeout, cancel := context.WithTimeout(ctx, databaseConnectionTimeoutMilliseconds*time.Millisecond)

	defer cancel()

	authToken, err := rdsutils.BuildAuthToken(ctxWithTimeout,
		fmt.Sprintf("%s:%s", cname, port),
		region, user, signer)

	return authToken, err
}

type LookupCNAME func(string) (string, error)

func (ia *IAMAuth) GetConnectionString(ctx context.Context, lookup LookupCNAME) (string, error) {
	cnameUntrimmed, err := lookup(ia.DatabaseHost)

	if err != nil {
		log.Error(ctx, fmt.Sprintf("could not lookup cname during iam auth: %v", err))
		return "", xerrors.Errorf("could not lookup cname during iam auth: %w", err)
	}
	//Trim the trailing dot from the cname
	cname := strings.TrimRight(cnameUntrimmed, ".")
	splitCname := strings.Split(cname, ".")

	if len(splitCname) != 6 {
		return "", xerrors.New(fmt.Sprintf("cname not in AWS format, cname:%s ", cname))
	}

	region := splitCname[2]

	authToken, err := ia.AuthTokenGenerator.GetAuthToken(ctx, region, cname, ia.DatabasePort, ia.DatabaseUser, ia.AmazonResourceName)

	if err != nil {
		return "", xerrors.Errorf("could not build auth token: %w", err)
	}

	var postgresConnection strings.Builder

	postgresConnection.WriteString(
		fmt.Sprintf("user=%s dbname=%s sslmode=%s port=%s host=%s password=%s",
			ia.DatabaseUser,
			ia.DatabaseName,
			"require",
			ia.DatabasePort,
			cname,
			authToken))

	return postgresConnection.String(), nil

}
func (id *iamDB) Connect(ctx context.Context) (driver.Conn, error) {

	connectionString, err := id.IAMAuth.GetConnectionString(ctx, net.LookupCNAME)

	if err != nil {
		return nil, xerrors.Errorf("could not get connection string: %w", err)
	}
	pgxConnector := &stdlib.Driver{}

	connector, err := pgxConnector.OpenConnector(connectionString)

	if err != nil {
		return nil, err
	}

	return connector.Connect(ctx)

}

func (id *iamDB) Driver() driver.Driver {
	return id
}

// driver.Driver interface
func (id *iamDB) Open(name string) (driver.Conn, error) {
	return nil, xerrors.New("driver open method unsupported")
}

func (ia IAMAuth) Connect(ctx context.Context) (*sqlx.DB, error) {
	db := sql.OpenDB(&iamDB{ia})

	err := db.Ping()

	if err != nil {
		return nil, xerrors.Errorf("could not ping db: %w", err)
	}

	return sqlx.NewDb(db, driverName), nil
}
```

Feel free to open an issue with any comments
