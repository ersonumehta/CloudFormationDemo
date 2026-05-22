# Admin Access Approval Workflow

## 📝 Overview

This serverless security workflow automatically captures IAM admin policy assignments and requires security team approval before allowing the permissions to remain active. If rejected, the admin permissions are automatically removed.

## 🏛️ Architecture

```
IAM Policy Assignment → EventBridge → Step Functions State Machine
                                            ↓
                        ┌───────────────────┼───────────────────┐
                        │                   │                   │
                  Lambda:             SNS Topic         Lambda:
                  Validate         (Email Notification)  Remove
                  Permission                             Permission
                        │                   │                   ↑
                        │                   │                   │
                        └───────────────────┴───────────────────┘
                                            │
                                    API Gateway
                                    (/approve | /reject)
```

## 📦 Components

### AWS Resources Created

1. **DynamoDB Table** (`AdminAccessApprovals`)
   - Stores approval requests and audit trail
   - TTL enabled (90 days retention)
   - Global Secondary Indexes for querying by user and status

2. **Lambda Functions** (Python 3.12)
   - `ValidatePermission`: Validates IAM policy assignments and checks whitelist
   - `ApprovalCallback`: Handles approval/rejection callbacks from API Gateway
   - `RemovePermission`: Removes admin permissions when rejected

3. **Step Functions State Machine** (`AdminAccessApprovalWorkflow`)
   - Orchestrates the entire approval workflow
   - Handles validation, notification, waiting for callback, and removal

4. **SNS Topic** (`AdminAccessApprovalNotifications`)
   - Sends email notifications to security team
   - Encrypted with KMS

5. **API Gateway** (REST API)
   - `/approve` endpoint: Approves admin access
   - `/reject` endpoint: Rejects and removes admin access

6. **EventBridge Rule** (`CaptureAdminPolicyAssignments`)
   - Captures IAM policy assignment events
   - Triggers Step Functions workflow

7. **KMS Key**
   - Encrypts approval tokens
   - Encrypts SNS messages

8. **S3 Bucket** (Optional)
   - Stores audit logs for permission removals
   - 7-year retention policy

## 🚀 Deployment

### Prerequisites

1. **AWS CLI** installed and configured
   ```bash
   aws --version
   ```

2. **AWS SAM CLI** installed
   ```bash
   sam --version
   ```

3. **Python 3.12** installed
   ```bash
   python --version
   ```

4. **CloudTrail** enabled in your AWS account
   - EventBridge relies on CloudTrail to capture IAM events

### Deployment Steps

#### Step 1: Validate the SAM Template

```bash
cd stepfunction
sam validate
```

#### Step 2: Build the Application

```bash
sam build
```

This will:
- Install Python dependencies from `requirements.txt` for each Lambda function
- Package the Lambda code
- Prepare the CloudFormation template

#### Step 3: Deploy the Application

**First-time deployment (guided):**

```bash
sam deploy --guided
```

You will be prompted for:
- **Stack Name**: `admin-access-approval-workflow` (or your choice)
- **AWS Region**: `us-east-1` (or your preferred region)
- **SecurityTeamEmail**: Email address for security team notifications
- **ApprovalTokenExpiryHours**: `24` (default)
- **AdminPolicyPatterns**: `AdministratorAccess,PowerUserAccess,IAMFullAccess` (default)
- **EnableAuditLogging**: `false` (set to `true` to enable S3 audit logs)
- **Confirm changes before deploy**: `Y`
- **Allow SAM CLI IAM role creation**: `Y`
- **Save arguments to configuration file**: `Y`

**Subsequent deployments:**

```bash
sam deploy
```

#### Step 4: Confirm SNS Email Subscription

After deployment, the security team will receive a subscription confirmation email. **Click the confirmation link** to start receiving approval notifications.

### Deployment Output

After successful deployment, you'll see outputs including:

```
Outputs:
  DynamoDBTableName: AdminAccessApprovals
  SNSTopicArn: arn:aws:sns:us-east-1:123456789012:AdminAccessApprovalNotifications
  ApiGatewayUrl: https://abc123.execute-api.us-east-1.amazonaws.com/prod
  StateMachineArn: arn:aws:states:us-east-1:123456789012:stateMachine:AdminAccessApprovalWorkflow
```

## ⚙️ Configuration

### Environment Variables

Each Lambda function has specific environment variables configured via the SAM template:

#### ValidatePermission Function
- `APPROVALS_TABLE`: DynamoDB table name
- `ADMIN_POLICY_PATTERNS`: Comma-separated policy name patterns
- `LOG_LEVEL`: Logging level (INFO, DEBUG, ERROR)

#### ApprovalCallback Function
- `APPROVALS_TABLE`: DynamoDB table name
- `KMS_KEY_ID`: KMS key ID for token decryption
- `TOKEN_EXPIRY_HOURS`: Token expiration time
- `LOG_LEVEL`: Logging level

#### RemovePermission Function
- `APPROVALS_TABLE`: DynamoDB table name
- `SNS_TOPIC_ARN`: SNS topic for notifications
- `AUDIT_BUCKET`: S3 bucket for audit logs (if enabled)
- `LOG_LEVEL`: Logging level

### Whitelist Configuration (Optional)

To exempt certain users/roles from approval requirements:

1. Create an SSM Parameter:

```bash
aws ssm put-parameter \
  --name "/admin-access-approval/whitelist" \
  --value "arn:aws:iam::123456789012:user/break-glass-admin,arn:aws:iam::123456789012:role/EmergencyAccess" \
  --type "String" \
  --description "Whitelisted principals exempt from admin access approval"
```

2. The `ValidatePermission` Lambda will automatically check this whitelist

### Customizing Admin Policy Patterns

Update the `AdminPolicyPatterns` parameter during deployment or modify the stack:

```bash
sam deploy --parameter-overrides AdminPolicyPatterns="AdministratorAccess,PowerUserAccess,SecurityAudit"
```

## 🔄 Workflow Process

### 1. Policy Assignment Event

When an IAM admin policy is assigned:

```bash
aws iam attach-user-policy \
  --user-name john.doe \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

### 2. EventBridge Captures Event

EventBridge rule detects the IAM API call via CloudTrail and triggers the Step Functions workflow.

### 3. Validation

The `ValidatePermission` Lambda:
- Checks if the policy is admin-level
- Checks if the user/role is whitelisted
- Stores the request in DynamoDB
- Returns approval requirement decision

### 4. Email Notification

If approval is required, security team receives an email:

```
🚨 Admin Access Approval Required

User: john.doe
User ARN: arn:aws:iam::123456789012:user/john.doe
Permission: AdministratorAccess
Policy ARN: arn:aws:iam::aws:policy/AdministratorAccess
Assigned At: 2026-05-22 17:28 UTC
Assigned By: admin@company.com

Action Required:
✅ Approve: https://api.company.com/approve?token=<encrypted-token>
❌ Reject: https://api.company.com/reject?token=<encrypted-token>

This request will expire in 24 hours.
Assignment ID: abc-123-def-456
```

### 5. Security Team Action

**Option A: Approve**
- Click the approve link
- Permission remains assigned
- Confirmation email sent

**Option B: Reject**
- Click the reject link
- `RemovePermission` Lambda detaches the policy
- Confirmation email sent

**Option C: No Action (Timeout)**
- After 24 hours, workflow times out
- Permission remains assigned (no automatic removal)
- Timeout notification sent

### 6. Audit Trail

All actions are logged:
- DynamoDB: Complete approval history
- CloudWatch Logs: Lambda execution logs
- S3 (optional): Detailed audit logs for removals

## 🔍 Monitoring & Troubleshooting

### CloudWatch Dashboards

View metrics for:
- Step Functions execution status
- Lambda function errors and duration
- API Gateway request counts
- DynamoDB read/write capacity

### CloudWatch Alarms

Two alarms are automatically created:

1. **StateMachine Failures**
   - Triggers when state machine executions fail
   - Threshold: 1 failure in 5 minutes

2. **Lambda Errors**
   - Triggers when Lambda functions have errors
   - Threshold: 3 errors in 5 minutes

### Viewing Logs

**Step Functions Execution History:**

```bash
aws stepfunctions list-executions \
  --state-machine-arn <StateMachineArn> \
  --max-results 10
```

**Lambda Logs:**

```bash
aws logs tail /aws/lambda/AdminAccessApproval-ValidatePermission --follow
aws logs tail /aws/lambda/AdminAccessApproval-ApprovalCallback --follow
aws logs tail /aws/lambda/AdminAccessApproval-RemovePermission --follow
```

**DynamoDB Query (Recent Approvals):**

```bash
aws dynamodb query \
  --table-name AdminAccessApprovals \
  --index-name StatusIndex \
  --key-condition-expression "#status = :status" \
  --expression-attribute-names '{"#status":"status"}' \
  --expression-attribute-values '{":status":{"S":"pending"}}'
```

### Common Issues

#### Issue: Email notifications not received

**Solution:**
1. Check SNS subscription status:
   ```bash
   aws sns list-subscriptions-by-topic --topic-arn <SNSTopicArn>
   ```
2. Confirm the email subscription (check spam folder)
3. Verify SNS topic permissions

#### Issue: Approval links not working

**Solution:**
1. Check API Gateway deployment:
   ```bash
   aws apigateway get-rest-apis
   ```
2. Verify Lambda function has correct permissions
3. Check CloudWatch Logs for Lambda errors

#### Issue: Permissions not being removed

**Solution:**
1. Check `RemovePermission` Lambda logs
2. Verify Lambda has IAM permissions to detach policies
3. Check if the user/role still exists
4. Review DynamoDB record for error messages

## 📊 Cost Estimation

### Zero Traffic Scenario

| Service | Monthly Cost |
|---------|-------------|
| EventBridge | $0.00 |
| Step Functions | $0.00 |
| Lambda (3 functions) | $0.00 |
| SNS | $0.00 |
| API Gateway | $0.00 |
| DynamoDB (On-Demand) | $0.00 |
| CloudWatch Logs | $0.00 |
| KMS Key | **$1.00** |
| S3 (Lambda code) | **< $0.01** |
| **Total** | **~$1.01/month** |

### Low Traffic (10 admin assignments/month)

| Service | Monthly Cost |
|---------|-------------|
| EventBridge | $0.01 |
| Step Functions | $0.10 |
| Lambda | $0.05 |
| SNS | $0.01 |
| API Gateway | $0.01 |
| DynamoDB | $0.01 |
| CloudWatch Logs | $0.02 |
| KMS | $1.00 |
| **Total** | **~$1.21/month** |

### High Traffic (100 admin assignments/month)

| Service | Monthly Cost |
|---------|-------------|
| EventBridge | $0.10 |
| Step Functions | $1.00 |
| Lambda | $0.50 |
| SNS | $0.10 |
| API Gateway | $0.10 |
| DynamoDB | $0.10 |
| CloudWatch Logs | $0.20 |
| KMS | $1.00 |
| **Total** | **~$3.10/month** |

**Key Takeaway:** Extremely cost-effective serverless solution!

## 🛡️ Security Considerations

### Token Security
- Tokens are encrypted using AWS KMS
- Tokens expire after 24 hours (configurable)
- Tokens are single-use (marked as used in DynamoDB)
- Token validation includes signature verification

### IAM Permissions
- Each Lambda has minimal required permissions (least privilege)
- Separate execution roles for each function
- Step Functions has limited permissions to invoke Lambdas and publish to SNS

### Data Encryption
- DynamoDB: Encryption at rest enabled
- SNS: Messages encrypted with KMS
- S3: Server-side encryption (AES-256)
- API Gateway: HTTPS only

### Audit Trail
- All approval requests logged to DynamoDB
- CloudWatch Logs for all Lambda executions
- Optional S3 audit logs for long-term retention
- CloudTrail captures all API calls

## 🧹 Cleanup

To delete the entire stack:

```bash
sam delete
```

Or using CloudFormation:

```bash
aws cloudformation delete-stack --stack-name admin-access-approval-workflow
```

**Note:** You may need to manually delete:
- S3 bucket (if audit logging was enabled and bucket has objects)
- CloudWatch Log Groups (if retention is set)
- SSM parameters (whitelist configuration)

## 📚 Additional Resources

- [AWS SAM Documentation](https://docs.aws.amazon.com/serverless-application-model/)
- [Step Functions Best Practices](https://docs.aws.amazon.com/step-functions/latest/dg/best-practices.html)
- [EventBridge Event Patterns](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-patterns.html)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)

## 👥 Support

For issues or questions:
1. Check CloudWatch Logs for error details
2. Review the troubleshooting section above
3. Consult AWS documentation
4. Contact your AWS support team

## 📝 License

This project is provided as-is for demonstration and educational purposes.

---

**Built with ❤️ using AWS SAM and Python**