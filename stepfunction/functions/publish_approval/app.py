import os
import json
import boto3
import base64
import hmac
import hashlib
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any

# Configure logging
logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

# AWS clients
dynamodb = boto3.resource('dynamodb')
sns = boto3.client('sns')

# Environment
APPROVALS_TABLE = os.environ.get('APPROVALS_TABLE', 'AdminAccessApprovals')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN', '')
API_BASE_URL = os.environ.get('API_BASE_URL', '')  # e.g. https://<api>.execute-api.<region>.amazonaws.com/prod
TOKEN_EXPIRY_HOURS = int(os.environ.get('TOKEN_EXPIRY_HOURS', '24'))
APP_SECRET = os.environ.get('APP_SECRET', '')


def sign_token(payload: Dict[str, Any]) -> str:
    """Sign payload with HMAC-SHA256 and return token payload.signature (both urlsafe base64)."""
    if not APP_SECRET:
        raise ValueError('Server misconfiguration: APP_SECRET not set')

    plaintext = json.dumps(payload).encode('utf-8')
    sig = hmac.new(APP_SECRET.encode('utf-8'), plaintext, hashlib.sha256).digest()
    payload_b64 = base64.urlsafe_b64encode(plaintext).decode('utf-8').rstrip('=')
    sig_b64 = base64.urlsafe_b64encode(sig).decode('utf-8').rstrip('=')
    return f"{payload_b64}.{sig_b64}"


def store_token_metadata(assignment_id: str, token: str, expires_at: str) -> None:
    table = dynamodb.Table(APPROVALS_TABLE)
    try:
        table.update_item(
            Key={'assignmentId': assignment_id},
            UpdateExpression='SET approvalToken = :t, tokenExpiry = :e, tokenCreatedAt = :c, tokenUsed = :u',
            ExpressionAttributeValues={
                ':t': token,
                ':e': expires_at,
                ':c': datetime.now(timezone.utc).isoformat(),
                ':u': False
            }
        )
        logger.info(f'Stored token metadata for assignment {assignment_id}')
    except Exception as e:
        logger.error(f'Error storing token metadata: {str(e)}')
        raise


def publish_notification(assignment_id: str, user_details: Dict[str, Any], permission_details: Dict[str, Any], approve_url: str, reject_url: str) -> None:
    if not SNS_TOPIC_ARN:
        logger.warning('SNS_TOPIC_ARN not configured, skipping publish')
        return

    subject = '🚨 Admin Access Approval Required'
    body = f"""
Admin Access Approval Required

User: {user_details.get('name', '')}
User ARN: {user_details.get('arn', '')}
Permission: {permission_details.get('name', '')}
Policy ARN: {permission_details.get('arn', '')}
Assignment ID: {assignment_id}

Approve: {approve_url}
Reject: {reject_url}

This link will expire at {datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRY_HOURS)} UTC
"""

    # Simple HTML with buttons
    html = f"""
<html>
  <body>
    <p>Admin Access Approval Required</p>
    <p><strong>User:</strong> {user_details.get('name', '')} (<code>{user_details.get('arn','')}</code>)</p>
    <p><strong>Permission:</strong> {permission_details.get('name', '')}</p>
    <p>
      <a href="{approve_url}" style="padding:12px 18px;background:#28a745;color:#fff;border-radius:6px;text-decoration:none;">Approve</a>
      &nbsp;
      <a href="{reject_url}" style="padding:12px 18px;background:#dc3545;color:#fff;border-radius:6px;text-decoration:none;">Reject</a>
    </p>
    <p>Assignment ID: {assignment_id}</p>
  </body>
</html>
"""

    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=body,
            MessageStructure='string',
            # include assignmentId as a message attribute for filtering/processing
            MessageAttributes={
                'assignmentId': {'DataType': 'String', 'StringValue': assignment_id},
                'category': {'DataType': 'String', 'StringValue': 'security-approval'}
            }
        )
        logger.info(f'Published approval notification for {assignment_id} to SNS')
    except Exception as e:
        logger.error(f'Error publishing SNS notification: {str(e)}')
        raise


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Entry point: expects payload with assignmentId, userDetails, permissionDetails, taskToken and apiGatewayUrl"""
    logger.info(f'Received event: {json.dumps(event)}')
    try:
        assignment_id = event.get('assignmentId') or event.get('notificationData', {}).get('assignmentId')
        user_details = event.get('userDetails') or event.get('notificationData', {}).get('userDetails', {})
        permission_details = event.get('permissionDetails') or event.get('notificationData', {}).get('permissionDetails', {})
        task_token = event.get('taskToken') or event.get('notificationData', {}).get('taskToken')
        api_url = event.get('apiGatewayUrl') or API_BASE_URL

        if not assignment_id or not task_token:
            raise ValueError('Missing assignmentId or taskToken')

        # Build token payloads for approve and reject
        expiry = datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRY_HOURS)
        expires_at = expiry.isoformat()

        approve_payload = {
            'assignmentId': assignment_id,
            'taskToken': task_token,
            'action': 'approve',
            'expiresAt': expires_at
        }
        reject_payload = {
            'assignmentId': assignment_id,
            'taskToken': task_token,
            'action': 'reject',
            'expiresAt': expires_at
        }

        approve_token = sign_token(approve_payload)
        reject_token = sign_token(reject_payload)

        # Store token metadata (store the encrypted token as well for simple lookup)
        store_token_metadata(assignment_id, approve_token + '::' + reject_token, expires_at)

        # Build URLs
        approve_url = f"{api_url}/approve?token={approve_token}"
        reject_url = f"{api_url}/reject?token={reject_token}"

        # Publish notification
        publish_notification(assignment_id, user_details, permission_details, approve_url, reject_url)

        return {
            'status': 'published',
            'assignmentId': assignment_id,
            'approveUrl': approve_url,
            'rejectUrl': reject_url,
            'expiresAt': expires_at
        }

    except Exception as e:
        logger.error(f'Error in publish_approval: {str(e)}', exc_info=True)
        raise

