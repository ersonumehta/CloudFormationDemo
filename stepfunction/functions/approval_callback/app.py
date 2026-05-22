import json
import os
import boto3
import base64
import hmac
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any
import logging

# Configure logging
logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

# Initialize AWS clients
dynamodb = boto3.resource('dynamodb')
stepfunctions = boto3.client('stepfunctions')

# Environment variables
APPROVALS_TABLE = os.environ.get('APPROVALS_TABLE', 'AdminAccessApprovals')
APP_SECRET = os.environ.get('APP_SECRET', '')
TOKEN_EXPIRY_HOURS = int(os.environ.get('TOKEN_EXPIRY_HOURS', '24'))


def verify_signed_token(token: str) -> Dict[str, Any]:
    """
    Verify and decode HMAC-signed token.
    Token format: base64url(payload) + '.' + base64url(signature)
    Payload is JSON containing assignmentId, taskToken, expiresAt, action
    """
    if not APP_SECRET:
        raise ValueError('Server misconfiguration: APP_SECRET not set')

    try:
        parts = token.split('.')
        if len(parts) != 2:
            raise ValueError('Invalid token format')

        payload_b64, sig_b64 = parts
        # restore padding
        payload_bytes = base64.urlsafe_b64decode(payload_b64 + '==')
        sig_bytes = base64.urlsafe_b64decode(sig_b64 + '==')

        # verify signature
        expected = hmac.new(APP_SECRET.encode('utf-8'), payload_bytes, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, sig_bytes):
            raise ValueError('Invalid token signature')

        token_data = json.loads(payload_bytes.decode('utf-8'))

        # Validate token structure
        required_fields = ['assignmentId', 'taskToken', 'expiresAt', 'action']
        for field in required_fields:
            if field not in token_data:
                raise ValueError(f"Missing required field: {field}")

        # Check expiration
        expires_at = datetime.fromisoformat(token_data['expiresAt'].replace('Z', '+00:00'))
        if datetime.now(timezone.utc) > expires_at:
            raise ValueError('Token has expired')

        logger.info(f"Successfully verified token for assignment {token_data['assignmentId']}")
        return token_data

    except Exception as e:
        logger.error(f"Error verifying token: {str(e)}")
        raise ValueError(f"Invalid or expired token: {str(e)}")


def check_token_usage(assignment_id: str) -> bool:
    """
    Check if the token has already been used.
    
    Args:
        assignment_id: The assignment ID from the token
    
    Returns:
        True if token has been used, False otherwise
    """
    table = dynamodb.Table(APPROVALS_TABLE)
    
    try:
        response = table.get_item(
            Key={'assignmentId': assignment_id}
        )
        
        if 'Item' in response:
            item = response['Item']
            if item.get('tokenUsed', False):
                logger.warning(f"Token for assignment {assignment_id} has already been used")
                return True
            if item.get('status') != 'pending':
                logger.warning(f"Assignment {assignment_id} is not in pending status: {item.get('status')}")
                return True
        
        return False
        
    except Exception as e:
        logger.error(f"Error checking token usage: {str(e)}")
        raise


def mark_token_used(assignment_id: str, action: str, approver: str = 'Unknown') -> None:
    """
    Mark the token as used in DynamoDB.
    
    Args:
        assignment_id: The assignment ID
        action: The action taken (approve/reject)
        approver: The person who approved/rejected
    """
    table = dynamodb.Table(APPROVALS_TABLE)
    timestamp = datetime.now(timezone.utc).isoformat()
    
    try:
        table.update_item(
            Key={'assignmentId': assignment_id},
            UpdateExpression='SET tokenUsed = :used, #status = :status, approver = :approver, '
                           'approvalTimestamp = :timestamp, updatedAt = :updated',
            ExpressionAttributeNames={
                '#status': 'status'
            },
            ExpressionAttributeValues={
                ':used': True,
                ':status': 'approved' if action == 'approve' else 'rejected',
                ':approver': approver,
                ':timestamp': timestamp,
                ':updated': timestamp
            }
        )
        logger.info(f"Marked token as used for assignment {assignment_id} with action {action}")
        
    except Exception as e:
        logger.error(f"Error marking token as used: {str(e)}")
        raise


def send_task_callback(task_token: str, action: str, assignment_id: str) -> None:
    """
    Send success or failure callback to Step Functions.
    
    Args:
        task_token: The Step Functions task token
        action: The action taken (approve/reject)
        assignment_id: The assignment ID
    """
    try:
        timestamp = datetime.now(timezone.utc).isoformat()
        if action == 'approve':
            output = {
                'decision': action,
                'assignmentId': assignment_id,
                'timestamp': timestamp
            }
            stepfunctions.send_task_success(
                taskToken=task_token,
                output=json.dumps(output)
            )
            logger.info(f"Sent task success to Step Functions for assignment {assignment_id} with decision {action}")

        elif action == 'reject':
            # For rejection, send a task failure so the state machine can handle the rejection path
            stepfunctions.send_task_failure(
                taskToken=task_token,
                error='RejectedBySecurity',
                cause=json.dumps({
                    'decision': action,
                    'assignmentId': assignment_id,
                    'timestamp': timestamp
                })
            )
            logger.info(f"Sent task failure to Step Functions for assignment {assignment_id} with decision {action}")

        else:
            # Fallback to sending success with decision payload
            output = {
                'decision': action,
                'assignmentId': assignment_id,
                'timestamp': timestamp
            }
            stepfunctions.send_task_success(
                taskToken=task_token,
                output=json.dumps(output)
            )
            logger.info(f"Sent task success (fallback) to Step Functions for assignment {assignment_id} with decision {action}")

    except Exception as e:
        logger.error(f"Error sending task callback: {str(e)}")
        # Try to send task failure if we failed sending success
        try:
            stepfunctions.send_task_failure(
                taskToken=task_token,
                error='CallbackError',
                cause=str(e)
            )
        except Exception as fail_error:
            logger.error(f"Error sending task failure: {str(fail_error)}")
        raise


def generate_html_response(success: bool, action: str, message: str) -> Dict[str, Any]:
    """
    Generate an HTML response for the user.
    
    Args:
        success: Whether the operation was successful
        action: The action taken (approve/reject)
        message: The message to display
    
    Returns:
        API Gateway response object
    """
    if success:
        if action == 'approve':
            title = '✅ Access Approved'
            color = '#28a745'
            icon = '✅'
        else:
            title = '❌ Access Rejected'
            color = '#dc3545'
            icon = '❌'
    else:
        title = '⚠️ Error'
        color = '#ffc107'
        icon = '⚠️'
    
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{title}</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                margin: 0;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            }}
            .container {{
                background: white;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                text-align: center;
                max-width: 500px;
            }}
            .icon {{
                font-size: 72px;
                margin-bottom: 20px;
            }}
            h1 {{
                color: {color};
                margin: 0 0 20px 0;
                font-size: 28px;
            }}
            p {{
                color: #666;
                font-size: 16px;
                line-height: 1.6;
                margin: 0;
            }}
            .timestamp {{
                margin-top: 20px;
                padding-top: 20px;
                border-top: 1px solid #eee;
                color: #999;
                font-size: 14px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="icon">{icon}</div>
            <h1>{title}</h1>
            <p>{message}</p>
            <div class="timestamp">
                {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
            </div>
        </div>
    </body>
    </html>
    """
    
    return {
        'statusCode': 200 if success else 400,
        'headers': {
            'Content-Type': 'text/html',
            'Cache-Control': 'no-cache, no-store, must-revalidate'
        },
        'body': html
    }


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for processing approval/rejection callbacks.
    
    Args:
        event: API Gateway event containing the encrypted token
        context: Lambda context object
    
    Returns:
        API Gateway response with HTML page
    """
    logger.info(f"Received event: {json.dumps(event)}")
    
    try:
        # Extract query parameters
        query_params = event.get('queryStringParameters', {})
        if not query_params or 'token' not in query_params:
            return generate_html_response(
                False, 'error',
                'Invalid request: Missing token parameter'
            )
        
        encrypted_token = query_params['token']
        
        # Determine action from path
        path = event.get('path', '').lower()
        if '/approve' in path:
            action = 'approve'
        elif '/reject' in path:
            action = 'reject'
        else:
            return generate_html_response(
                False, 'error',
                'Invalid request: Unknown action'
            )
        
        # Verify and validate token (HMAC signed)
        try:
            token_data = verify_signed_token(encrypted_token)
        except ValueError as e:
            return generate_html_response(
                False, 'error',
                f'Invalid or expired token: {str(e)}'
            )
        
        assignment_id = token_data['assignmentId']
        task_token = token_data['taskToken']
        token_action = token_data['action']
        
        # Verify action matches token
        if action != token_action:
            return generate_html_response(
                False, 'error',
                f'Action mismatch: Token is for {token_action}, but {action} was requested'
            )
        
        # Check if token has already been used
        if check_token_usage(assignment_id):
            return generate_html_response(
                False, 'error',
                'This approval link has already been used or the request is no longer pending'
            )
        
        # Get requester info (if available from request context)
        requester = event.get('requestContext', {}).get('identity', {}).get('userArn', 'Unknown')
        
        # Mark token as used
        mark_token_used(assignment_id, action, requester)
        
        # Send callback to Step Functions
        send_task_callback(task_token, action, assignment_id)
        
        # Generate success response
        if action == 'approve':
            message = 'The admin access has been approved successfully. No further action is required.'
        else:
            message = 'The admin access has been rejected. The permission will be removed automatically.'
        
        return generate_html_response(True, action, message)
        
    except Exception as e:
        logger.error(f"Error in lambda_handler: {str(e)}", exc_info=True)
        return generate_html_response(
            False, 'error',
            f'An error occurred while processing your request: {str(e)}'
        )