import json
import os
import boto3
from datetime import datetime, timezone
from typing import Dict, Any, List
import logging

# Configure logging
logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

# Initialize AWS clients
iam = boto3.client('iam')
dynamodb = boto3.resource('dynamodb')
sns = boto3.client('sns')
s3 = boto3.client('s3')

# Environment variables
APPROVALS_TABLE = os.environ.get('APPROVALS_TABLE', 'AdminAccessApprovals')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN', '')
AUDIT_BUCKET = os.environ.get('AUDIT_BUCKET', '')


def get_assignment_details(assignment_id: str) -> Dict[str, Any]:
    """
    Retrieve assignment details from DynamoDB.
    
    Args:
        assignment_id: The assignment ID
    
    Returns:
        Dictionary with assignment details
    """
    table = dynamodb.Table(APPROVALS_TABLE)
    
    try:
        response = table.get_item(
            Key={'assignmentId': assignment_id}
        )
        
        if 'Item' not in response:
            raise ValueError(f"Assignment {assignment_id} not found")
        
        return response['Item']
        
    except Exception as e:
        logger.error(f"Error retrieving assignment details: {str(e)}")
        raise


def detach_managed_policy(principal_type: str, principal_name: str, policy_arn: str) -> bool:
    """
    Detach a managed policy from a user, role, or group.
    
    Args:
        principal_type: Type of principal (user, role, group)
        principal_name: Name of the principal
        policy_arn: ARN of the policy to detach
    
    Returns:
        True if successful, False otherwise
    """
    try:
        if principal_type == 'user':
            iam.detach_user_policy(
                UserName=principal_name,
                PolicyArn=policy_arn
            )
            logger.info(f"Detached policy {policy_arn} from user {principal_name}")
            
        elif principal_type == 'role':
            iam.detach_role_policy(
                RoleName=principal_name,
                PolicyArn=policy_arn
            )
            logger.info(f"Detached policy {policy_arn} from role {principal_name}")
            
        elif principal_type == 'group':
            iam.detach_group_policy(
                GroupName=principal_name,
                PolicyArn=policy_arn
            )
            logger.info(f"Detached policy {policy_arn} from group {principal_name}")
            
        else:
            logger.error(f"Unknown principal type: {principal_type}")
            return False
        
        return True
        
    except iam.exceptions.NoSuchEntityException:
        logger.warning(f"Principal {principal_name} or policy {policy_arn} not found (may have been deleted)")
        return True  # Consider this a success since the policy is not attached
        
    except Exception as e:
        logger.error(f"Error detaching managed policy: {str(e)}")
        return False


def delete_inline_policy(principal_type: str, principal_name: str, policy_name: str) -> bool:
    """
    Delete an inline policy from a user, role, or group.
    
    Args:
        principal_type: Type of principal (user, role, group)
        principal_name: Name of the principal
        policy_name: Name of the inline policy to delete
    
    Returns:
        True if successful, False otherwise
    """
    try:
        if principal_type == 'user':
            iam.delete_user_policy(
                UserName=principal_name,
                PolicyName=policy_name
            )
            logger.info(f"Deleted inline policy {policy_name} from user {principal_name}")
            
        elif principal_type == 'role':
            iam.delete_role_policy(
                RoleName=principal_name,
                PolicyName=policy_name
            )
            logger.info(f"Deleted inline policy {policy_name} from role {principal_name}")
            
        elif principal_type == 'group':
            iam.delete_group_policy(
                GroupName=principal_name,
                PolicyName=policy_name
            )
            logger.info(f"Deleted inline policy {policy_name} from group {principal_name}")
            
        else:
            logger.error(f"Unknown principal type: {principal_type}")
            return False
        
        return True
        
    except iam.exceptions.NoSuchEntityException:
        logger.warning(f"Principal {principal_name} or policy {policy_name} not found (may have been deleted)")
        return True  # Consider this a success since the policy doesn't exist
        
    except Exception as e:
        logger.error(f"Error deleting inline policy: {str(e)}")
        return False


def verify_policy_removed(principal_type: str, principal_name: str, policy_identifier: str) -> bool:
    """
    Verify that a policy has been removed from a principal.
    
    Args:
        principal_type: Type of principal (user, role, group)
        principal_name: Name of the principal
        policy_identifier: ARN for managed policies or name for inline policies
    
    Returns:
        True if policy is not attached, False if still attached
    """
    try:
        if principal_type == 'user':
            # Check managed policies
            response = iam.list_attached_user_policies(UserName=principal_name)
            for policy in response.get('AttachedPolicies', []):
                if policy['PolicyArn'] == policy_identifier:
                    return False
            
            # Check inline policies
            response = iam.list_user_policies(UserName=principal_name)
            if policy_identifier in response.get('PolicyNames', []):
                return False
                
        elif principal_type == 'role':
            # Check managed policies
            response = iam.list_attached_role_policies(RoleName=principal_name)
            for policy in response.get('AttachedPolicies', []):
                if policy['PolicyArn'] == policy_identifier:
                    return False
            
            # Check inline policies
            response = iam.list_role_policies(RoleName=principal_name)
            if policy_identifier in response.get('PolicyNames', []):
                return False
        
        return True
        
    except Exception as e:
        logger.error(f"Error verifying policy removal: {str(e)}")
        return False


def log_to_audit_trail(assignment_id: str, details: Dict[str, Any], success: bool) -> None:
    """
    Log the permission removal to S3 audit trail.
    
    Args:
        assignment_id: The assignment ID
        details: Details of the removal operation
        success: Whether the removal was successful
    """
    if not AUDIT_BUCKET:
        logger.warning("Audit bucket not configured, skipping S3 logging")
        return
    
    try:
        timestamp = datetime.now(timezone.utc)
        log_entry = {
            'assignmentId': assignment_id,
            'timestamp': timestamp.isoformat(),
            'action': 'PERMISSION_REMOVED',
            'success': success,
            'details': details
        }
        
        # Create S3 key with date partitioning
        s3_key = f"audit-logs/{timestamp.year}/{timestamp.month:02d}/{timestamp.day:02d}/{assignment_id}.json"
        
        s3.put_object(
            Bucket=AUDIT_BUCKET,
            Key=s3_key,
            Body=json.dumps(log_entry, indent=2),
            ContentType='application/json',
            ServerSideEncryption='AES256'
        )
        
        logger.info(f"Logged removal to S3: {s3_key}")
        
    except Exception as e:
        logger.error(f"Error logging to S3 audit trail: {str(e)}")
        # Don't raise - logging failure shouldn't fail the entire operation


def update_dynamodb_record(assignment_id: str, success: bool, error_message: str = '') -> None:
    """
    Update the DynamoDB record with removal status.
    
    Args:
        assignment_id: The assignment ID
        success: Whether the removal was successful
        error_message: Error message if removal failed
    """
    table = dynamodb.Table(APPROVALS_TABLE)
    timestamp = datetime.now(timezone.utc).isoformat()
    
    try:
        update_expr = 'SET #status = :status, updatedAt = :updated, removalTimestamp = :removal'
        expr_values = {
            ':status': 'removed' if success else 'removal_failed',
            ':updated': timestamp,
            ':removal': timestamp
        }
        
        if error_message:
            update_expr += ', removalError = :error'
            expr_values[':error'] = error_message
        
        table.update_item(
            Key={'assignmentId': assignment_id},
            UpdateExpression=update_expr,
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues=expr_values
        )
        
        logger.info(f"Updated DynamoDB record for assignment {assignment_id}")
        
    except Exception as e:
        logger.error(f"Error updating DynamoDB record: {str(e)}")
        raise


def send_notification(assignment_details: Dict[str, Any], success: bool, error_message: str = '') -> None:
    """
    Send notification about the permission removal.
    
    Args:
        assignment_details: Details of the assignment
        success: Whether the removal was successful
        error_message: Error message if removal failed
    """
    if not SNS_TOPIC_ARN:
        logger.warning("SNS topic not configured, skipping notification")
        return
    
    try:
        if success:
            subject = '✅ Admin Access Removed Successfully'
            message = f"""
Admin Access Removal Confirmation

The following admin access has been successfully removed:

User: {assignment_details.get('userId', 'Unknown')}
User ARN: {assignment_details.get('userArn', 'Unknown')}
Permission: {assignment_details.get('policyName', 'Unknown')}
Policy ARN: {assignment_details.get('policyArn', 'Unknown')}
Assignment ID: {assignment_details.get('assignmentId', 'Unknown')}
Removed At: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
Rejected By: {assignment_details.get('approver', 'Unknown')}

The permission has been successfully detached from the user.
"""
        else:
            subject = '⚠️ Admin Access Removal Failed'
            message = f"""
Admin Access Removal Failure

Failed to remove the following admin access:

User: {assignment_details.get('userId', 'Unknown')}
User ARN: {assignment_details.get('userArn', 'Unknown')}
Permission: {assignment_details.get('policyName', 'Unknown')}
Policy ARN: {assignment_details.get('policyArn', 'Unknown')}
Assignment ID: {assignment_details.get('assignmentId', 'Unknown')}
Attempted At: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}

Error: {error_message}

Please investigate and remove the permission manually if necessary.
"""
        
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=message,
            MessageAttributes={
                'priority': {'DataType': 'String', 'StringValue': 'high' if not success else 'normal'},
                'category': {'DataType': 'String', 'StringValue': 'security-removal'},
                'assignmentId': {'DataType': 'String', 'StringValue': assignment_details.get('assignmentId', '')}
            }
        )
        
        logger.info(f"Sent notification for assignment {assignment_details.get('assignmentId')}")
        
    except Exception as e:
        logger.error(f"Error sending notification: {str(e)}")
        # Don't raise - notification failure shouldn't fail the entire operation


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for removing admin permissions.
    
    Args:
        event: Event containing assignment details from Step Functions
        context: Lambda context object
    
    Returns:
        Dictionary with removal results
    """
    logger.info(f"Received event: {json.dumps(event)}")
    
    try:
        # Extract assignment ID from event
        assignment_id = event.get('assignmentId', '')
        if not assignment_id:
            raise ValueError("Missing assignmentId in event")
        
        # Get assignment details from DynamoDB
        assignment_details = get_assignment_details(assignment_id)
        
        user_arn = assignment_details.get('userArn', '')
        user_type = assignment_details.get('userType', 'user')
        policy_arn = assignment_details.get('policyArn', '')
        policy_name = assignment_details.get('policyName', '')
        
        # Extract principal name from ARN
        principal_name = user_arn.split('/')[-1] if user_arn else ''
        
        if not principal_name or not policy_arn:
            raise ValueError("Missing required fields in assignment details")
        
        logger.info(f"Removing {policy_arn} from {user_type} {principal_name}")
        
        # Determine if this is a managed or inline policy
        is_inline = policy_arn.startswith('inline:')
        
        # Remove the policy
        if is_inline:
            inline_policy_name = policy_arn.replace('inline:', '')
            success = delete_inline_policy(user_type, principal_name, inline_policy_name)
            policy_identifier = inline_policy_name
        else:
            success = detach_managed_policy(user_type, principal_name, policy_arn)
            policy_identifier = policy_arn
        
        error_message = ''
        
        if success:
            # Verify the policy was actually removed
            verified = verify_policy_removed(user_type, principal_name, policy_identifier)
            if not verified:
                success = False
                error_message = 'Policy removal verification failed - policy may still be attached'
                logger.error(error_message)
        else:
            error_message = 'Failed to remove policy'
        
        # Log to audit trail
        audit_details = {
            'principalName': principal_name,
            'principalType': user_type,
            'principalArn': user_arn,
            'policyArn': policy_arn,
            'policyName': policy_name,
            'isInline': is_inline,
            'verificationStatus': 'verified' if success else 'failed'
        }
        log_to_audit_trail(assignment_id, audit_details, success)
        
        # Update DynamoDB record
        update_dynamodb_record(assignment_id, success, error_message)
        
        # Send notification
        send_notification(assignment_details, success, error_message)
        
        # Return result
        return {
            'success': success,
            'assignmentId': assignment_id,
            'principalName': principal_name,
            'policyName': policy_name,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'errorMessage': error_message if not success else ''
        }
        
    except Exception as e:
        logger.error(f"Error in lambda_handler: {str(e)}", exc_info=True)
        
        # Try to update DynamoDB and send notification about the failure
        try:
            if 'assignment_id' in locals():
                update_dynamodb_record(assignment_id, False, str(e))
                if 'assignment_details' in locals():
                    send_notification(assignment_details, False, str(e))
        except Exception as update_error:
            logger.error(f"Error updating failure status: {str(update_error)}")
        
        raise