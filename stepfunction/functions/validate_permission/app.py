import json
import os
import boto3
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List
import logging

# Configure logging
logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

# Initialize AWS clients
dynamodb = boto3.resource('dynamodb')
iam = boto3.client('iam')
ssm = boto3.client('ssm')

# Environment variables
APPROVALS_TABLE = os.environ.get('APPROVALS_TABLE', 'AdminAccessApprovals')
ADMIN_POLICY_PATTERNS = os.environ.get('ADMIN_POLICY_PATTERNS', 'AdministratorAccess,PowerUserAccess,IAMFullAccess').split(',')


def is_admin_policy(policy_arn: str, policy_name: str) -> bool:
    """
    Determine if a policy is considered an admin-level policy.
    
    Args:
        policy_arn: The ARN of the policy
        policy_name: The name of the policy
    
    Returns:
        True if the policy is admin-level, False otherwise
    """
    # Check against configured patterns
    for pattern in ADMIN_POLICY_PATTERNS:
        pattern = pattern.strip()
        if pattern.lower() in policy_name.lower():
            logger.info(f"Policy {policy_name} matches admin pattern {pattern}")
            return True
    
    # Check for common admin policy ARNs
    admin_arns = [
        'arn:aws:iam::aws:policy/AdministratorAccess',
        'arn:aws:iam::aws:policy/PowerUserAccess',
        'arn:aws:iam::aws:policy/IAMFullAccess'
    ]
    
    if policy_arn in admin_arns:
        logger.info(f"Policy ARN {policy_arn} is a known admin policy")
        return True
    
    return False


def get_whitelist() -> List[str]:
    """
    Retrieve the whitelist of principals that are exempt from approval.
    
    Returns:
        List of whitelisted principal ARNs
    """
    try:
        # Try to get from SSM Parameter Store
        response = ssm.get_parameter(
            Name='/admin-access-approval/whitelist',
            WithDecryption=False
        )
        whitelist = response['Parameter']['Value'].split(',')
        logger.info(f"Retrieved whitelist from SSM: {len(whitelist)} entries")
        return [item.strip() for item in whitelist]
    except ssm.exceptions.ParameterNotFound:
        logger.warning("Whitelist parameter not found in SSM, using empty whitelist")
        return []
    except Exception as e:
        logger.error(f"Error retrieving whitelist: {str(e)}")
        return []


def is_whitelisted(principal_arn: str, whitelist: List[str]) -> bool:
    """
    Check if a principal is in the whitelist.
    
    Args:
        principal_arn: The ARN of the principal (user/role)
        whitelist: List of whitelisted ARNs
    
    Returns:
        True if whitelisted, False otherwise
    """
    for whitelisted_arn in whitelist:
        if whitelisted_arn in principal_arn or principal_arn == whitelisted_arn:
            logger.info(f"Principal {principal_arn} is whitelisted")
            return True
    return False


def enrich_user_details(principal_arn: str, principal_type: str) -> Dict[str, Any]:
    """
    Enrich user/role details from IAM.
    
    Args:
        principal_arn: The ARN of the principal
        principal_type: Type of principal (user, role, group)
    
    Returns:
        Dictionary with enriched details
    """
    details = {
        'arn': principal_arn,
        'type': principal_type,
        'name': principal_arn.split('/')[-1]
    }
    
    try:
        if principal_type == 'user':
            user_name = principal_arn.split('/')[-1]
            response = iam.get_user(UserName=user_name)
            user = response['User']
            details['userId'] = user.get('UserId', '')
            details['createDate'] = user.get('CreateDate', '').isoformat() if user.get('CreateDate') else ''
            
            # Try to get user tags for additional info
            try:
                tags_response = iam.list_user_tags(UserName=user_name)
                details['tags'] = {tag['Key']: tag['Value'] for tag in tags_response.get('Tags', [])}
            except Exception as e:
                logger.warning(f"Could not retrieve user tags: {str(e)}")
                details['tags'] = {}
                
        elif principal_type == 'role':
            role_name = principal_arn.split('/')[-1]
            response = iam.get_role(RoleName=role_name)
            role = response['Role']
            details['roleId'] = role.get('RoleId', '')
            details['createDate'] = role.get('CreateDate', '').isoformat() if role.get('CreateDate') else ''
            
    except Exception as e:
        logger.error(f"Error enriching {principal_type} details: {str(e)}")
    
    return details


def store_approval_request(assignment_id: str, event_details: Dict[str, Any], 
                          user_details: Dict[str, Any], permission_details: Dict[str, Any]) -> None:
    """
    Store the approval request in DynamoDB.
    
    Args:
        assignment_id: Unique ID for this assignment
        event_details: Details from the EventBridge event
        user_details: Enriched user details
        permission_details: Details about the permission
    """
    table = dynamodb.Table(APPROVALS_TABLE)
    
    timestamp = datetime.now(timezone.utc).isoformat()
    
    item = {
        'assignmentId': assignment_id,
        'timestamp': timestamp,
        'userId': user_details.get('name', ''),
        'userArn': user_details.get('arn', ''),
        'userType': user_details.get('type', ''),
        'policyArn': permission_details.get('arn', ''),
        'policyName': permission_details.get('name', ''),
        'assignedBy': event_details.get('principal', ''),
        'status': 'pending',
        'tokenUsed': False,
        'eventTime': event_details.get('time', timestamp),
        'requestParameters': json.dumps(event_details.get('requestParameters', {})),
        'createdAt': timestamp,
        'updatedAt': timestamp,
        # TTL: 90 days from now (in Unix timestamp)
        'ttl': int((datetime.now(timezone.utc).timestamp() + (90 * 24 * 60 * 60)))
    }
    
    try:
        table.put_item(Item=item)
        logger.info(f"Stored approval request with ID: {assignment_id}")
    except Exception as e:
        logger.error(f"Error storing approval request: {str(e)}")
        raise


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for validating admin permission assignments.
    
    Args:
        event: EventBridge event containing IAM policy assignment details
        context: Lambda context object
    
    Returns:
        Dictionary with validation results and decision
    """
    logger.info(f"Received event: {json.dumps(event)}")
    
    try:
        # Extract event details
        detail = event.get('detail', {})
        event_name = detail.get('eventName', '')
        request_parameters = detail.get('requestParameters', {})
        user_identity = detail.get('userIdentity', {})
        event_time = event.get('time', datetime.now(timezone.utc).isoformat())
        
        # Determine the principal (user/role) and policy
        principal_arn = ''
        principal_type = ''
        policy_arn = ''
        policy_name = ''
        
        # Handle different IAM events
        if event_name == 'AttachUserPolicy':
            principal_arn = request_parameters.get('userArn', '')
            if not principal_arn:
                user_name = request_parameters.get('userName', '')
                account_id = event.get('account', '')
                principal_arn = f"arn:aws:iam::{account_id}:user/{user_name}"
            principal_type = 'user'
            policy_arn = request_parameters.get('policyArn', '')
            
        elif event_name == 'AttachRolePolicy':
            role_name = request_parameters.get('roleName', '')
            account_id = event.get('account', '')
            principal_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
            principal_type = 'role'
            policy_arn = request_parameters.get('policyArn', '')
            
        elif event_name == 'AttachGroupPolicy':
            group_name = request_parameters.get('groupName', '')
            account_id = event.get('account', '')
            principal_arn = f"arn:aws:iam::{account_id}:group/{group_name}"
            principal_type = 'group'
            policy_arn = request_parameters.get('policyArn', '')
            
        elif event_name == 'PutUserPolicy':
            user_name = request_parameters.get('userName', '')
            account_id = event.get('account', '')
            principal_arn = f"arn:aws:iam::{account_id}:user/{user_name}"
            principal_type = 'user'
            policy_name = request_parameters.get('policyName', '')
            policy_arn = f"inline:{policy_name}"
        
        # Extract policy name from ARN if not already set
        if not policy_name and policy_arn:
            policy_name = policy_arn.split('/')[-1]
        
        logger.info(f"Processing {event_name}: {principal_arn} <- {policy_arn}")
        
        # Check if this is an admin-level policy
        if not is_admin_policy(policy_arn, policy_name):
            logger.info(f"Policy {policy_name} is not an admin-level policy, no approval needed")
            return {
                'requiresApproval': False,
                'reason': 'Not an admin-level policy',
                'policyName': policy_name,
                'policyArn': policy_arn
            }
        
        # Check whitelist
        whitelist = get_whitelist()
        if is_whitelisted(principal_arn, whitelist):
            logger.info(f"Principal {principal_arn} is whitelisted, no approval needed")
            return {
                'requiresApproval': False,
                'reason': 'Principal is whitelisted',
                'principalArn': principal_arn,
                'policyName': policy_name
            }
        
        # Generate unique assignment ID
        assignment_id = str(uuid.uuid4())
        
        # Enrich user details
        user_details = enrich_user_details(principal_arn, principal_type)
        
        # Prepare permission details
        permission_details = {
            'arn': policy_arn,
            'name': policy_name
        }
        
        # Prepare event details
        event_details = {
            'eventName': event_name,
            'time': event_time,
            'principal': user_identity.get('arn', user_identity.get('principalId', 'Unknown')),
            'requestParameters': request_parameters
        }
        
        # Store approval request in DynamoDB
        store_approval_request(assignment_id, event_details, user_details, permission_details)
        
        # Return decision requiring approval
        return {
            'requiresApproval': True,
            'assignmentId': assignment_id,
            'userDetails': user_details,
            'permissionDetails': permission_details,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'eventName': event_name,
            'assignedBy': event_details['principal']
        }
        
    except Exception as e:
        logger.error(f"Error in lambda_handler: {str(e)}", exc_info=True)
        raise