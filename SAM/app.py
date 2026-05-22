import os
import json
import boto3

# Initialize the DynamoDB client outside the handler to reuse connection warm-starts
dynamodb = boto3.resource('dynamodb')
TABLE_NAME = os.environ.get('TABLE_NAME', 'UserTable')
table = dynamodb.Table(TABLE_NAME)

# Default partition key ID used when a specific id is not provided
RECORD_ID = "global_user"

def lambda_handler(event, context):
    http_method = event.get('httpMethod')
    path = event.get('path', '/')

    # 0. HANDLE THE ROOT PATH
    if path == '/' or path == '/Prod':
        return create_response(404, {
            "error": "No route exists for this",
            "message": "Not Found",
            "available_endpoints": [
                "POST /name - Set a name (body: {\"id\"?: \"...\", \"name\": \"...\"})",
                "GET /name/{id} - Get a name by id"
            ]
        })

    # 1. HANDLE THE GET REQUEST
    if http_method == 'GET':
        try:
            # Read id from pathParameters (e.g. /name/{id}) if provided, otherwise use default RECORD_ID
            path_params = event.get('pathParameters') or {}
            record_id = path_params.get('id', RECORD_ID)

            response = table.get_item(Key={'id': record_id})
            if 'Item' in response:
                user_name = response['Item'].get('name')
                return create_response(200, { 'id': record_id, 'name': user_name })
            else:
                return create_response(404, f"No name set for id '{record_id}'")
        except Exception as e:
            return create_response(500, f"Error reading database: {str(e)}")

    # 2. HANDLE THE POST REQUEST
    elif http_method == 'POST':
        try:
            # Parse the incoming JSON payload (e.g., {"id": "some-id", "name": "Sonu"} or just {"name": "Sonu"})
            body = json.loads(event.get('body', '{}'))
            user_name = body.get('name')
            record_id = body.get('id', RECORD_ID)

            if not user_name:
                return create_response(400, "Missing 'name' field in JSON payload")

            # Save the name to DynamoDB under the provided id (or default)
            table.put_item(Item={'id': record_id, 'name': user_name})
            return create_response(200, { 'id': record_id, 'name': user_name, 'message': f"Successfully set name to {user_name}" })
        except Exception as e:
            return create_response(500, f"Error writing to database: {str(e)}")

    # Handle unsupported HTTP methods
    return create_response(405, "Method Not Allowed")

def create_response(status_code, message_body):
    """Helper utility to format standard API Gateway responses"""
    # If the caller passed a dict/serializable object, return it as the body directly.
    if isinstance(message_body, (dict, list)):
        body_payload = message_body
    else:
        body_payload = {"message": message_body}

    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*" # Enables CORS
        },
        "body": json.dumps(body_payload)
    }
