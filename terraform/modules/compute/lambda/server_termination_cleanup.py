"""
NHP Server Termination Cleanup Lambda

This Lambda function handles ASG lifecycle hooks for NHP Server termination.
When an NHP Server is terminating, this function:
1. Queries the server-ac-index table for all ACs assigned to this server
2. Updates each AC assignment to remove this server from assigned_servers
3. Deletes AC assignments that have no remaining servers
4. Deletes the server-ac-index entries for this server
5. Completes the lifecycle hook to allow termination to proceed

This ensures DynamoDB assignments are cleaned up BEFORE the instance terminates,
providing immediate cleanup instead of waiting for Console health monitor.
"""

import json
import logging
import os
import boto3
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment variables
AC_ASSIGNMENTS_TABLE = os.environ.get('AC_ASSIGNMENTS_TABLE')
SERVER_AC_INDEX_TABLE = os.environ.get('SERVER_AC_INDEX_TABLE')

# Initialize clients (AWS_REGION is always set in Lambda environment)
dynamodb = boto3.resource('dynamodb')
autoscaling = boto3.client('autoscaling')


def handler(event, context):
    """
    Lambda handler for ASG lifecycle hook events.

    Event structure (from EventBridge/SNS):
    {
        "detail": {
            "LifecycleHookName": "nhp-server-termination-hook",
            "AutoScalingGroupName": "nhp-sandbox-server",
            "LifecycleActionToken": "...",
            "EC2InstanceId": "i-1234567890abcdef0",
            "LifecycleTransition": "autoscaling:EC2_INSTANCE_TERMINATING"
        }
    }
    """
    logger.info(f"Received event: {json.dumps(event)}")

    # Extract lifecycle hook details
    detail = event.get('detail', {})
    instance_id = detail.get('EC2InstanceId')
    lifecycle_hook_name = detail.get('LifecycleHookName')
    asg_name = detail.get('AutoScalingGroupName')
    lifecycle_token = detail.get('LifecycleActionToken')

    if not all([instance_id, lifecycle_hook_name, asg_name, lifecycle_token]):
        logger.error(f"Missing required fields in event: instance_id={instance_id}, "
                     f"hook={lifecycle_hook_name}, asg={asg_name}, token={bool(lifecycle_token)}")
        return {'statusCode': 400, 'body': 'Missing required fields'}

    logger.info(f"Processing termination for instance: {instance_id}")

    try:
        # Step 1: Get all ACs assigned to this server
        ac_ids = get_acs_for_server(instance_id)
        logger.info(f"Found {len(ac_ids)} ACs assigned to server {instance_id}")

        # Step 2: Update each AC assignment to remove this server
        updated_count = 0
        deleted_count = 0
        for ac_id in ac_ids:
            result = update_ac_assignment(ac_id, instance_id)
            if result == 'updated':
                updated_count += 1
            elif result == 'deleted':
                deleted_count += 1

        logger.info(f"Updated {updated_count} assignments, deleted {deleted_count} assignments")

        # Step 3: Delete server-ac-index entries for this server
        delete_server_index_entries(instance_id, ac_ids)

        # Step 4: Complete the lifecycle hook
        complete_lifecycle_action(asg_name, lifecycle_hook_name, lifecycle_token, instance_id)

        return {
            'statusCode': 200,
            'body': json.dumps({
                'instance_id': instance_id,
                'acs_processed': len(ac_ids),
                'updated': updated_count,
                'deleted': deleted_count
            })
        }

    except Exception as e:
        logger.error(f"Error processing termination: {str(e)}", exc_info=True)

        # Complete the lifecycle hook to avoid blocking termination, even if cleanup failed.
        # The Console health monitor will handle backup cleanup.
        try:
            complete_lifecycle_action(asg_name, lifecycle_hook_name, lifecycle_token, instance_id)
            logger.info(f"Lifecycle completed despite cleanup error for instance {instance_id}")
        except Exception as complete_error:
            logger.error(f"Failed to complete lifecycle action: {str(complete_error)}")

        # Re-raise to ensure CloudWatch Lambda Errors metric captures the failure.
        # This enables proper alerting even though termination will proceed.
        # Operators should check logs to see lifecycle_completed status.
        raise


def get_acs_for_server(server_id: str) -> list:
    """
    Query server-ac-index table to get all AC IDs assigned to this server.
    """
    if not SERVER_AC_INDEX_TABLE:
        logger.warning("SERVER_AC_INDEX_TABLE not configured, skipping")
        return []

    table = dynamodb.Table(SERVER_AC_INDEX_TABLE)
    ac_ids = []

    try:
        response = table.query(
            KeyConditionExpression='server_id = :sid',
            ExpressionAttributeValues={':sid': server_id}
        )

        for item in response.get('Items', []):
            if 'ac_id' in item:
                ac_ids.append(item['ac_id'])

        # Handle pagination
        while 'LastEvaluatedKey' in response:
            response = table.query(
                KeyConditionExpression='server_id = :sid',
                ExpressionAttributeValues={':sid': server_id},
                ExclusiveStartKey=response['LastEvaluatedKey']
            )
            for item in response.get('Items', []):
                if 'ac_id' in item:
                    ac_ids.append(item['ac_id'])

    except ClientError as e:
        logger.error(f"Error querying server-ac-index: {e.response['Error']['Message']}")
        raise

    return ac_ids


def update_ac_assignment(ac_id: str, server_id: str) -> str:
    """
    Update AC assignment to remove the terminated server from assigned_servers.
    If no servers remain, delete the assignment.

    Returns: 'updated', 'deleted', or 'skipped'
    """
    if not AC_ASSIGNMENTS_TABLE:
        logger.warning("AC_ASSIGNMENTS_TABLE not configured, skipping")
        return 'skipped'

    table = dynamodb.Table(AC_ASSIGNMENTS_TABLE)

    try:
        # Get current assignment
        response = table.get_item(Key={'ac_id': ac_id})
        item = response.get('Item')

        if not item:
            logger.info(f"Assignment for AC {ac_id} not found (may have been deleted)")
            return 'skipped'

        assigned_servers = item.get('assigned_servers', [])

        # Filter out the terminated server
        # Server can be identified by ID, IP, or InternalIP
        updated_servers = [
            srv for srv in assigned_servers
            if srv.get('id') != server_id and
               srv.get('ID') != server_id and
               srv.get('instance_id') != server_id
        ]

        if len(updated_servers) == len(assigned_servers):
            # Server wasn't in this assignment (index might be stale)
            logger.info(f"Server {server_id} not found in assignment for AC {ac_id}")
            return 'skipped'

        if len(updated_servers) == 0:
            # No servers left - delete the assignment
            logger.info(f"Deleting assignment for AC {ac_id} (no servers remaining)")
            table.delete_item(Key={'ac_id': ac_id})
            return 'deleted'
        else:
            # Update with remaining servers
            logger.info(f"Updating assignment for AC {ac_id}: {len(assigned_servers)} -> {len(updated_servers)} servers")
            table.update_item(
                Key={'ac_id': ac_id},
                UpdateExpression='SET assigned_servers = :servers',
                ExpressionAttributeValues={':servers': updated_servers}
            )
            return 'updated'

    except ClientError as e:
        logger.error(f"Error updating assignment for AC {ac_id}: {e.response['Error']['Message']}")
        raise


def delete_server_index_entries(server_id: str, ac_ids: list):
    """
    Delete all server-ac-index entries for this server.
    """
    if not SERVER_AC_INDEX_TABLE or not ac_ids:
        return

    table = dynamodb.Table(SERVER_AC_INDEX_TABLE)

    # Use batch writer for efficiency.
    # Note: batch_writer buffers operations and sends on context exit,
    # so we wrap the entire block in try/except to catch batch errors.
    try:
        with table.batch_writer() as batch:
            for ac_id in ac_ids:
                batch.delete_item(Key={'server_id': server_id, 'ac_id': ac_id})
        logger.info(f"Deleted {len(ac_ids)} server-ac-index entries for server {server_id}")
    except ClientError as e:
        logger.warning(f"Batch delete failed for server {server_id}: {e.response['Error']['Message']}")


def complete_lifecycle_action(asg_name: str, hook_name: str, token: str, instance_id: str):
    """
    Complete the ASG lifecycle action to allow termination to proceed.
    """
    logger.info(f"Completing lifecycle action for instance {instance_id}")

    try:
        autoscaling.complete_lifecycle_action(
            LifecycleHookName=hook_name,
            AutoScalingGroupName=asg_name,
            LifecycleActionToken=token,
            LifecycleActionResult='CONTINUE',
            InstanceId=instance_id
        )
        logger.info(f"Lifecycle action completed successfully for instance {instance_id}")
    except ClientError as e:
        logger.error(f"Failed to complete lifecycle action: {e.response['Error']['Message']}")
        raise
