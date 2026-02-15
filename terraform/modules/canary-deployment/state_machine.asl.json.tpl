{
  "Comment": "Canary deployment orchestrator using ASG instance refresh with checkpoint-based health checks",
  "StartAt": "PrepareDeployment",
  "TimeoutSeconds": 3600,
  "States": {
    "PrepareDeployment": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "Parameters": {
        "FunctionName": "${orchestrator_lambda_arn}",
        "Payload": {
          "action": "prepare",
          "deployment_input.$": "$"
        }
      },
      "ResultSelector": {
        "result.$": "$.Payload"
      },
      "ResultPath": "$.prepare",
      "Next": "StartRefresh",
      "Catch": [
        {
          "ErrorEquals": ["States.ALL"],
          "ResultPath": "$.error",
          "Next": "HandleError"
        }
      ]
    },

    "StartRefresh": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "Parameters": {
        "FunctionName": "${orchestrator_lambda_arn}",
        "Payload": {
          "action": "start_refresh",
          "asg_name.$": "$.prepare.result.asg_name",
          "image_tag.$": "$.image_tag",
          "deployment_id.$": "$.prepare.result.deployment_id"
        }
      },
      "ResultSelector": {
        "result.$": "$.Payload"
      },
      "ResultPath": "$.refresh",
      "Next": "WaitForRefresh",
      "Catch": [
        {
          "ErrorEquals": ["States.ALL"],
          "ResultPath": "$.error",
          "Next": "HandleError"
        }
      ]
    },

    "WaitForRefresh": {
      "Type": "Wait",
      "Seconds": 30,
      "Next": "CheckRefreshStatus"
    },

    "CheckRefreshStatus": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "Parameters": {
        "FunctionName": "${orchestrator_lambda_arn}",
        "Payload": {
          "action": "check_refresh_status",
          "instance_refresh_id.$": "$.refresh.result.instance_refresh_id",
          "asg_name.$": "$.prepare.result.asg_name"
        }
      },
      "ResultSelector": {
        "result.$": "$.Payload"
      },
      "ResultPath": "$.status",
      "Next": "EvaluateStatus",
      "Catch": [
        {
          "ErrorEquals": ["States.ALL"],
          "ResultPath": "$.error",
          "Next": "HandleError"
        }
      ]
    },

    "EvaluateStatus": {
      "Type": "Choice",
      "Choices": [
        {
          "And": [
            {
              "Variable": "$.status.result.status",
              "StringEquals": "InProgress"
            },
            {
              "Variable": "$.status.result.at_checkpoint",
              "BooleanEquals": true
            }
          ],
          "Next": "WaitForHealthSettling"
        },
        {
          "Variable": "$.status.result.status",
          "StringEquals": "InProgress",
          "Next": "WaitForRefresh"
        },
        {
          "Variable": "$.status.result.status",
          "StringEquals": "Successful",
          "Next": "WaitForFinalHealthSettling"
        },
        {
          "Variable": "$.status.result.status",
          "StringEquals": "Failed",
          "Next": "NotifyFailure"
        },
        {
          "Variable": "$.status.result.status",
          "StringEquals": "Cancelled",
          "Next": "NotifyFailure"
        }
      ],
      "Default": "WaitForRefresh"
    },

    "WaitForHealthSettling": {
      "Type": "Wait",
      "Comment": "Allow NLB targets to register and pass health checks before evaluating",
      "Seconds": 90,
      "Next": "CheckHealth"
    },

    "CheckHealth": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "Parameters": {
        "FunctionName": "${orchestrator_lambda_arn}",
        "Payload": {
          "action": "check_health",
          "asg_name.$": "$.prepare.result.asg_name",
          "deployment_id.$": "$.prepare.result.deployment_id"
        }
      },
      "ResultSelector": {
        "result.$": "$.Payload"
      },
      "ResultPath": "$.health",
      "Next": "EvaluateHealth",
      "Catch": [
        {
          "ErrorEquals": ["States.ALL"],
          "ResultPath": "$.error",
          "Next": "HandleError"
        }
      ]
    },

    "EvaluateHealth": {
      "Type": "Choice",
      "Choices": [
        {
          "Variable": "$.health.result.healthy",
          "BooleanEquals": true,
          "Next": "WaitForRefresh"
        },
        {
          "Variable": "$.health.result.healthy",
          "BooleanEquals": false,
          "Next": "NotifyUnhealthy"
        }
      ],
      "Default": "NotifyUnhealthy"
    },

    "WaitForFinalHealthSettling": {
      "Type": "Wait",
      "Comment": "Allow NLB targets to stabilize after refresh completes before final check",
      "Seconds": 90,
      "Next": "CheckFinalHealth"
    },

    "CheckFinalHealth": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "Parameters": {
        "FunctionName": "${orchestrator_lambda_arn}",
        "Payload": {
          "action": "check_health",
          "asg_name.$": "$.prepare.result.asg_name",
          "deployment_id.$": "$.prepare.result.deployment_id"
        }
      },
      "ResultSelector": {
        "result.$": "$.Payload"
      },
      "ResultPath": "$.final_health",
      "Next": "EvaluateFinalHealth",
      "Catch": [
        {
          "ErrorEquals": ["States.ALL"],
          "ResultPath": "$.error",
          "Next": "HandleError"
        }
      ]
    },

    "EvaluateFinalHealth": {
      "Type": "Choice",
      "Choices": [
        {
          "Variable": "$.final_health.result.healthy",
          "BooleanEquals": true,
          "Next": "CompleteDeployment"
        },
        {
          "Variable": "$.final_health.result.healthy",
          "BooleanEquals": false,
          "Next": "NotifyUnhealthy"
        }
      ],
      "Default": "NotifyUnhealthy"
    },

    "CompleteDeployment": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "Parameters": {
        "FunctionName": "${orchestrator_lambda_arn}",
        "Payload": {
          "action": "complete",
          "asg_name.$": "$.prepare.result.asg_name",
          "deployment_id.$": "$.prepare.result.deployment_id",
          "image_tag.$": "$.image_tag"
        }
      },
      "ResultSelector": {
        "result.$": "$.Payload"
      },
      "ResultPath": "$.complete",
      "Next": "NotifySuccess",
      "Catch": [
        {
          "ErrorEquals": ["States.ALL"],
          "ResultPath": "$.error",
          "Next": "HandleError"
        }
      ]
    },

    "NotifySuccess": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "Parameters": {
        "FunctionName": "${orchestrator_lambda_arn}",
        "Payload": {
          "action": "notify",
          "status": "success",
          "message": "Canary deployment completed successfully",
          "deployment_id.$": "$.prepare.result.deployment_id",
          "image_tag.$": "$.image_tag"
        }
      },
      "ResultSelector": {
        "result.$": "$.Payload"
      },
      "ResultPath": "$.notify",
      "Next": "DeploymentSucceeded",
      "Catch": [
        {
          "ErrorEquals": ["States.ALL"],
          "ResultPath": "$.error",
          "Next": "HandleError"
        }
      ]
    },

    "DeploymentSucceeded": {
      "Type": "Succeed"
    },

    "NotifyUnhealthy": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "Parameters": {
        "FunctionName": "${orchestrator_lambda_arn}",
        "Payload": {
          "action": "notify",
          "status": "unhealthy",
          "message": "Health check failed, initiating rollback",
          "deployment_id.$": "$.prepare.result.deployment_id",
          "image_tag.$": "$.image_tag"
        }
      },
      "ResultSelector": {
        "result.$": "$.Payload"
      },
      "ResultPath": "$.notify_unhealthy",
      "Next": "RollbackRefresh",
      "Catch": [
        {
          "ErrorEquals": ["States.ALL"],
          "ResultPath": "$.error",
          "Next": "HandleError"
        }
      ]
    },

    "RollbackRefresh": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "Parameters": {
        "FunctionName": "${orchestrator_lambda_arn}",
        "Payload": {
          "action": "rollback",
          "instance_refresh_id.$": "$.refresh.result.instance_refresh_id",
          "asg_name.$": "$.prepare.result.asg_name",
          "deployment_id.$": "$.prepare.result.deployment_id"
        }
      },
      "ResultSelector": {
        "result.$": "$.Payload"
      },
      "ResultPath": "$.rollback",
      "Next": "WaitForRollback",
      "Catch": [
        {
          "ErrorEquals": ["States.ALL"],
          "ResultPath": "$.error",
          "Next": "HandleError"
        }
      ]
    },

    "WaitForRollback": {
      "Type": "Wait",
      "Seconds": 30,
      "Next": "CheckRollbackStatus"
    },

    "CheckRollbackStatus": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "Parameters": {
        "FunctionName": "${orchestrator_lambda_arn}",
        "Payload": {
          "action": "check_refresh_status",
          "instance_refresh_id.$": "$.refresh.result.instance_refresh_id",
          "asg_name.$": "$.prepare.result.asg_name"
        }
      },
      "ResultSelector": {
        "result.$": "$.Payload"
      },
      "ResultPath": "$.rollback_status",
      "Next": "EvaluateRollback",
      "Catch": [
        {
          "ErrorEquals": ["States.ALL"],
          "ResultPath": "$.error",
          "Next": "HandleError"
        }
      ]
    },

    "EvaluateRollback": {
      "Type": "Choice",
      "Choices": [
        {
          "Variable": "$.rollback_status.result.status",
          "StringEquals": "RollbackSuccessful",
          "Next": "NotifyRollbackComplete"
        },
        {
          "Variable": "$.rollback_status.result.status",
          "StringEquals": "RollbackInProgress",
          "Next": "WaitForRollback"
        },
        {
          "Variable": "$.rollback_status.result.status",
          "StringEquals": "RollbackFailed",
          "Next": "NotifyRollbackFailed"
        }
      ],
      "Default": "NotifyRollbackFailed"
    },

    "NotifyRollbackComplete": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "Parameters": {
        "FunctionName": "${orchestrator_lambda_arn}",
        "Payload": {
          "action": "notify",
          "status": "rolled_back",
          "message": "Deployment rolled back successfully",
          "deployment_id.$": "$.prepare.result.deployment_id",
          "image_tag.$": "$.image_tag"
        }
      },
      "ResultSelector": {
        "result.$": "$.Payload"
      },
      "ResultPath": "$.notify_rollback",
      "Next": "CleanupAfterRollback",
      "Catch": [
        {
          "ErrorEquals": ["States.ALL"],
          "ResultPath": "$.error",
          "Next": "HandleError"
        }
      ]
    },

    "CleanupAfterRollback": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "Parameters": {
        "FunctionName": "${orchestrator_lambda_arn}",
        "Payload": {
          "action": "complete",
          "deployment_id.$": "$.prepare.result.deployment_id"
        }
      },
      "ResultSelector": {
        "result.$": "$.Payload"
      },
      "ResultPath": "$.cleanup",
      "Next": "DeploymentRolledBack",
      "Catch": [
        {
          "ErrorEquals": ["States.ALL"],
          "ResultPath": "$.error",
          "Next": "DeploymentRolledBack"
        }
      ]
    },

    "DeploymentRolledBack": {
      "Type": "Succeed"
    },

    "NotifyRollbackFailed": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "Parameters": {
        "FunctionName": "${orchestrator_lambda_arn}",
        "Payload": {
          "action": "notify",
          "status": "rollback_failed",
          "message": "Rollback failed - manual intervention required",
          "deployment_id.$": "$.prepare.result.deployment_id",
          "image_tag.$": "$.image_tag"
        }
      },
      "ResultSelector": {
        "result.$": "$.Payload"
      },
      "ResultPath": "$.notify_rollback_failed",
      "Next": "CleanupAfterRollbackFailure",
      "Catch": [
        {
          "ErrorEquals": ["States.ALL"],
          "ResultPath": "$.error",
          "Next": "CleanupAfterRollbackFailure"
        }
      ]
    },

    "CleanupAfterRollbackFailure": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "Parameters": {
        "FunctionName": "${orchestrator_lambda_arn}",
        "Payload": {
          "action": "complete"
        }
      },
      "ResultSelector": {
        "result.$": "$.Payload"
      },
      "ResultPath": "$.cleanup_rollback_failure",
      "Next": "DeploymentRollbackFailed",
      "Catch": [
        {
          "ErrorEquals": ["States.ALL"],
          "ResultPath": "$.error",
          "Next": "DeploymentRollbackFailed"
        }
      ]
    },

    "DeploymentRollbackFailed": {
      "Type": "Fail",
      "Error": "RollbackFailed",
      "Cause": "Deployment rollback failed and requires manual intervention"
    },

    "NotifyFailure": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "Parameters": {
        "FunctionName": "${orchestrator_lambda_arn}",
        "Payload": {
          "action": "notify",
          "status": "failed",
          "message": "Instance refresh failed or was cancelled",
          "deployment_id.$": "$.prepare.result.deployment_id",
          "image_tag.$": "$.image_tag"
        }
      },
      "ResultSelector": {
        "result.$": "$.Payload"
      },
      "ResultPath": "$.notify_failure",
      "Next": "CleanupAfterFailure",
      "Catch": [
        {
          "ErrorEquals": ["States.ALL"],
          "ResultPath": "$.error",
          "Next": "CleanupAfterFailure"
        }
      ]
    },

    "CleanupAfterFailure": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "Parameters": {
        "FunctionName": "${orchestrator_lambda_arn}",
        "Payload": {
          "action": "complete"
        }
      },
      "ResultSelector": {
        "result.$": "$.Payload"
      },
      "ResultPath": "$.cleanup_failure",
      "Next": "DeploymentFailed",
      "Catch": [
        {
          "ErrorEquals": ["States.ALL"],
          "ResultPath": "$.error",
          "Next": "DeploymentFailed"
        }
      ]
    },

    "HandleError": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "Parameters": {
        "FunctionName": "${orchestrator_lambda_arn}",
        "Payload": {
          "action": "notify",
          "status": "error",
          "message": "State machine encountered an error",
          "error.$": "$.error"
        }
      },
      "ResultSelector": {
        "result.$": "$.Payload"
      },
      "ResultPath": "$.error_notify",
      "Next": "CleanupAfterFailure",
      "Catch": [
        {
          "ErrorEquals": ["States.ALL"],
          "ResultPath": "$.error_notify_failed",
          "Next": "CleanupAfterFailure"
        }
      ]
    },

    "DeploymentFailed": {
      "Type": "Fail",
      "Error": "DeploymentFailed",
      "Cause": "Canary deployment failed"
    }
  }
}
