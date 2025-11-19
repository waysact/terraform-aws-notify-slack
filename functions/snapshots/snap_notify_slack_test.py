# -*- coding: utf-8 -*-
# snapshottest: v1 - https://goo.gl/zC4yUc
from __future__ import unicode_literals

from snapshottest import Snapshot

snapshots = Snapshot()

snapshots[
    "test_event_get_slack_message_payload_snapshots event_aws_health_event.json"
] = [
    {
        "attachments": [
            {
                "color": "danger",
                "fallback": "New AWS Health Event for EC2",
                "fields": [
                    {"short": True, "title": "Affected Service", "value": "`EC2`"},
                    {"short": True, "title": "Affected Region", "value": "`us-west-2`"},
                    {
                        "short": False,
                        "title": "Code",
                        "value": "`AWS_EC2_INSTANCE_STORE_DRIVE_PERFORMANCE_DEGRADED`",
                    },
                    {
                        "short": False,
                        "title": "Event Description",
                        "value": "`A description of the event will be provided here`",
                    },
                    {
                        "short": False,
                        "title": "Affected Resources",
                        "value": "`i-abcd1111`",
                    },
                    {
                        "short": True,
                        "title": "Start Time",
                        "value": "`Sat, 05 Jun 2016 15:10:09 GMT`",
                    },
                    {"short": True, "title": "End Time", "value": "`<unknown>`"},
                    {
                        "short": False,
                        "title": "Link to Event",
                        "value": "https://phd.aws.amazon.com/phd/home?region=us-west-2#/dashboard/open-issues",
                    },
                ],
                "text": "New AWS Health Event for EC2",
            }
        ],
        "channel": "slack_testing_sandbox",
        "icon_emoji": ":aws:",
        "username": "notify_slack_test",
    }
]

snapshots[
    "test_event_get_slack_message_payload_snapshots event_cloudtrail_authorize_security_group_ingress.json"
] = [
    {
        "attachments": [
            {
                "color": "#FF9900",
                "fallback": "AuthorizeSecurityGroupIngress by AIDAIPSVCDGDEZEXAMPLE:session-name",
                "fields": [
                    {
                        "short": True,
                        "title": "Event",
                        "value": "🔓 *AuthorizeSecurityGroupIngress*",
                    },
                    {"short": True, "title": "Region", "value": "us-east-1"},
                    {
                        "short": True,
                        "title": "Security Group ID",
                        "value": "`sg-0abcd1234efgh5678`",
                    },
                    {
                        "short": False,
                        "title": "Rule Changes",
                        "value": """• TCP | port 443 | 10.0.0.0/8 | Allow HTTPS from internal network
• TCP | port 22 | SG: sg-0xyz9876abcd5432 | Allow SSH from bastion host""",
                    },
                    {
                        "short": False,
                        "title": "Principal",
                        "value": "👤 AIDAIPSVCDGDEZEXAMPLE:session-name (Assumed Role)",
                    },
                    {"short": True, "title": "Time", "value": "2025-01-15T23:15:30Z"},
                    {"short": True, "title": "Source IP", "value": "203.0.113.42"},
                    {
                        "short": False,
                        "title": "Tool",
                        "value": "🏗️ Terraform 1.6.0 | AWS Provider 5.30.0",
                    },
                ],
                "mrkdwn_in": ["text", "fields"],
                "title": "🔐 Security Configuration Change",
            }
        ],
        "channel": "slack_testing_sandbox",
        "icon_emoji": ":aws:",
        "username": "notify_slack_test",
    }
]

snapshots[
    "test_event_get_slack_message_payload_snapshots event_cloudtrail_authorize_sg_port_zero.json"
] = [
    {
        "attachments": [
            {
                "color": "#FF9900",
                "fallback": "AuthorizeSecurityGroupIngress by network-engineer",
                "fields": [
                    {
                        "short": True,
                        "title": "Event",
                        "value": "🔓 *AuthorizeSecurityGroupIngress*",
                    },
                    {"short": True, "title": "Region", "value": "us-east-1"},
                    {
                        "short": True,
                        "title": "Security Group ID",
                        "value": "`sg-0test1234port0567`",
                    },
                    {
                        "short": False,
                        "title": "Rule Changes",
                        "value": "• TCP | port 0 | 10.0.0.0/16 | Test rule with port 0",
                    },
                    {
                        "short": False,
                        "title": "Principal",
                        "value": "👤 network-engineer (IAM User) 🔐",
                    },
                    {"short": True, "title": "Time", "value": "2025-01-16T14:20:00Z"},
                    {"short": True, "title": "Source IP", "value": "192.0.2.100"},
                ],
                "mrkdwn_in": ["text", "fields"],
                "title": "🔐 Security Configuration Change",
            }
        ],
        "channel": "slack_testing_sandbox",
        "icon_emoji": ":aws:",
        "username": "notify_slack_test",
    }
]

snapshots[
    "test_event_get_slack_message_payload_snapshots event_cloudtrail_create_network_acl_entry.json"
] = [
    {
        "attachments": [
            {
                "color": "#FF9900",
                "fallback": "CreateNetworkAclEntry by network-admin",
                "fields": [
                    {
                        "short": True,
                        "title": "Event",
                        "value": "➕ *CreateNetworkAclEntry*",
                    },
                    {"short": True, "title": "Region", "value": "us-west-2"},
                    {
                        "short": True,
                        "title": "Network ACL ID",
                        "value": "`acl-0123456789abcdef0`",
                    },
                    {
                        "short": False,
                        "title": "NACL Entry Details",
                        "value": "Rule #: 100 | Action: ALLOW | Direction: Ingress | CIDR: 192.168.1.0/24 | Protocol: TCP",
                    },
                    {
                        "short": False,
                        "title": "Principal",
                        "value": "👤 network-admin (IAM User) 🔐",
                    },
                    {"short": True, "title": "Time", "value": "2025-01-15T23:30:45Z"},
                    {"short": True, "title": "Source IP", "value": "198.51.100.25"},
                    {
                        "short": False,
                        "title": "Tool",
                        "value": "🏗️ Terraform 1.7.0 | AWS Provider 5.40.0",
                    },
                ],
                "mrkdwn_in": ["text", "fields"],
                "title": "🔐 Security Configuration Change",
            }
        ],
        "channel": "slack_testing_sandbox",
        "icon_emoji": ":aws:",
        "username": "notify_slack_test",
    }
]

snapshots[
    "test_event_get_slack_message_payload_snapshots event_cloudtrail_create_security_group.json"
] = [
    {
        "attachments": [
            {
                "color": "#FF9900",
                "fallback": "CreateSecurityGroup by userExample",
                "fields": [
                    {
                        "short": True,
                        "title": "Event",
                        "value": "🆕 *CreateSecurityGroup*",
                    },
                    {"short": True, "title": "Region", "value": "eu-west-1"},
                    {
                        "short": True,
                        "title": "Security Group ID",
                        "value": "`sg-077f4afab6ad41d72`",
                    },
                    {
                        "short": True,
                        "title": "Security Group Name",
                        "value": "`utility-instance`",
                    },
                    {"short": True, "title": "VPC ID", "value": "`vpc-730b0311`"},
                    {
                        "short": False,
                        "title": "Description",
                        "value": "Allow full outbound access for EC2 utility instance",
                    },
                    {
                        "short": False,
                        "title": "Principal",
                        "value": "👤 userExample (IAM User) 🔐",
                    },
                    {"short": True, "title": "Time", "value": "2025-01-15T22:44:07Z"},
                    {"short": True, "title": "Source IP", "value": "52.93.178.234"},
                    {
                        "short": False,
                        "title": "Tool",
                        "value": "🏗️ Terraform 0.12.31 | AWS Provider 5.94.1",
                    },
                ],
                "mrkdwn_in": ["text", "fields"],
                "title": "🔐 Security Configuration Change",
            }
        ],
        "channel": "slack_testing_sandbox",
        "icon_emoji": ":aws:",
        "username": "notify_slack_test",
    }
]

snapshots[
    "test_event_get_slack_message_payload_snapshots event_cloudtrail_delete_security_group.json"
] = [
    {
        "attachments": [
            {
                "color": "#FF9900",
                "fallback": "DeleteSecurityGroup by security-admin",
                "fields": [
                    {
                        "short": True,
                        "title": "Event",
                        "value": "🗑️ *DeleteSecurityGroup*",
                    },
                    {"short": True, "title": "Region", "value": "ap-southeast-1"},
                    {
                        "short": True,
                        "title": "Security Group ID",
                        "value": "`sg-0old1234removed567`",
                    },
                    {
                        "short": False,
                        "title": "Principal",
                        "value": "👤 security-admin (IAM User)",
                    },
                    {"short": True, "title": "Time", "value": "2025-01-16T10:22:15Z"},
                    {"short": True, "title": "Source IP", "value": "203.0.113.99"},
                ],
                "mrkdwn_in": ["text", "fields"],
                "title": "🔐 Security Configuration Change",
            }
        ],
        "channel": "slack_testing_sandbox",
        "icon_emoji": ":aws:",
        "username": "notify_slack_test",
    }
]

snapshots[
    "test_event_get_slack_message_payload_snapshots event_cloudwatch_alarm.json"
] = [
    {
        "attachments": [
            {
                "color": "danger",
                "fallback": "Alarm Example triggered",
                "fields": [
                    {"short": True, "title": "Alarm Name", "value": "`Example`"},
                    {
                        "short": False,
                        "title": "Alarm Description",
                        "value": "`Example alarm description.`",
                    },
                    {
                        "short": False,
                        "title": "Alarm reason",
                        "value": "`Threshold Crossed`",
                    },
                    {"short": True, "title": "Old State", "value": "`OK`"},
                    {"short": True, "title": "Current State", "value": "`ALARM`"},
                    {
                        "short": False,
                        "title": "Link to Alarm",
                        "value": "https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#alarm:alarmFilter=ANY;name=Example",
                    },
                ],
                "text": "AWS CloudWatch notification - Example",
            }
        ],
        "channel": "slack_testing_sandbox",
        "icon_emoji": ":aws:",
        "username": "notify_slack_test",
    }
]

snapshots[
    "test_event_get_slack_message_payload_snapshots event_guardduty_finding_high.json"
] = [
    {
        "attachments": [
            {
                "color": "danger",
                "fallback": "GuardDuty Finding: SAMPLE Unprotected port on EC2 instance i-123123123 is being probed",
                "fields": [
                    {
                        "short": False,
                        "title": "Description",
                        "value": "`EC2 instance has an unprotected port which is being probed by a known malicious host.`",
                    },
                    {
                        "short": False,
                        "title": "Finding Type",
                        "value": "`Recon:EC2 PortProbeUnprotectedPort`",
                    },
                    {
                        "short": True,
                        "title": "First Seen",
                        "value": "`2020-01-02T01:02:03Z`",
                    },
                    {
                        "short": True,
                        "title": "Last Seen",
                        "value": "`2020-01-03T01:02:03Z`",
                    },
                    {"short": True, "title": "Severity", "value": "`High`"},
                    {"short": True, "title": "Account ID", "value": "`123456789`"},
                    {"short": True, "title": "Count", "value": "`1234`"},
                    {
                        "short": False,
                        "title": "Link to Finding",
                        "value": "https://console.aws.amazon.com/guardduty/home?region=us-east-1#/findings?search=id%3Dsample-id-2",
                    },
                ],
                "text": "AWS GuardDuty Finding - SAMPLE Unprotected port on EC2 instance i-123123123 is being probed",
            }
        ],
        "channel": "slack_testing_sandbox",
        "icon_emoji": ":aws:",
        "username": "notify_slack_test",
    }
]

snapshots[
    "test_event_get_slack_message_payload_snapshots event_guardduty_finding_low.json"
] = [
    {
        "attachments": [
            {
                "color": "#777777",
                "fallback": "GuardDuty Finding: SAMPLE Unprotected port on EC2 instance i-123123123 is being probed",
                "fields": [
                    {
                        "short": False,
                        "title": "Description",
                        "value": "`EC2 instance has an unprotected port which is being probed by a known malicious host.`",
                    },
                    {
                        "short": False,
                        "title": "Finding Type",
                        "value": "`Recon:EC2 PortProbeUnprotectedPort`",
                    },
                    {
                        "short": True,
                        "title": "First Seen",
                        "value": "`2020-01-02T01:02:03Z`",
                    },
                    {
                        "short": True,
                        "title": "Last Seen",
                        "value": "`2020-01-03T01:02:03Z`",
                    },
                    {"short": True, "title": "Severity", "value": "`Low`"},
                    {"short": True, "title": "Account ID", "value": "`123456789`"},
                    {"short": True, "title": "Count", "value": "`1234`"},
                    {
                        "short": False,
                        "title": "Link to Finding",
                        "value": "https://console.aws.amazon.com/guardduty/home?region=us-east-1#/findings?search=id%3Dsample-id-2",
                    },
                ],
                "text": "AWS GuardDuty Finding - SAMPLE Unprotected port on EC2 instance i-123123123 is being probed",
            }
        ],
        "channel": "slack_testing_sandbox",
        "icon_emoji": ":aws:",
        "username": "notify_slack_test",
    }
]

snapshots[
    "test_event_get_slack_message_payload_snapshots event_guardduty_finding_medium.json"
] = [
    {
        "attachments": [
            {
                "color": "warning",
                "fallback": "GuardDuty Finding: SAMPLE Unprotected port on EC2 instance i-123123123 is being probed",
                "fields": [
                    {
                        "short": False,
                        "title": "Description",
                        "value": "`EC2 instance has an unprotected port which is being probed by a known malicious host.`",
                    },
                    {
                        "short": False,
                        "title": "Finding Type",
                        "value": "`Recon:EC2 PortProbeUnprotectedPort`",
                    },
                    {
                        "short": True,
                        "title": "First Seen",
                        "value": "`2020-01-02T01:02:03Z`",
                    },
                    {
                        "short": True,
                        "title": "Last Seen",
                        "value": "`2020-01-03T01:02:03Z`",
                    },
                    {"short": True, "title": "Severity", "value": "`Medium`"},
                    {"short": True, "title": "Account ID", "value": "`123456789`"},
                    {"short": True, "title": "Count", "value": "`1234`"},
                    {
                        "short": False,
                        "title": "Link to Finding",
                        "value": "https://console.aws.amazon.com/guardduty/home?region=us-east-1#/findings?search=id%3Dsample-id-2",
                    },
                ],
                "text": "AWS GuardDuty Finding - SAMPLE Unprotected port on EC2 instance i-123123123 is being probed",
            }
        ],
        "channel": "slack_testing_sandbox",
        "icon_emoji": ":aws:",
        "username": "notify_slack_test",
    }
]

snapshots["test_sns_get_slack_message_payload_snapshots message_backup.json"] = [
    {
        "attachments": [
            {
                "fields": [
                    {"title": "✅ An AWS Backup job was completed successfully"},
                    {"short": False, "value": "BackupJob ID"},
                    {"short": False, "value": "`1b2345b2-f22c-4dab-5eb6-bbc7890ed123`"},
                    {"short": False, "value": "Resource ARN"},
                    {
                        "short": False,
                        "value": "`arn:aws:ec2:us-west-1:123456789012:volume/vol-012f345df6789012e`",
                    },
                    {"short": False, "value": "Recovery point ARN"},
                    {
                        "short": False,
                        "value": "`arn:aws:ec2:us-west-1:123456789012:volume/vol-012f345df6789012d`",
                    },
                ]
            }
        ],
        "channel": "slack_testing_sandbox",
        "icon_emoji": ":aws:",
        "username": "notify_slack_test",
    },
    {
        "attachments": [
            {
                "fields": [
                    {"title": "⚠️ An AWS Backup job failed"},
                    {"short": False, "value": "BackupJob ID"},
                    {"short": False, "value": "`1b2345b2-f22c-4dab-5eb6-bbc7890ed123`"},
                    {"short": False, "value": "Resource ARN"},
                    {
                        "short": False,
                        "value": "`arn:aws:ec2:us-west-1:123456789012:volume/vol-012f345df6789012e`",
                    },
                ]
            }
        ],
        "channel": "slack_testing_sandbox",
        "icon_emoji": ":aws:",
        "username": "notify_slack_test",
    },
    {
        "attachments": [
            {
                "fields": [
                    {"title": "⚠️ An AWS Backup job failed to complete in time"},
                    {"short": False, "value": "BackupJob ID"},
                    {"short": False, "value": "`1b2345b2-f22c-4dab-5eb6-bbc7890ed123`"},
                    {"short": False, "value": "Resource ARN"},
                    {
                        "short": False,
                        "value": "`arn:aws:ec2:us-west-1:123456789012:volume/vol-012f345df6789012e`",
                    },
                ]
            }
        ],
        "channel": "slack_testing_sandbox",
        "icon_emoji": ":aws:",
        "username": "notify_slack_test",
    },
]

snapshots[
    "test_sns_get_slack_message_payload_snapshots message_cloudwatch_alarm.json"
] = [
    {
        "attachments": [
            {
                "color": "good",
                "fallback": "Alarm DBMigrationRequired triggered",
                "fields": [
                    {
                        "short": True,
                        "title": "Alarm Name",
                        "value": "`DBMigrationRequired`",
                    },
                    {
                        "short": False,
                        "title": "Alarm Description",
                        "value": '`App is reporting "A JPA error occurred(Unable to build EntityManagerFactory)"`',
                    },
                    {
                        "short": False,
                        "title": "Alarm reason",
                        "value": "`Threshold Crossed: 1 datapoint [1.0 (12/02/19 15:44:00)] was not less than the threshold (1.0).`",
                    },
                    {"short": True, "title": "Old State", "value": "`ALARM`"},
                    {"short": True, "title": "Current State", "value": "`OK`"},
                    {
                        "short": False,
                        "title": "Link to Alarm",
                        "value": "https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#alarm:alarmFilter=ANY;name=DBMigrationRequired",
                    },
                ],
                "text": "AWS CloudWatch notification - DBMigrationRequired",
            }
        ],
        "channel": "slack_testing_sandbox",
        "icon_emoji": ":aws:",
        "username": "notify_slack_test",
    }
]

snapshots[
    "test_sns_get_slack_message_payload_snapshots message_dms_notification.json"
] = [
    {
        "attachments": [
            {
                "fallback": "A new message",
                "fields": [
                    {
                        "short": True,
                        "title": "Event Source",
                        "value": "`replication-task`",
                    },
                    {
                        "short": True,
                        "title": "Event Time",
                        "value": "`2019-02-12 15:45:24.091`",
                    },
                    {
                        "short": False,
                        "title": "Identifier Link",
                        "value": "`https://console.aws.amazon.com/dms/home?region=us-east-1#tasks:ids=hello-world`",
                    },
                    {"short": True, "title": "SourceId", "value": "`hello-world`"},
                    {
                        "short": False,
                        "title": "Event ID",
                        "value": "`http://docs.aws.amazon.com/dms/latest/userguide/CHAP_Events.html#DMS-EVENT-0079 `",
                    },
                    {
                        "short": False,
                        "title": "Event Message",
                        "value": "`Replication task has stopped.`",
                    },
                ],
                "mrkdwn_in": ["value"],
                "text": "AWS notification",
                "title": "DMS Notification Message",
            }
        ],
        "channel": "slack_testing_sandbox",
        "icon_emoji": ":aws:",
        "username": "notify_slack_test",
    }
]

snapshots[
    "test_sns_get_slack_message_payload_snapshots message_glue_notification.json"
] = [
    {
        "attachments": [
            {
                "fallback": "A new message",
                "fields": [
                    {"short": True, "title": "version", "value": "`0`"},
                    {
                        "short": False,
                        "title": "id",
                        "value": "`ad3c3da1-148c-d5da-9a6a-79f1bc9a8a2e`",
                    },
                    {
                        "short": True,
                        "title": "detail-type",
                        "value": "`Glue Job State Change`",
                    },
                    {"short": True, "title": "source", "value": "`aws.glue`"},
                    {"short": True, "title": "account", "value": "`000000000000`"},
                    {"short": True, "title": "time", "value": "`2021-06-18T12:34:06Z`"},
                    {"short": True, "title": "region", "value": "`us-east-2`"},
                    {"short": True, "title": "resources", "value": "`[]`"},
                    {
                        "short": False,
                        "title": "detail",
                        "value": '`{"jobName": "test_job", "severity": "ERROR", "state": "FAILED", "jobRunId": "jr_ca2144d747b45ad412d3c66a1b6934b6b27aa252be9a21a95c54dfaa224a1925", "message": "SystemExit: 1"}`',
                    },
                ],
                "mrkdwn_in": ["value"],
                "text": "AWS notification",
                "title": "Message",
            }
        ],
        "channel": "slack_testing_sandbox",
        "icon_emoji": ":aws:",
        "username": "notify_slack_test",
    }
]

snapshots[
    "test_sns_get_slack_message_payload_snapshots message_guardduty_finding.json"
] = [
    {
        "attachments": [
            {
                "color": "danger",
                "fallback": "GuardDuty Finding: SAMPLE Unprotected port on EC2 instance i-123123123 is being probed",
                "fields": [
                    {
                        "short": False,
                        "title": "Description",
                        "value": "`EC2 instance has an unprotected port which is being probed by a known malicious host.`",
                    },
                    {
                        "short": False,
                        "title": "Finding Type",
                        "value": "`Recon:EC2 PortProbeUnprotectedPort`",
                    },
                    {
                        "short": True,
                        "title": "First Seen",
                        "value": "`2020-01-02T01:02:03Z`",
                    },
                    {
                        "short": True,
                        "title": "Last Seen",
                        "value": "`2020-01-03T01:02:03Z`",
                    },
                    {"short": True, "title": "Severity", "value": "`High`"},
                    {"short": True, "title": "Account ID", "value": "`123456789`"},
                    {"short": True, "title": "Count", "value": "`1234`"},
                    {
                        "short": False,
                        "title": "Link to Finding",
                        "value": "https://console.amazonaws-us-gov.com/guardduty/home?region=us-gov-east-1#/findings?search=id%3Dsample-id-2",
                    },
                ],
                "text": "AWS GuardDuty Finding - SAMPLE Unprotected port on EC2 instance i-123123123 is being probed",
            }
        ],
        "channel": "slack_testing_sandbox",
        "icon_emoji": ":aws:",
        "username": "notify_slack_test",
    }
]

snapshots[
    "test_sns_get_slack_message_payload_snapshots message_guardduty_malware_protection_object_scan_result.json"
] = [
    {
        "attachments": [
            {
                "color": "danger",
                "fallback": "GuardDuty Malware Scan Result: THREATS_FOUND",
                "fields": [
                    {
                        "short": False,
                        "title": "S3 Bucket",
                        "value": "`amzn-s3-demo-bucket`",
                    },
                    {
                        "short": False,
                        "title": "S3 Object",
                        "value": "`APKAEIBAERJR2EXAMPLE`",
                    },
                    {
                        "short": False,
                        "title": "Link to S3 object",
                        "value": "https://console.aws.amazon.com/s3/object/amzn-s3-demo-bucket?region=us-east-1&prefix=APKAEIBAERJR2EXAMPLE",
                    },
                ],
                "text": "AWS GuardDuty Malware Scan Result - THREATS_FOUND",
            }
        ],
        "channel": "slack_testing_sandbox",
        "icon_emoji": ":aws:",
        "username": "notify_slack_test",
    }
]

snapshots["test_sns_get_slack_message_payload_snapshots message_text_message.json"] = [
    {
        "attachments": [
            {
                "fallback": "A new message",
                "fields": [
                    {
                        "short": False,
                        "value": """This
is
a typical multi-line
message from SNS!

Have a ~good~ amazing day! :)""",
                    }
                ],
                "mrkdwn_in": ["value"],
                "text": "AWS notification",
                "title": "All Fine",
            }
        ],
        "channel": "slack_testing_sandbox",
        "icon_emoji": ":aws:",
        "username": "notify_slack_test",
    }
]
