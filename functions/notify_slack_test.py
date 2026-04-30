# -*- coding: utf-8 -*-
"""
Slack Notification Test
-----------------------

Unit tests for `notify_slack.py`

"""

import ast
import os
from datetime import datetime, timedelta, timezone

import notify_slack
import pytest
from botocore.stub import Stubber


def test_sns_get_slack_message_payload_snapshots(snapshot, monkeypatch):
    """
    Compare outputs of get_slack_message_payload() with snapshots stored

    Run `pipenv run test:updatesnapshots` to update snapshot images
    """

    monkeypatch.setenv("SLACK_CHANNEL", "slack_testing_sandbox")
    monkeypatch.setenv("SLACK_USERNAME", "notify_slack_test")
    monkeypatch.setenv("SLACK_EMOJI", ":aws:")

    # These are SNS messages that invoke the lambda handler; the event payload is in the
    # `message` field
    _dir = "./messages"
    messages = [f for f in os.listdir(_dir) if os.path.isfile(os.path.join(_dir, f))]

    for file in messages:
        with open(os.path.join(_dir, file), "r") as ofile:
            event = ast.literal_eval(ofile.read())

            attachments = []
            # These are as delivered wrapped in an SNS message payload so we unpack
            for record in event["Records"]:
                sns = record["Sns"]
                subject = sns["Subject"]
                message = sns["Message"]
                region = sns["TopicArn"].split(":")[3]

                attachment = notify_slack.get_slack_message_payload(
                    message=message, region=region, subject=subject
                )
                attachments.append(attachment)

            filename = os.path.basename(file)
            snapshot.assert_match(attachments, f"message_{filename}")


def test_event_get_slack_message_payload_snapshots(snapshot, monkeypatch):
    """
    Compare outputs of get_slack_message_payload() with snapshots stored

    Run `pipenv run test:updatesnapshots` to update snapshot images
    """

    monkeypatch.setenv("SLACK_CHANNEL", "slack_testing_sandbox")
    monkeypatch.setenv("SLACK_USERNAME", "notify_slack_test")
    monkeypatch.setenv("SLACK_EMOJI", ":aws:")

    # These are just the raw events that will be converted to JSON string and
    # sent via SNS message
    _dir = "./events"
    events = [f for f in os.listdir(_dir) if os.path.isfile(os.path.join(_dir, f))]

    for file in events:
        with open(os.path.join(_dir, file), "r") as ofile:
            event = ast.literal_eval(ofile.read())

            attachment = notify_slack.get_slack_message_payload(
                message=event, region="us-east-1", subject="bar"
            )
            attachments = [attachment]

            filename = os.path.basename(file)
            snapshot.assert_match(attachments, f"event_{filename}")


def test_environment_variables_set(monkeypatch):
    """
    Should pass since environment variables are provided
    """

    monkeypatch.setenv("SLACK_CHANNEL", "slack_testing_sandbox")
    monkeypatch.setenv("SLACK_USERNAME", "notify_slack_test")
    monkeypatch.setenv("SLACK_EMOJI", ":aws:")
    monkeypatch.setenv(
        "SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/YOUR/WEBOOK/URL"
    )

    with open(os.path.join("./messages/text_message.json"), "r") as efile:
        event = ast.literal_eval(efile.read())

        for record in event["Records"]:
            sns = record["Sns"]
            subject = sns["Subject"]
            message = sns["Message"]
            region = sns["TopicArn"].split(":")[3]

            notify_slack.get_slack_message_payload(
                message=message, region=region, subject=subject
            )


def test_environment_variables_missing():
    """
    Should pass since environment variables are NOT provided and
    will raise a `KeyError`
    """
    with pytest.raises(KeyError):
        # will raise before parsing/validation
        notify_slack.get_slack_message_payload(message={}, region="foo", subject="bar")


@pytest.mark.parametrize(
    "region,service,expected",
    [
        (
            "us-east-1",
            "cloudwatch",
            "https://console.aws.amazon.com/cloudwatch/home?region=us-east-1",
        ),
        (
            "us-gov-east-1",
            "cloudwatch",
            "https://console.amazonaws-us-gov.com/cloudwatch/home?region=us-gov-east-1",
        ),
        (
            "us-east-1",
            "guardduty",
            "https://console.aws.amazon.com/guardduty/home?region=us-east-1",
        ),
        (
            "us-gov-east-1",
            "guardduty",
            "https://console.amazonaws-us-gov.com/guardduty/home?region=us-gov-east-1",
        ),
    ],
)
def test_get_service_url(region, service, expected):
    assert notify_slack.get_service_url(region=region, service=service) == expected


def test_get_service_url_exception():
    """
    Should raise error since service is not defined in enum
    """
    with pytest.raises(KeyError):
        notify_slack.get_service_url(region="us-east-1", service="athena")


# ---------------------------------------------------------------------------
# ECS Service Action steady state suppression
# ---------------------------------------------------------------------------


_DISPATCHED_TS_ISO = "2026-04-15T05:17:49.421Z"
_DISPATCHED_TS = datetime(2026, 4, 15, 5, 17, 49, 421000, tzinfo=timezone.utc)


def _steady_state_event(message_dict_overrides=None):
    """Build a SERVICE_STEADY_STATE EventBridge payload for tests."""
    payload = {
        "version": "0",
        "id": "af3c9036-1c77-4be7-85d7-a2c23cf8a3bc",
        "detail-type": "ECS Service Action",
        "source": "aws.ecs",
        "account": "123456789012",
        "time": "2026-04-15T05:17:49Z",
        "region": "us-east-1",
        "resources": [
            "arn:aws:ecs:us-east-1:123456789012:service/my-cluster/my-service"
        ],
        "detail": {
            "eventType": "INFO",
            "eventName": "SERVICE_STEADY_STATE",
            "clusterArn": "arn:aws:ecs:us-east-1:123456789012:cluster/my-cluster",
            "createdAt": _DISPATCHED_TS_ISO,
        },
    }
    if message_dict_overrides:
        payload["detail"].update(message_dict_overrides)
    return payload


def _ecs_event(message, offset_ms):
    """Build a single `events[]` entry as returned by DescribeServices.

    `offset_ms` is the number of milliseconds before the dispatched event;
    `0` means the timestamps match exactly (the dispatched event itself).
    """
    return {
        "id": f"event-{offset_ms}",
        "createdAt": _DISPATCHED_TS - timedelta(milliseconds=offset_ms),
        "message": message,
    }


def _stub_describe_services(events):
    """Wrap the module-level ECS_CLIENT with a Stubber returning `events`."""
    stubber = Stubber(notify_slack.ECS_CLIENT)
    stubber.add_response(
        "describe_services",
        {
            "services": [
                {
                    "serviceName": "my-service",
                    "clusterArn": (
                        "arn:aws:ecs:us-east-1:123456789012:cluster/my-cluster"
                    ),
                    "events": events,
                }
            ],
            "failures": [],
        },
        expected_params={"cluster": "my-cluster", "services": ["my-service"]},
    )
    return stubber


def test_suppress_skips_non_steady_state_without_api_call():
    message = _steady_state_event({"eventName": "SERVICE_DEPLOYMENT_COMPLETED"})
    # No stubber: should never reach the boto client.
    assert notify_slack.should_suppress_ecs_service_action(message) is False


def test_suppress_when_predecessor_is_steady_state_match_by_timestamp():
    events = [
        _ecs_event("(service my-service) has reached a steady state.", 0),
        _ecs_event("(service my-service) has reached a steady state.", 60_000),
    ]
    with _stub_describe_services(events):
        assert (
            notify_slack.should_suppress_ecs_service_action(_steady_state_event())
            is True
        )


def test_notify_when_predecessor_is_deployment_completed_match_by_timestamp():
    events = [
        _ecs_event("(service my-service) has reached a steady state.", 0),
        _ecs_event(
            "(service my-service) has completed deployment of "
            "(taskDefinition my-task:42).",
            500,
        ),
    ]
    with _stub_describe_services(events):
        assert (
            notify_slack.should_suppress_ecs_service_action(_steady_state_event())
            is False
        )


def test_notify_when_predecessor_is_unhealthy_match_by_timestamp():
    events = [
        _ecs_event("(service my-service) has reached a steady state.", 0),
        _ecs_event(
            "(service my-service) (task abcd) failed container health checks.",
            12_000,
        ),
    ]
    with _stub_describe_services(events):
        assert (
            notify_slack.should_suppress_ecs_service_action(_steady_state_event())
            is False
        )


def test_suppress_when_dispatched_event_aged_out_and_head_is_steady_state():
    # Dispatched event has aged off the 100-event window; the timestamp match
    # fails and the head of `events[]` is itself another heartbeat, meaning
    # the predecessor we care about is also steady. Suppress.
    events = [
        _ecs_event("(service my-service) has reached a steady state.", 60_000),
        _ecs_event("(service my-service) has reached a steady state.", 120_000),
    ]
    with _stub_describe_services(events):
        assert (
            notify_slack.should_suppress_ecs_service_action(_steady_state_event())
            is True
        )


def test_notify_when_dispatched_event_not_yet_propagated_and_head_is_real():
    # Propagation race: the dispatched event has not appeared in `events[]`
    # yet; the head is a non-steady event so we treat it as the predecessor.
    events = [
        _ecs_event(
            "(service my-service) has completed deployment of "
            "(taskDefinition my-task:42).",
            500,
        ),
        _ecs_event("(service my-service) has reached a steady state.", 90_000),
    ]
    with _stub_describe_services(events):
        assert (
            notify_slack.should_suppress_ecs_service_action(_steady_state_event())
            is False
        )


def test_suppress_when_events_list_is_empty():
    with _stub_describe_services([]):
        assert (
            notify_slack.should_suppress_ecs_service_action(_steady_state_event())
            is True
        )


def test_suppress_when_match_is_only_visible_event():
    events = [_ecs_event("(service my-service) has reached a steady state.", 0)]
    with _stub_describe_services(events):
        assert (
            notify_slack.should_suppress_ecs_service_action(_steady_state_event())
            is True
        )


def test_notify_when_describe_services_raises():
    stubber = Stubber(notify_slack.ECS_CLIENT)
    stubber.add_client_error(
        "describe_services",
        service_error_code="ThrottlingException",
        service_message="Rate exceeded",
        http_status_code=400,
    )
    with stubber:
        # Fail open: throttle / transient errors must not drop the message.
        assert (
            notify_slack.should_suppress_ecs_service_action(_steady_state_event())
            is False
        )


def test_notify_when_created_at_missing_falls_back_positionally_to_real_event():
    # `detail.createdAt` absent: timestamp match cannot run. Head of `events`
    # is a non-steady event, treated as the predecessor.
    message = _steady_state_event()
    del message["detail"]["createdAt"]
    events = [
        _ecs_event(
            "(service my-service) (task abcd) failed container health checks.",
            1_000,
        ),
        _ecs_event("(service my-service) has reached a steady state.", 60_000),
    ]
    with _stub_describe_services(events):
        assert notify_slack.should_suppress_ecs_service_action(message) is False


def test_suppress_when_created_at_missing_and_head_is_steady_state():
    message = _steady_state_event()
    del message["detail"]["createdAt"]
    events = [
        _ecs_event("(service my-service) has reached a steady state.", 1_000),
        _ecs_event("(service my-service) has reached a steady state.", 60_000),
    ]
    with _stub_describe_services(events):
        assert notify_slack.should_suppress_ecs_service_action(message) is True


def test_suppress_handles_old_format_service_arn():
    # Old ARN format: cluster name is not in the ARN, has to come from
    # `detail.clusterArn`.
    message = _steady_state_event()
    message["resources"] = ["arn:aws:ecs:us-east-1:123456789012:service/my-service"]
    events = [
        _ecs_event("(service my-service) has reached a steady state.", 0),
        _ecs_event("(service my-service) has reached a steady state.", 60_000),
    ]
    with _stub_describe_services(events):
        assert notify_slack.should_suppress_ecs_service_action(message) is True
