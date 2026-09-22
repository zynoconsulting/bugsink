import json
import re

import requests
from django.utils import timezone

from django import forms
from django.template.defaultfilters import truncatechars

from snappea.decorators import shared_task
from bugsink.app_settings import get_settings
from bugsink.transaction import immediate_atomic

from issues.models import Issue
from .base import BaseWebhookBackend
from .webhook_security import validate_webhook_url


class SlackConfigForm(forms.Form):
    webhook_url = forms.URLField(required=True, assume_scheme="https")

    # Slack does not support multi-channel webhooks, as per the docs:
    # > You cannot override the default channel (chosen by the user who installed your app), username, or icon when
    # > you're using incoming webhooks to post messages. Instead, these values will always inherit from the associated
    # > Slack app configuration.

    def __init__(self, *args, **kwargs):
        config = kwargs.pop("config", None)

        super().__init__(*args, **kwargs)
        if config:
            self.fields["webhook_url"].initial = config.get("webhook_url", "")

    def get_config(self):
        return {
            "webhook_url": self.cleaned_data.get("webhook_url"),
        }

    def clean_webhook_url(self):
        webhook_url = self.cleaned_data["webhook_url"]
        try:
            validate_webhook_url(webhook_url)
        except ValueError as e:
            raise forms.ValidationError(str(e)) from e
        return webhook_url


def _safe_markdown(text):
    # Slack assigns a special meaning to some characters, so we need to escape them
    # to prevent them from being interpreted as formatting/special characters.
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("*", "\\*").replace("_", "\\_")


def _store_failure_info(service_config_id, exception, response=None):
    """Store failure information in the MessagingServiceConfig with immediate_atomic"""
    from alerts.models import MessagingServiceConfig

    with immediate_atomic(only_if_needed=True):
        try:
            config = MessagingServiceConfig.objects.get(id=service_config_id)

            config.last_failure_timestamp = timezone.now()
            config.last_failure_error_type = type(exception).__name__
            config.last_failure_error_message = str(exception)

            # Handle requests-specific errors
            if response is not None:
                config.last_failure_status_code = response.status_code
                config.last_failure_response_text = response.text[:2000]  # Limit response text size

                # Check if response is JSON
                try:
                    json.loads(response.text)
                    config.last_failure_is_json = True
                except (json.JSONDecodeError, ValueError):
                    config.last_failure_is_json = False
            else:
                # Non-HTTP errors
                config.last_failure_status_code = None
                config.last_failure_response_text = None
                config.last_failure_is_json = None

            config.save()
        except MessagingServiceConfig.DoesNotExist:
            # Config was deleted while task was running
            pass


def _store_success_info(service_config_id):
    """Clear failure information on successful operation"""
    from alerts.models import MessagingServiceConfig

    with immediate_atomic(only_if_needed=True):
        try:
            config = MessagingServiceConfig.objects.get(id=service_config_id)
            config.clear_failure_status()
            config.save()
        except MessagingServiceConfig.DoesNotExist:
            # Config was deleted while task was running
            pass


def _build_test_data(project_name, display_name):
    # See Slack's Block Kit Builder

    return {"text": "Test message by Bugsink to test the webhook setup.",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "TEST issue",
                    },
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "Test message by Bugsink to test the webhook setup.",
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": "*project*: " + _safe_markdown(project_name),
                        },
                        {
                            "type": "mrkdwn",
                            "text": "*message backend*: " + _safe_markdown(display_name),
                        },
                    ]
                }
            ]}


@shared_task
def slack_backend_send_test_message(webhook_url, project_name, display_name, service_config_id):
    data = _build_test_data(project_name, display_name)

    try:
        result = SlackBackend.safe_post(
            webhook_url,
            data=json.dumps(data),
            headers={"Content-Type": "application/json"},
        )

        result.raise_for_status()

        _store_success_info(service_config_id)
    except requests.RequestException as e:
        response = getattr(e, 'response', None)
        _store_failure_info(service_config_id, e, response)

    except Exception as e:
        _store_failure_info(service_config_id, e)


def _build_alert_data(issue, alert_reason, unmute_reason=None, milestone_reason=None, environment=None):
    issue_url = get_settings().BASE_URL + issue.get_absolute_url()
    title = truncatechars(issue.title().replace("|", ""), 150)
    link = f"<{issue_url}|view on Bugsink>"

    sections = [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": title,
                    },
                },
                {
                    "type": "section",
                    "text": {
                        "type": "plain_text",
                        "text": f"{alert_reason} issue",
                    },
                },
               ]

    for reason in [unmute_reason, milestone_reason]:
        if reason:
            sections.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": reason,
                },
            })

    # assumption: visavis email, project.name is of less importance, because in slack-like things you may (though not
    # always) do one-channel per project. more so for site_title (if you have multiple Bugsinks, you'll surely have
    # multiple slack channels)
    fields = {
        "project": issue.project.name
    }

    if environment:
        fields["environment"] = environment

    sections += [{"type": "section",
                  "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*{field}*: " + _safe_markdown(value),
                        } for field, value in fields.items()
                    ]}]

    sections += [{
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": link,
                    },
                }]

    # slack service-backend also support mattermost; mattermost requires at least one text field; use the first section
    return {"text": sections[0]["text"]["text"], "blocks": sections}


@shared_task
def slack_backend_send_alert(
        webhook_url, issue_id, state_description, alert_article, alert_reason, service_config_id, unmute_reason=None,
        milestone_reason=None, environment=None):

    issue = Issue.objects.get(id=issue_id)
    data = _build_alert_data(issue, alert_reason, unmute_reason, milestone_reason, environment)

    try:
        result = SlackBackend.safe_post(
            webhook_url,
            data=json.dumps(data),
            headers={"Content-Type": "application/json"},
        )

        result.raise_for_status()

        _store_success_info(service_config_id)
    except requests.RequestException as e:
        response = getattr(e, 'response', None)
        _store_failure_info(service_config_id, e, response)

    except Exception as e:
        _store_failure_info(service_config_id, e)


class SlackBackend(BaseWebhookBackend):
    def __init__(self, service_config):
        self.service_config = service_config

    @classmethod
    def get_form_class(cls):
        return SlackConfigForm

    def send_test_message(self):
        config = json.loads(self.service_config.config)
        slack_backend_send_test_message.delay(
            config["webhook_url"],
            self.service_config.project.name,
            self.service_config.display_name,
            self.service_config.id,
        )

    def send_alert(self, issue_id, state_description, alert_article, alert_reason, **kwargs):
        config = json.loads(self.service_config.config)
        slack_backend_send_alert.delay(
            config["webhook_url"],
            issue_id,
            state_description,
            alert_article,
            alert_reason,
            self.service_config.id,
            **kwargs,
        )


# The Slack bot backend below exists because incoming webhooks (see SlackConfigForm) cannot choose a channel: the
# channel is baked into the webhook by whoever installed the app. With a bot token (one per Bugsink installation, in
# the SLACK_BOT_TOKEN setting) the channel is ours to pick, which is what makes per-environment routing useful.

SLACK_POST_MESSAGE_URL = "https://slack.com/api/chat.postMessage"

CHANNEL_ID_RE = re.compile(r"[A-Z][A-Z0-9]{4,}")


class SlackBotConfigForm(forms.Form):
    channel_id = forms.CharField(
        required=True,
        strip=True,
        help_text='Channel ID to post to, e.g. "C0123456789" (in Slack: channel name > About > Channel ID). The bot '
                  'must be a member of the channel.',
    )

    def __init__(self, *args, **kwargs):
        config = kwargs.pop("config", None)

        super().__init__(*args, **kwargs)
        if config:
            self.fields["channel_id"].initial = config.get("channel_id", "")

    def get_config(self):
        return {
            "channel_id": self.cleaned_data.get("channel_id"),
        }

    def clean_channel_id(self):
        channel_id = self.cleaned_data["channel_id"]
        if not CHANNEL_ID_RE.fullmatch(channel_id):
            raise forms.ValidationError('Channel ID must look like "C0123456789" (not the channel name).')
        return channel_id

    def clean(self):
        if not get_settings().SLACK_BOT_TOKEN:
            raise forms.ValidationError(
                "SLACK_BOT_TOKEN is not configured for this Bugsink installation; ask your administrator to set it.")
        return super().clean()


def _post_as_bot(data, channel_id, service_config_id):
    # The token is read here rather than passed in as a task argument: task arguments are stored in the snappea queue
    # database, and a bot token has no business being there.
    token = get_settings().SLACK_BOT_TOKEN

    data["channel"] = channel_id

    try:
        if not token:
            raise ValueError("SLACK_BOT_TOKEN is not configured")

        result = SlackBotBackend.safe_post(
            SLACK_POST_MESSAGE_URL,
            data=json.dumps(data),
            headers={"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + token},
        )

        result.raise_for_status()

        # Slack answers 200 OK with {"ok": false, "error": "..."} for anything it doesn't like (unknown channel, bot
        # not in the channel, bad token), so the status code alone tells us nothing.
        answer = result.json()
        if not answer.get("ok"):
            raise ValueError("Slack said: %s" % answer.get("error", "(no error given)"))

        _store_success_info(service_config_id)
    except requests.RequestException as e:
        response = getattr(e, 'response', None)
        _store_failure_info(service_config_id, e, response)

    except Exception as e:
        _store_failure_info(service_config_id, e)


@shared_task
def slackbot_backend_send_test_message(channel_id, project_name, display_name, service_config_id):
    _post_as_bot(_build_test_data(project_name, display_name), channel_id, service_config_id)


@shared_task
def slackbot_backend_send_alert(
        channel_id, issue_id, state_description, alert_article, alert_reason, service_config_id, unmute_reason=None,
        milestone_reason=None, environment=None):

    issue = Issue.objects.get(id=issue_id)
    data = _build_alert_data(issue, alert_reason, unmute_reason, milestone_reason, environment)
    _post_as_bot(data, channel_id, service_config_id)


class SlackBotBackend(BaseWebhookBackend):
    def __init__(self, service_config):
        self.service_config = service_config

    @classmethod
    def get_form_class(cls):
        return SlackBotConfigForm

    def send_test_message(self):
        config = json.loads(self.service_config.config)
        slackbot_backend_send_test_message.delay(
            config["channel_id"],
            self.service_config.project.name,
            self.service_config.display_name,
            self.service_config.id,
        )

    def send_alert(self, issue_id, state_description, alert_article, alert_reason, **kwargs):
        config = json.loads(self.service_config.config)
        slackbot_backend_send_alert.delay(
            config["channel_id"],
            issue_id,
            state_description,
            alert_article,
            alert_reason,
            self.service_config.id,
            **kwargs,
        )
