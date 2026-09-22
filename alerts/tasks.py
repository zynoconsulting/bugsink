from snappea.decorators import shared_task

from django.template.defaultfilters import truncatechars

from projects.models import ProjectMembership
from teams.models import TeamMembership
from bugsink.app_settings import get_settings

from bugsink.utils import send_rendered_email


def _get_users_for_email_alert(issue):
    # _perhaps_ it's possible to make some super-smart 3-way join that does the below, but I'd say that "just doing it
    # with a (constant) few separate queries and some work in Python" is absolutely fine. (especially for something in
    # an async task)

    pms = list(
        ProjectMembership.objects.filter(
            project=issue.project, accepted=True, user__is_active=True,
        ).exclude(send_email_alerts=False).select_related("user"))
    user_ids = [pm.user_id for pm in pms]
    tms = {
        tm.user_id: tm
        for tm in TeamMembership.objects.filter(team=issue.project.team, user_id__in=user_ids, accepted=True)
    }
    for pm in pms:
        if pm.send_email_alerts is True:
            yield pm.user
        # elif pm.send_email_alerts is False:   # we do this with the .exclude in the above
        #     continue

        else:  # (pm.send_email_alerts is None)

            if pm.user_id in tms:

                if tms[pm.user_id].send_email_alerts is True:
                    yield pm.user
                elif tms[pm.user_id].send_email_alerts is False:
                    continue
                else:   # tm exists, but is set to None
                    if pm.user.send_email_alerts is True:
                        yield pm.user
                    elif pm.user.send_email_alerts is False:
                        continue

            else:  # no team-level definition
                if pm.user.send_email_alerts is True:
                    yield pm.user
                elif pm.user.send_email_alerts is False:
                    continue

                # there is no None at this level


def is_order_of_magnitude(event_count):
    """True when event_count is exactly a power of ten (10, 100, 1_000, ...), i.e. an order of magnitude was reached."""
    return event_count >= 10 and event_count == 10 ** (len(str(event_count)) - 1)


# The `environment` parameters below default to "" so that tasks queued by a previous version of Bugsink (which is to
# say: tasks that are still in the snappea queue across an upgrade) don't fail on an unexpected call signature.

@shared_task
def send_new_issue_alert(issue_id, environment=""):
    _send_alert(issue_id, "New issue", "a", "NEW", environment=environment)


@shared_task
def send_regression_alert(issue_id, environment=""):
    _send_alert(issue_id, "Regression", "a", "REGRESSED", environment=environment)


@shared_task
def send_unmute_alert(issue_id, unmute_reason, environment=""):
    _send_alert(issue_id, "Unmuted issue", "an", "UNMUTED", environment=environment, unmute_reason=unmute_reason)


@shared_task
def send_volume_milestone_alert(issue_id, event_count, environment=""):
    # Messaging services only (send_email=False): "this issue is an order of magnitude bigger than it was" is a
    # heads-up that belongs in a chat channel; it's not worth a separate mail to everyone on the project.
    _send_alert(
        issue_id, "Volume milestone", "a", "GROWING", environment=environment, send_email=False,
        milestone_reason="Reached %s events" % f"{event_count:,}")


def _matches_environment(service, environment):
    # A service without an environment gets everything; a service with one only gets that environment's alerts. Note
    # that this means alerts we cannot attribute to an environment (no environment on the triggering event) only reach
    # the "all environments" services, which is the desired reading of "this alert is not about your environment".
    return service.environment == "" or service.environment == environment


def _send_alert(issue_id, state_description, alert_article, alert_reason, environment="", send_email=True, **kwargs):
    # NOTE: as it stands, there is a bit of asymmetry here: _send_alert is always called in delayed fashion; it delays
    # some work itself (message backends) though not all (emails). I kept it like this to be able to add functionality
    # without breaking too much (in particular, I like the 3 entry points (send_xx_alert) in the current setup). The
    # present solution at least has the advantage that possibly frickle external calls don't break each other.
    # The way forward is probably to keep the single 3-way callpoint, but make that non-delayed, and do the calls of
    # both message-service and email based alerts in delayed fashion.

    from issues.models import Issue  # avoid circular import

    issue = Issue.objects.get(id=issue_id)

    for service in issue.project.service_configs.all():
        if not _matches_environment(service, environment):
            continue

        service_backend = service.get_backend()
        service_backend.send_alert(
            issue_id, state_description, alert_article, alert_reason, environment=environment, **kwargs)

    if not send_email:
        return

    for user in _get_users_for_email_alert(issue):
        send_rendered_email(
            subject=f'"{truncatechars(issue.title(), 80)}" in "{issue.project.name}" ({state_description})',
            base_template_name="mails/issue_alert",
            recipient_list=[user.email],
            context={
                "site_title": get_settings().SITE_TITLE,
                "base_url": get_settings().BASE_URL + "/",
                "issue_title": issue.title(),
                "project_name": issue.project.name,
                "issue_url": get_settings().BASE_URL + issue.get_absolute_url(),
                "state_description": state_description,
                "alert_article": alert_article,
                "alert_reason": alert_reason,
                "settings_url": get_settings().BASE_URL + "/accounts/preferences/",
                **kwargs,
            },
        )
