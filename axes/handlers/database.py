from datetime import datetime, timedelta
from logging import getLogger
from typing import List, Optional

from django.db import router, transaction
from django.db.models import F, Q, QuerySet, Sum, Value
from django.db.models.functions import Concat
from django.http import HttpRequest
from django.http import QueryDict
from django.http.multipartparser import MultiPartParserError
from django.utils import timezone

from axes.attempts import get_cool_off_threshold
from axes.conf import settings
from axes.handlers.base import AbstractAxesHandler, AxesBaseHandler
from axes.helpers import (
    get_client_parameters,
    get_client_http_referer,
    get_client_session_hash,
    get_client_str,
    get_client_username,
    get_credentials,
    get_failure_limit,
    get_lockout_parameters,
    get_query_str,
    get_attempt_expiration,
    sanitize_request_payload,
)
from axes.models import (
    AccessAttempt,
    AccessAttemptExpiration,
    AccessFailureLog,
    AccessLog,
)
from axes.signals import user_locked_out

log = getLogger(__name__)


class AxesDatabaseHandler(AbstractAxesHandler, AxesBaseHandler):
    """
    Signal handler implementation that records user login attempts to database and locks users out if necessary.

    .. note:: The get_user_attempts function is called several time during the authentication and lockout
              process, caching its output can be dangerous.
    """

    def reset_attempts(
        self,
        *,
        ip_address: Optional[str] = None,
        username: Optional[str] = None,
        ip_or_username: bool = False,
    ) -> int:
        attempts = AccessAttempt.objects.all()

        if ip_or_username:
            attempts = attempts.filter(Q(ip_address=ip_address) | Q(username=username))
        else:
            if ip_address:
                attempts = attempts.filter(ip_address=ip_address)
            if username:
                attempts = attempts.filter(username=username)

        count, _ = attempts.delete()
        log.info("AXES: Reset %d access attempts from database.", count)

        return count

    def reset_logs(self, *, age_days: Optional[int] = None) -> int:
        if age_days is None:
            count, _ = AccessLog.objects.all().delete()
            log.info("AXES: Reset all %d access logs from database.", count)
        else:
            limit = timezone.now() - timedelta(days=age_days)
            count, _ = AccessLog.objects.filter(attempt_time__lte=limit).delete()
            log.info(
                "AXES: Reset %d access logs older than %d days from database.",
                count,
                age_days,
            )

        return count

    def reset_failure_logs(self, *, age_days: Optional[int] = None) -> int:
        if age_days is None:
            count, _ = AccessFailureLog.objects.all().delete()
            log.info("AXES: Reset all %d access failure logs from database.", count)
        else:
            limit = timezone.now() - timedelta(days=age_days)
            count, _ = AccessFailureLog.objects.filter(attempt_time__lte=limit).delete()
            log.info(
                "AXES: Reset %d access failure logs older than %d days from database.",
                count,
                age_days,
            )

        return count

    def remove_out_of_limit_failure_logs(
        self,
        *,
        username: str,
        limit: Optional[int] = settings.AXES_ACCESS_FAILURE_LOG_PER_USER_LIMIT,
    ) -> int:
        count = 0
        failures = AccessFailureLog.objects.filter(username=username)
        out_of_limit_failures_logs = failures.count() - limit
        if out_of_limit_failures_logs > 0:
            for failure in failures[:out_of_limit_failures_logs]:
                failure.delete()
                count += 1
        return count

    def apply_retention_policy(
        self, *, now: Optional[datetime] = None
    ) -> List[dict]:
        """
        Apply the age based retention policy to every configured log category.

        The operation is opt-in (``settings.AXES_RETENTION_ENABLED``) and
        idempotent: rerunning it only deletes rows that still cross the age
        threshold. Audit entries contain a category, reason and count but never
        any deleted row content. Database errors are reported in the audit list
        instead of propagating so a cleanup failure can not break login flows.
        """

        audit: List[dict] = []
        if not settings.AXES_RETENTION_ENABLED:
            log.debug("AXES: Retention policy is disabled, skipping cleanup.")
            return audit

        reference_time = now or timezone.now()
        category_models = {
            "failure": AccessFailureLog,
            "success": AccessLog,
            "attempt": AccessAttempt,
        }

        for category, model in category_models.items():
            age_days = settings.AXES_RETENTION_DAYS.get(category)
            if age_days is None:
                continue
            try:
                age_days = int(age_days)
                if age_days < 0:
                    raise ValueError("retention age must be zero or positive")
                cutoff = reference_time - timedelta(days=age_days)
                count, _ = model.objects.filter(attempt_time__lte=cutoff).delete()
            except (TypeError, ValueError) as error:
                log.exception(
                    "AXES: Retention policy configuration is invalid for category %s: %s",
                    category,
                    error.__class__.__name__,
                )
                audit.append(
                    {
                        "category": category,
                        "reason": "invalid_configuration",
                        "count": 0,
                        "error": error.__class__.__name__,
                    }
                )
                continue
            except Exception as error:  # pylint: disable=broad-except
                log.exception(
                    "AXES: Retention cleanup failed for category %s: %s",
                    category,
                    error.__class__.__name__,
                )
                audit.append(
                    {
                        "category": category,
                        "reason": "delete_failed",
                        "count": 0,
                        "error": error.__class__.__name__,
                    }
                )
                continue

            reason = f"age_over_{age_days}_days"
            log.info(
                "AXES: Retention policy deleted %d %s log record(s) (%s).",
                count,
                category,
                reason,
            )
            audit.append(
                {"category": category, "reason": reason, "count": count}
            )

        return audit

    def _safe_apply_retention_policy(
        self, *, now: Optional[datetime] = None
    ) -> None:
        """Run retention cleanup while guaranteeing login flow isolation."""

        try:
            self.apply_retention_policy(now=now)
        except Exception as error:  # pylint: disable=broad-except
            log.exception(
                "AXES: Retention policy aborted without affecting login flow: %s",
                error.__class__.__name__,
            )

    @staticmethod
    def _minimum_field(value: Optional[str]) -> str:
        """
        Project a metadata field down to the minimum value needed for joins.

        Under field projection the log rows keep only correlation fields
        (username/IP/user agent/session hash); descriptive metadata is dropped
        rather than stored. The legacy behaviour keeps the supplied value.
        """

        if settings.AXES_LOG_FIELD_PROJECTION_ENABLED:
            return ""
        return value or ""

    @staticmethod
    def _project_request_data(query: QueryDict) -> str:
        """Return sanitized JSON when projection is enabled, legacy text otherwise."""

        if settings.AXES_LOG_FIELD_PROJECTION_ENABLED:
            return sanitize_request_payload(query).replace("\0", "0x00")
        return get_query_str(query).replace("\0", "0x00")

    def get_failures(self, request, credentials: Optional[dict] = None) -> int:
        attempts_list = self.get_user_attempts(request, credentials)
        attempt_count = max(
            (
                attempts.aggregate(Sum("failures_since_start"))[
                    "failures_since_start__sum"
                ]
                or 0
            )
            for attempts in attempts_list
        )
        return attempt_count

    def user_login_failed(self, sender, credentials: dict, request=None, **kwargs):
        """
        When user login fails, save AccessFailureLog record in database,
        save AccessAttempt record in database, mark request with
        lockout attribute and emit lockout signal.
        """

        log.info("AXES: User login failed, running database handler for failure.")

        if request is None:
            log.error(
                "AXES: AxesDatabaseHandler.user_login_failed does not function without a request."
            )
            return

        # 1. database query: Clean up expired user attempts from the database before logging new attempts
        self.clean_expired_user_attempts(request, credentials)

        # Retention is best-effort: a pruning failure must never block sign-in.
        self._safe_apply_retention_policy()

        username = get_client_username(request, credentials)
        client_str = get_client_str(
            username,
            request.axes_ip_address,
            request.axes_user_agent,
            request.axes_path_info,
            request,
        )

        # If axes denied access, don't record the failed attempt as that would reset the lockout time.
        if (
            not settings.AXES_RESET_COOL_OFF_ON_FAILURE_DURING_LOCKOUT
            and request.axes_locked_out
        ):
            request.axes_credentials = credentials
            user_locked_out.send(
                "axes",
                request=request,
                username=username,
                ip_address=request.axes_ip_address,
            )
            return

        # This replaces null byte chars that crash saving failures. When field
        # projection is enabled the payload is sanitized recursively instead.
        get_data = self._project_request_data(request.GET)
        try:
            post_data = self._project_request_data(request.POST)
        except MultiPartParserError as ex:
            post_data = (
                f'Could not access "request.POST": {ex.__class__.__name__}: {ex}'
            )

        if self.is_whitelisted(request, credentials):
            log.info("AXES: Login failed from whitelisted client %s.", client_str)
            return

        # 2. database query: Get or create access record with the new failure data
        lockout_parameters = get_lockout_parameters(request, credentials)
        if lockout_parameters == ["username"] and username is None:
            log.warning(
                "AXES: Username is None and username is the only one lockout parameter, new record will NOT be created."
            )
        else:
            with transaction.atomic(using=router.db_for_write(AccessAttempt)):
                (
                    attempt,
                    created,
                ) = AccessAttempt.objects.select_for_update().get_or_create(
                    username=username,
                    ip_address=request.axes_ip_address,
                    user_agent=request.axes_user_agent,
                    defaults={
                        "get_data": get_data,
                        "post_data": post_data,
                        "http_accept": request.axes_http_accept,
                        "path_info": request.axes_path_info,
                        "http_referer": get_client_http_referer(request),
                        "failures_since_start": 1,
                        "attempt_time": request.axes_attempt_time,
                    },
                )

                # Record failed attempt with all the relevant information.
                # Filtering based on username, IP address and user agent handled elsewhere,
                # and this handler just records the available information for further use.
                if created:
                    log.warning(
                        "AXES: New login failure by %s. Created new record in the database.",
                        client_str,
                    )

                # 3. database query if there were previous attempts in the database
                # Update failed attempt information but do not touch the username, IP address, or user agent fields,
                # because attackers can request the site with multiple different configurations
                # in order to bypass the defense mechanisms that are used by the site.
                else:
                    if settings.AXES_LOG_FIELD_PROJECTION_ENABLED:
                        # Keep the latest bounded, parseable projection instead
                        # of concatenating payloads into an ever growing field.
                        attempt.get_data = get_data
                        attempt.post_data = post_data
                    else:
                        separator = "\n---------\n"

                        attempt.get_data = Concat(
                            "get_data", Value(separator + get_data)
                        )
                        attempt.post_data = Concat(
                            "post_data", Value(separator + post_data)
                        )
                    attempt.http_accept = request.axes_http_accept
                    attempt.path_info = request.axes_path_info
                    attempt.failures_since_start = F("failures_since_start") + 1
                    attempt.attempt_time = request.axes_attempt_time
                    attempt.save()

                    log.warning(
                        "AXES: Repeated login failure by %s. Updated existing record in the database.",
                        client_str,
                    )

                if settings.AXES_USE_ATTEMPT_EXPIRATION:
                    if not hasattr(attempt, "expiration") or attempt.expiration is None:
                        log.debug(
                            "AXES: Creating new AccessAttemptExpiration for %s",
                            client_str,
                        )
                        attempt.expiration = AccessAttemptExpiration.objects.create(
                            access_attempt=attempt,
                            expires_at=get_attempt_expiration(request),
                        )
                    else:
                        attempt.expiration.expires_at = max(
                            get_attempt_expiration(request),
                            attempt.expiration.expires_at,
                        )
                        attempt.expiration.save()

        # 3. or 4. database query: Calculate the current maximum failure number from the existing attempts
        failures_since_start = self.get_failures(request, credentials)
        request.axes_failures_since_start = failures_since_start

        if (
            settings.AXES_LOCK_OUT_AT_FAILURE
            and failures_since_start >= get_failure_limit(request, credentials)
        ):
            log.warning(
                "AXES: Locking out %s after repeated login failures.", client_str
            )

            request.axes_locked_out = True
            request.axes_credentials = credentials
            user_locked_out.send(
                "axes",
                request=request,
                username=username,
                ip_address=request.axes_ip_address,
            )

        # 5. database entry: Log for ever the attempt in the AccessFailureLog
        if settings.AXES_ENABLE_ACCESS_FAILURE_LOG:
            with transaction.atomic(using=router.db_for_write(AccessFailureLog)):
                AccessFailureLog.objects.create(
                    username=username,
                    ip_address=request.axes_ip_address,
                    user_agent=request.axes_user_agent,
                    http_accept=self._minimum_field(request.axes_http_accept),
                    path_info=self._minimum_field(request.axes_path_info),
                    http_referer=self._minimum_field(get_client_http_referer(request)),
                    attempt_time=request.axes_attempt_time,
                    locked_out=request.axes_locked_out,
                    session_hash=get_client_session_hash(request),
                )
                self.remove_out_of_limit_failure_logs(username=username)

    def user_logged_in(self, sender, request, user, **kwargs):
        """
        When user logs in, update the AccessLog related to the user.
        """

        username = user.get_username()
        credentials = get_credentials(username)
        client_str = get_client_str(
            username,
            request.axes_ip_address,
            request.axes_user_agent,
            request.axes_path_info,
            request,
        )

        log.info("AXES: Successful login by %s.", client_str)

        # 1. database query: Clean up expired user attempts from the database
        self.clean_expired_user_attempts(request, credentials)

        # Best-effort age based cleanup, isolated from the login transaction.
        self._safe_apply_retention_policy()

        if not settings.AXES_DISABLE_ACCESS_LOG:
            # 2. database query: Insert new access logs with login time
            AccessLog.objects.create(
                username=username,
                ip_address=request.axes_ip_address,
                user_agent=request.axes_user_agent,
                http_accept=self._minimum_field(request.axes_http_accept),
                path_info=self._minimum_field(request.axes_path_info),
                http_referer=self._minimum_field(
                    get_client_http_referer(request)
                ),
                attempt_time=request.axes_attempt_time,
                # evaluate session hash here to ensure having the correct
                # value which is stored on the backend
                session_hash=get_client_session_hash(request),
            )

        if settings.AXES_RESET_ON_SUCCESS:
            # 3. database query: Reset failed attempts for the logging in user
            count = self.reset_user_attempts(request, credentials)
            log.info(
                "AXES: Deleted %d failed login attempts by %s from database.",
                count,
                client_str,
            )

    def user_logged_out(self, sender, request, user, **kwargs):
        """
        When user logs out, update the AccessLog related to the user.
        """

        username = user.get_username() if user else None
        credentials = get_credentials(username) if username else None
        client_str = get_client_str(
            username,
            request.axes_ip_address,
            request.axes_user_agent,
            request.axes_path_info,
            request,
        )

        # 1. database query: Clean up expired user attempts from the database
        self.clean_expired_user_attempts(request, credentials)

        log.info("AXES: Successful logout by %s.", client_str)

        if username and not settings.AXES_DISABLE_ACCESS_LOG:
            # 2. database query: Update existing attempt logs with logout time
            AccessLog.objects.filter(
                username=username,
                logout_time__isnull=True,
                # update only access log for given session
                session_hash=get_client_session_hash(request),
            ).update(logout_time=request.axes_attempt_time)

    def filter_user_attempts(
        self, request: HttpRequest, credentials: Optional[dict] = None
    ) -> List[QuerySet]:
        """
        Return a list querysets of AccessAttempts that match the given request and credentials.
        """

        username = get_client_username(request, credentials)

        filter_kwargs_list = get_client_parameters(
            username,
            request.axes_ip_address,
            request.axes_user_agent,
            request,
            credentials,
        )
        attempts_list = [
            AccessAttempt.objects.filter(**filter_kwargs)
            for filter_kwargs in filter_kwargs_list
        ]
        return attempts_list

    def get_user_attempts(
        self, request: HttpRequest, credentials: Optional[dict] = None  # noqa
    ) -> List[QuerySet]:
        """
        Get list of querysets with valid user attempts that match the given request and credentials.
        """

        attempts_list = self.filter_user_attempts(request, credentials)

        if settings.AXES_COOLOFF_TIME is None:
            log.debug(
                "AXES: Getting all access attempts from database because no AXES_COOLOFF_TIME is configured"
            )
            return attempts_list

        threshold = get_cool_off_threshold(request)
        log.debug("AXES: Getting access attempts that are newer than %s", threshold)
        return [
            attempts.filter(attempt_time__gte=threshold) for attempts in attempts_list
        ]

    def clean_expired_user_attempts(
        self,
        request: Optional[HttpRequest] = None,
        credentials: Optional[dict] = None,  # noqa
    ) -> int:
        """
        Clean expired user attempts from the database.
        """

        if settings.AXES_COOLOFF_TIME is None:
            log.debug(
                "AXES: Skipping clean for expired access attempts because no AXES_COOLOFF_TIME is configured"
            )
            return 0

        if settings.AXES_USE_ATTEMPT_EXPIRATION:
            threshold = timezone.now()
            count, _ = AccessAttempt.objects.filter(
                expiration__expires_at__lte=threshold
            ).delete()
            log.info(
                "AXES: Cleaned up %s expired access attempts from database that expiry were older than %s",
                count,
                threshold,
            )
        else:
            threshold = get_cool_off_threshold(request)
            count, _ = AccessAttempt.objects.filter(
                attempt_time__lte=threshold
            ).delete()
            log.info(
                "AXES: Cleaned up %s expired access attempts from database that were older than %s",
                count,
                threshold,
            )
        return count

    def reset_user_attempts(
        self, request: HttpRequest, credentials: Optional[dict] = None
    ) -> int:
        """
        Reset all user attempts that match the given request and credentials.
        """

        attempts_list = self.filter_user_attempts(request, credentials)

        count = 0
        for attempts in attempts_list:
            _count, _ = attempts.delete()
            count += _count
        log.info("AXES: Reset %s access attempts from database.", count)

        return count

    def post_save_access_attempt(self, instance, **kwargs):
        """
        Handles the ``axes.models.AccessAttempt`` object post save signal.

        When needed, all post_save actions for this backend should be located
        here.
        """

    def post_delete_access_attempt(self, instance, **kwargs):
        """
        Handles the ``axes.models.AccessAttempt`` object post delete signal.

        When needed, all post_delete actions for this backend should be located
        here.
        """
