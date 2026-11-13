from django.conf import settings
from django.db import models
from django.utils.translation import gettext_lazy as _


class AccessBase(models.Model):
    user_agent = models.CharField(_("User Agent"), max_length=255, db_index=True)

    ip_address = models.GenericIPAddressField(_("IP Address"), null=True, db_index=True)

    username = models.CharField(_("Username"), max_length=255, null=True, db_index=True)

    http_accept = models.CharField(_("HTTP Accept"), max_length=1025)

    path_info = models.CharField(_("Path"), max_length=255)

    http_referer = models.CharField(
        _("HTTP Referer"), default="", blank=True, max_length=255
    )

    attempt_time = models.DateTimeField(_("Attempt Time"), auto_now_add=True)

    class Meta:
        app_label = "axes"
        abstract = True
        ordering = ["-attempt_time"]


class AccessFailureLog(AccessBase):
    locked_out = models.BooleanField(
        _("Access lock out"), null=False, blank=True, default=False
    )

    session_hash = models.CharField(
        _("Session key hash (sha256)"), default="", blank=True, max_length=64
    )

    def __str__(self):
        locked_out_str = " locked out" if self.locked_out else ""
        return f"Failed access: user {self.username}{locked_out_str} on {self.attempt_time} from {self.ip_address}"

    def get_related_success_log(self):
        """
        Return the successful AccessLog sharing the correlation fields.

        The session hash is the strongest correlation key; username and IP keep
        the lookup usable for anonymous or pre-session failures.
        """

        from axes.models import AccessLog

        queryset = AccessLog.objects.filter(
            username=self.username,
            ip_address=self.ip_address,
            attempt_time__gte=self.attempt_time,
        )
        if self.session_hash:
            matched = queryset.filter(session_hash=self.session_hash).first()
            if matched is not None:
                return matched
        return queryset.order_by("attempt_time").first()

    class Meta:
        verbose_name = _("access failure")
        verbose_name_plural = _("access failures")


class AccessAttempt(AccessBase):
    get_data = models.TextField(_("GET Data"))

    post_data = models.TextField(_("POST Data"))

    failures_since_start = models.PositiveIntegerField(_("Failed Logins"))

    def __str__(self):
        return f"Attempted Access: {self.attempt_time}"

    def is_locked_out(self) -> bool:
        """Return whether this attempt row alone crosses the failure limit."""

        failure_limit = settings.AXES_FAILURE_LIMIT
        if callable(failure_limit):
            try:
                resolved_limit = failure_limit(None, None)
            except TypeError:
                resolved_limit = failure_limit(request=None, credentials=None)
            return self.failures_since_start >= resolved_limit
        if isinstance(failure_limit, str):
            from django.utils.module_loading import import_string

            resolved_callable = import_string(failure_limit)
            try:
                resolved_limit = resolved_callable(None, None)
            except TypeError:
                resolved_limit = resolved_callable(
                    request=None, credentials=None
                )
            return self.failures_since_start >= resolved_limit
        return self.failures_since_start >= failure_limit

    def get_lockout_explanation(self) -> str:
        """Human-readable failure count and lockout state for audit views."""

        state = "locked out" if self.is_locked_out() else "not locked out"
        return (
            f"{self.failures_since_start} failed login(s), {state} "
            f"as of {self.attempt_time}"
        )

    def get_related_failure_logs(self):
        """Return the failure log rows explaining this attempt's counter."""

        from axes.models import AccessFailureLog

        return AccessFailureLog.objects.filter(
            username=self.username,
            ip_address=self.ip_address,
            user_agent=self.user_agent,
        ).order_by("attempt_time")

    class Meta:
        verbose_name = _("access attempt")
        verbose_name_plural = _("access attempts")
        unique_together = [["username", "ip_address", "user_agent"]]


class AccessAttemptExpiration(models.Model):
    access_attempt = models.OneToOneField(
        AccessAttempt,
        primary_key=True,
        on_delete=models.CASCADE,
        related_name="expiration",
        verbose_name=_("Access Attempt"),
    )
    expires_at = models.DateTimeField(
        _("Expires At"),
        help_text=_("The time when access attempt expires and is no longer valid."),
    )

    class Meta:
        verbose_name = _("access attempt expiration")
        verbose_name_plural = _("access attempt expirations")


class AccessLog(AccessBase):
    logout_time = models.DateTimeField(_("Logout Time"), null=True, blank=True)
    session_hash = models.CharField(
        _("Session key hash (sha256)"), default="", blank=True, max_length=64
    )

    def __str__(self):
        return f"Access Log for {self.username} @ {self.attempt_time}"

    class Meta:
        verbose_name = _("access log")
        verbose_name_plural = _("access logs")
