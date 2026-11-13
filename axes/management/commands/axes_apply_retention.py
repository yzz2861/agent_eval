from django.core.management.base import BaseCommand

from axes.handlers.proxy import AxesProxyHandler


class Command(BaseCommand):
    help = "Apply the age based Axes log retention policy and print an audit."

    def handle(self, *args, **options):
        audit = AxesProxyHandler.apply_retention_policy()
        if not audit:
            self.stdout.write(
                "Retention policy disabled or no categories configured."
            )
            return
        for entry in audit:
            line = (
                f"{entry['category']}: {entry['count']} record(s) deleted "
                f"({entry['reason']})"
            )
            if "error" in entry:
                line += f" [{entry['error']}]"
            self.stdout.write(line)
