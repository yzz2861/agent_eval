"""STIX data markings used by the offline release gate."""

from stix2 import CustomMarking
from stix2.properties import ListProperty, StringProperty

AUTHORIZATION_MARKING_TYPE = "x-investigation-authorization"
RELEASE_PURPOSE = "external-release"
APPROVED_STATUS = "approved"

# Conclusion scopes mirror the two review cells:
# - entity-attribute: only entity property assertions may be produced
# - relationship: derived links/associations may be produced
SCOPE_ENTITY_ATTRIBUTE = "entity-attribute"
SCOPE_RELATIONSHIP = "relationship"


@CustomMarking(
    AUTHORIZATION_MARKING_TYPE,
    [
        ("x_authorization_id", StringProperty(required=True)),
        ("x_permitted_purposes", ListProperty(StringProperty(), required=True)),
        ("x_scope", ListProperty(StringProperty(), required=True)),
        ("x_status", StringProperty(required=True)),
    ],
)
class InvestigationAuthorization:
    """Original investigation authorization carried as a STIX marking.

    A marking is usable for outbound release only when it simultaneously:
    * is approved (``x_status == "approved"``),
    * lists the release purpose in ``x_permitted_purposes``, and
    * covers the conclusion scope in ``x_scope``.
    """

    def permits(self, purpose, scope):
        return (
            self.x_status == APPROVED_STATUS
            and purpose in self.x_permitted_purposes
            and scope in self.x_scope
        )
