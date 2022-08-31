import json
from fnmatch import fnmatch

import panther_event_type_helpers as event_type
from panther_base_helpers import get_binding_deltas
from panther_analysis_tool.enriched_event import PantherEvent
from panther_base_helpers import deep_get

ADMIN_ROLES = {
    # Primitive Rolesx
    "roles/owner",
    # Predefined Roles
    "roles/*Admin",
}


def get_event_type(event):
    # currently, only tracking a handful of event types
    for delta in get_binding_deltas(event):
        if delta["action"] == "ADD":
            if any(
                (
                    fnmatch(delta.get("role", ""), admin_role_pattern)
                    for admin_role_pattern in ADMIN_ROLES
                )
            ):
                return event_type.ADMIN_ROLE_ASSIGNED

    return None


def get_admin_map(event):
    roles_assigned = {}
    for delta in get_binding_deltas(event):
        if delta.get("action") == "ADD":
            roles_assigned[delta.get("member")] = delta.get("role")

    return roles_assigned


def get_modified_users(event):
    roles_assigned = get_admin_map(event)

    return json.dumps(list(roles_assigned.values()), default=PantherEvent.json_encoder)


def get_iam_roles(event):
    roles_assigned = get_admin_map(event)

    return json.dumps(list(roles_assigned.keys()), default=PantherEvent.json_encoder)

def get_resource_tags(event):
    """
    Returns a list of resource tags like pod, cluster, namespace

    Suppressions could allow exceptions for if a string matches any tag
    """
    resource_tags = []
    for path in [
        ['resource', 'labels', 'cluster_name'],
        ['resource','labels','pod_name'],
        ['resource','labels','container_name'],
        ['resource','labels','location'],
        ['resource','type']
        ]:
        value = deep_get(event, *path)
        if value:
            resource_tags.append(value)
    
    return resource_tags
