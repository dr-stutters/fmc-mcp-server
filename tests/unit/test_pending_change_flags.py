"""fmc_pending_changes masks secret-named fields, but a true/false value is a setting, not a secret.

W6N live-B (F77, FMC 10.0.1, 2026-10-21): the BGPIPv4Neighbor row of the t1 hub read "Send Community attribute
to this neighbor: ********" because 'Community' matches the SNMP-community pattern; the same row's "Generate
default routes: true" showed that FMC lists flags as the text true/false. Passwords, keys and communities
with a value keep being masked."""

import pytest

from fmc_mcp.tools.deploy import pending_row

# The neighbour row's shape (pendingchanges valueAdded entries are {fieldName, newValue}); field names as FMC
# listed them on the hub, the MD5 password's encrypted text made up.
NEIGHBOR = {
    "entityName": "192.0.2.2",
    "entityType": "BGPIPv4Neighbor",
    "action": "ADD",
    "valueAdded": [
        {"fieldName": "Generate default routes", "newValue": "true"},
        {"fieldName": "Send Community attribute to this neighbor", "newValue": "false"},
        {"fieldName": "Password", "newValue": "U2FsdGVkX1+encrypted"},
    ],
}


def test_flag_values_of_secret_named_fields_are_shown() -> None:
    row = pending_row(NEIGHBOR)
    assert row["changes"] == [
        "Generate default routes: true",
        "Send Community attribute to this neighbor: false",
        "Password: ********",
    ]


def test_an_updated_flag_shows_both_sides() -> None:
    row = pending_row(
        {
            "entityName": "192.0.2.2",
            "valueUpdated": [
                {
                    "fieldName": "Send Community attribute to this neighbor",
                    "oldValue": "false",
                    "newValue": "TRUE",
                }
            ],
        }
    )
    assert row["changes"] == ["Send Community attribute to this neighbor: false -> TRUE"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("SNMP Community", "c0mmun1ty"),
        ("Community String", "public"),
        ("Pre-shared Key", "s3cret-psk"),
        ("Secret", "12345"),  # a number can be a secret
    ],
)
def test_secrets_stay_masked(field: str, value: str) -> None:
    row = pending_row({"entityName": "x", "valueAdded": [{"fieldName": field, "newValue": value}]})
    assert row["changes"] == [f"{field}: ********"]


def test_empty_secret_values_stay_empty() -> None:
    row = pending_row(
        {"entityName": "x", "valueUpdated": [{"fieldName": "Password", "oldValue": "", "newValue": "abc"}]}
    )
    assert row["changes"] == ["Password:  -> ********"]


# Review of #308: only an allow-listed flag label shows true/false; any other secret-named field is masked
# whatever its value, a community, password or key that reads "false" or "true" included.
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("SNMP Community", "false"),
        ("SNMP Community", "true"),
        ("Community String", "false"),
        ("Community", "true"),
        ("Read Community", "TRUE"),
        ("Password", "true"),
        ("Pre-shared Key", "false"),
        ("Secret", "False"),
        ("Authentication Key", "true"),
        ("Send Community String to this neighbor", "false"),  # not the allow-listed label
        ("Password", True),
    ],
)
def test_flag_looking_values_of_other_secret_fields_stay_masked(field: str, value: object) -> None:
    row = pending_row({"entityName": "x", "valueAdded": [{"fieldName": field, "newValue": value}]})
    assert row["changes"] == [f"{field}: ********"]


def test_the_allow_listed_label_matches_without_case_or_extra_spaces() -> None:
    field = "send  community Attribute to this Neighbor"
    row = pending_row({"entityName": "x", "valueAdded": [{"fieldName": field, "newValue": "true"}]})
    assert row["changes"] == [f"{field}: true"]
    row = pending_row({"entityName": "x", "valueAdded": [{"fieldName": field, "newValue": "s3cr3t"}]})
    assert row["changes"] == [f"{field}: ********"]  # not a flag value: masked
