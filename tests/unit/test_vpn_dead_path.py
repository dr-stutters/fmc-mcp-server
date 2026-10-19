"""F41/F49 live proof (mcp-fw-t1, dead WAN on a spoke): fmc_vpn_status when a tunnel is down and the IKEv2
counters don't move within a minute or two, the growth window kept over 15 minutes, and FMC's empty
tunneldetails. The lab and helpers are test_vpn_status's."""

import time
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from fmc_mcp.tools import sdwan_status

from .test_vpn_status import lab, run, server


@pytest.fixture(autouse=True)
def _fresh_ike_counters() -> Any:
    sdwan_status._IKE_SEEN.clear()
    yield
    sdwan_status._IKE_SEEN.clear()


# `show crypto ikev2 stats` on a spoke whose WAN link was down (F41/F49 live proof, mcp-fw-t1): two readings
# ~5 minutes apart. The spoke retried IKE once between them; within a 1-2 minute window nothing grew.
DEAD_WAN_STATS = (
    "Active Tunnels:                          0\n"
    "Previous Tunnels:                        3\n"
    "System Capacity Failures:                0\n"
    "Authentication Failures:                 0\n"
    "Decrypt Failures:                        0\n"
    "Hash Failures:                           0\n"
    "Previous Tunnels:                        3\n"
    "Previous Tunnels Wraps:                  0\n"
    "Retransmit limit exceeded:               2\n"
    "Last clearing time: Never\n"
    "Last cleared: Never\n"
)
DEAD_WAN_STATS_LATER = DEAD_WAN_STATS.replace(
    "Retransmit limit exceeded:               2\n",
    "Retransmit limit exceeded:               3\nInitial exchange failed:                 1\n",
)


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def monotonic(self) -> float:
        return self.now

    def time(self) -> float:
        return time.time()


async def test_dead_wan_quiet_window_is_not_reported_as_no_failures(
    fmc: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Live: two calls 73 s apart said only 'no IKEv2 failures in the last 73 s', and the prompt sent that
    to 'compare the IKE policies'. A quiet window now says it proves little, gives the counters so far and
    sends to the path first; a later call compares with every reading of the last 15 minutes."""
    clock = _Clock()
    monkeypatch.setattr(sdwan_status, "time", clock)
    outputs: dict[str, dict[str, str]] = {"d-a": {"show crypto ikev2 stats": DEAD_WAN_STATS}}
    lab(fmc, outputs=outputs)

    def reasons(r: dict[str, Any]) -> list[str]:
        down = next(d for d in r["degraded"] if d["what"] == "tunnel" and d["topology"] == "mcp-fw-pb")
        return [x for x in down["reasons"] if x.startswith("branch-a: ") and "IKE SA" not in x]

    async with Client(server()) as c:
        await run(c, "fmc_vpn_status", {"topology": "mcp-fw-pb"})
        clock.now += 73
        [quiet] = reasons(await run(c, "fmc_vpn_status", {"topology": "mcp-fw-pb"}))
        assert "no new IKEv2 failures in the last 73 s" in quiet and "doesn't rule out a dead path" in quiet
        assert "Retransmit limit exceeded 2" in quiet and "Authentication Failures 0" in quiet
        assert "the path is the likelier cause, not the key" in quiet
        assert "ping the peer's WAN address and the WAN gateway" in quiet and "up/up" in quiet
        # the spoke retries once in the next minutes: seen against the previous call ...
        clock.now += 133
        outputs["d-a"]["show crypto ikev2 stats"] = DEAD_WAN_STATS_LATER
        [retry] = reasons(await run(c, "fmc_vpn_status", {"topology": "mcp-fw-pb"}))
        assert "the peer doesn't answer" in retry
        # ... and, a minute later with nothing new, still against the first reading (266 s ago)
        clock.now += 60
        r = await run(c, "fmc_vpn_status", {"topology": "mcp-fw-pb"})
    [still] = reasons(r)
    assert "the peer doesn't answer" in still
    ike = next(d for d in r["devices"] if d["device"] == "branch-a")["ikev2"]
    assert ike["since_last_check"] == {
        "seconds": 266,
        "authentication_failures": 0,
        "retransmit_limit_exceeded": 1,
        "initial_exchange_failed": 1,
    }


def test_ike_growth_horizon_and_clear(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = _Clock()
    monkeypatch.setattr(sdwan_status, "time", clock)
    a = {"authentication_failures": 0, "retransmit_limit_exceeded": 2, "initial_exchange_failed": 0}
    b = {**a, "retransmit_limit_exceeded": 3}
    assert sdwan_status.ike_growth("d", a) is None
    clock.now += 60
    assert sdwan_status.ike_growth("d", b)["retransmit_limit_exceeded"] == 1  # type: ignore[index]
    clock.now += sdwan_status.IKE_HORIZON_S + 1  # both readings too old: nothing to compare with
    assert sdwan_status.ike_growth("d", b) is None
    clock.now += 60
    cleared = {**a, "retransmit_limit_exceeded": 0}
    assert sdwan_status.ike_growth("d", cleared) is None  # counters cleared in between
    clock.now += 60
    assert sdwan_status.ike_growth("d", cleared) == {
        "seconds": 60,
        "authentication_failures": 0,
        "retransmit_limit_exceeded": 0,
        "initial_exchange_failed": 0,
    }


async def test_tunnel_details_without_peer_data_say_so(fmc: respx.MockRouter) -> None:
    """Live: FMC 10.0.1 answered tunneldetails for an up SD-WAN tunnel with nothing for either peer, and
    the row showed `fmc_details: {}` with no reason."""
    lab(fmc)
    fmc.get(url__regex=r".*/health/tunnelstatuses/[^/]+/tunneldetails").mock(
        return_value=httpx.Response(200, json={"paging": {"offset": 0, "limit": 0, "count": 0, "pages": 0}})
    )
    async with Client(server()) as c:
        r = await run(c, "fmc_vpn_status", {"tunnel_details": True})
    details = [t["fmc_details"] for topo in r["topologies"] for t in topo["tunnels"] if "fmc_details" in t]
    assert details and all(isinstance(d, str) and "no data for either peer" in d for d in details)


def test_tunnel_down_cause_on_the_live_readings() -> None:
    """The two ends' `ikev2` blocks as fmc_vpn_status returned them live (second call, 133 s after the first):
    the spoke (initiator, WAN link down) and the hub, whose authentication failures were left over from the
    wrong-PSK test an hour before."""
    quiet = {
        "seconds": 133,
        "authentication_failures": 0,
        "retransmit_limit_exceeded": 0,
        "initial_exchange_failed": 0,
    }
    spoke = {
        "active_tunnels": 0,
        "authentication_failures": 0,
        "initial_exchange_failed": 1,
        "retransmit_limit_exceeded": 3,
        "sas_locally_initiated_failed": 1,
        "counters_since": "never cleared",
        "since_last_check": quiet,
    }
    hub = {**spoke, "active_tunnels": 2, "authentication_failures": 9, "initial_exchange_failed": 0}
    hub["retransmit_limit_exceeded"] = 4
    said = str(sdwan_status.tunnel_down_cause(spoke, "fmc_vpn_status"))
    assert said.startswith("no new IKEv2 failures in the last 133 s, which doesn't rule out a dead path")
    assert "Retransmit limit exceeded 3, Initial exchange failed 1, Authentication Failures 0" in said
    assert "the path is the likelier cause" in said and said.endswith("to catch the next attempt")
    assert "fmc_vpn_status again in a few minutes" in said
    hub_said = str(sdwan_status.tunnel_down_cause(hub, "fmc_vpn_status"))
    assert "Authentication Failures 9" in hub_said and "likelier cause" not in hub_said
    assert "Check the path to the peer first" in hub_said
