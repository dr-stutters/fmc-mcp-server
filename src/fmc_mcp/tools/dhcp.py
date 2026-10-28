"""DHCP on FTD interfaces (F94): the DHCP server (address pools per interface, and the DNS, domain, lease
and auto-config settings every pool hands out) and DHCP relay (relay agents on client interfaces, the
servers they forward to). Small-branch designs use the FTD as the branch LAN's DHCP server, or relay to a
central one.

FMC keeps both as one settings object per device: devicerecords/{id}/dhcp/dhcpserver/{id} and
.../dhcp/dhcprelaysettings/{id} (the id is the device's; FMC 10.0.1 answers a device with nothing
configured with just {type: DHCPServerSettings | DHCPRelaySettings, id}). They are read, changed and put
back whole: never POSTed. Changes reach the FTD with the next fmc_deploy.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import copy
import ipaddress
from collections.abc import Awaitable, Callable
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field

from fmc_mcp._core import (
    Confirm,
    InvalidRequest,
    Plan,
    ToolRegistrar,
    UpstreamError,
    get_client,
)
from fmc_mcp._core.writes import field_changes
from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview
from fmc_mcp.tools.common import Domain, ref_label, ref_of, resolve_object
from fmc_mcp.tools.device_config import (
    InterfaceRef,
    device_interfaces,
    network_by_value,
    pick_interface,
    resolve_device,
    static_network,
)
from fmc_mcp.tools.devices import DEVICES, DeviceRef
from fmc_mcp.tools.object_writes import editable

SERVER = "dhcp/dhcpserver"
RELAY = "dhcp/dhcprelaysettings"
# Interface kinds a DHCP server pool or relay agent can sit on (named, routed data interfaces).
DHCP_KINDS = ["physical", "subinterface", "etherchannel", "vlan", "bridge_group"]
LEASE_MIN, LEASE_MAX = 300, 1_048_575  # seconds, the FTD's 'dhcpd lease' range
MAX_RELAY_SERVERS = 10  # the FTD takes up to ten relay servers in all (four per interface)
MAX_POOL = 256  # the FTD's per-pool address limit (Device Configuration Guide, DHCP server guidelines)
HOST_PREFIX = "dhcp-"  # host objects this tool creates for server IPs no host object has


# --- reading ------------------------------------------------------------------------------------


async def singleton(app: FmcApp, dev_id: str, sub: str, domain: str | None) -> tuple[str, dict[str, Any]]:
    """(item path, current settings) for one of the device's DHCP settings objects."""
    base = await app.config_path(f"{DEVICES}/{dev_id}/{sub}", domain)
    page = await app.all(base, expanded=False)
    oid = (page.items[0].get("id") if page.items else None) or dev_id
    path = f"{base}/{oid}"
    cur = await app.api.get(path)
    return path, dict(cur or {"id": oid})


def dhcp_summary(
    server: dict[str, Any] | None,
    relay: dict[str, Any] | None,
    names: dict[str, str] | None = None,
) -> dict[str, Any] | None:
    """The device's DHCP server pools and relay settings in plain fields, or None when neither is set.
    `names`: interface id -> logical name (FMC's references may carry only the id)."""
    names = names or {}

    def iface(ref: Any) -> str | None:
        if not isinstance(ref, dict):
            return None
        return names.get(str(ref.get("id"))) or ref.get("name") or ref.get("id")

    out: dict[str, Any] = {}
    s = server or {}
    pools = [
        {
            "interface": iface(p.get("interface")),
            "pool": p.get("addressPool")
            or (f"variable {ref_label(p['addressPoolVariable'])}" if p.get("addressPoolVariable") else None),
            "enabled": p.get("enableDHCP"),
        }
        for p in s.get("dhcpServers") or []
    ]
    srv = {
        "pools": pools,
        "dns_servers": [ref_label(s[k]) for k in ("primaryDNSServer", "secondaryDNSServer") if s.get(k)],
        "wins_servers": [ref_label(s[k]) for k in ("primaryWINSServer", "secondaryWINSServer") if s.get(k)],
        "search_domain": s.get("searchDomain"),
        "lease_seconds": int(s["leaseLengthInSec"])
        if str(s.get("leaseLengthInSec") or "").isdigit()
        else None,
        "ping_timeout_ms": s.get("pingTimeoutInMs"),
        "auto_config_interface": iface(s.get("autoConfigInterface")),
        "options": [str(o.get("optionCode")) for o in s.get("dhcpOptions") or []],
    }
    srv = {k: v for k, v in srv.items() if v not in (None, "", [])}
    if srv:
        out["server"] = srv
    r = relay or {}
    agents = [
        {
            "interface": iface(a.get("interface")),
            "ipv4": a.get("enableDHCPIPv4Relay"),
            "ipv6": a.get("enableDHCPIPv6Relay"),
            "set_route": a.get("setRoute"),
        }
        for a in r.get("dhcpRelayAgent") or []
    ]
    rel = {
        "agents": [{k: v for k, v in a.items() if v is not None} for a in agents],
        "servers": [
            {"server": ref_label(x.get("server") or {}), "interface": iface(x.get("interface"))}
            for x in r.get("dhcpRelayServers") or []
        ],
        "ipv4_timeout_seconds": r.get("ipv4TimeoutInSec"),
        "trust_all_information": r.get("trustAllInformation"),
    }
    rel = {k: v for k, v in rel.items() if v not in (None, "", [])}
    if agents or rel.get("servers"):
        out["relay"] = rel
    return out or None


async def device_dhcp(app: FmcApp, device: dict[str, Any], domain: str | None) -> dict[str, Any] | None:
    """dhcp_summary for a device record, read from FMC; None when nothing is set or the model has no
    DHCP settings (404/405)."""
    dev_id = str(device["id"])
    found: dict[str, dict[str, Any]] = {}
    for key, sub in (("server", SERVER), ("relay", RELAY)):
        try:
            found[key] = (await singleton(app, dev_id, sub, domain))[1]
        except UpstreamError as e:
            if e.status_code not in (404, 405):
                raise
    if not any(_configured(v) for v in found.values()):
        return None
    names: dict[str, str] = {}
    try:
        for _, i in await device_interfaces(app, dev_id, domain, DHCP_KINDS):
            names[str(i.get("id"))] = str(i.get("ifname") or hw_name(i))
    except UpstreamError:
        pass
    return dhcp_summary(found.get("server"), found.get("relay"), names)


def _configured(obj: dict[str, Any]) -> bool:
    return any(k not in ("id", "type", "links", "metadata", "name", "version") for k in obj)


# --- planning -----------------------------------------------------------------------------------


def parse_pool(value: str) -> tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]:
    try:
        a, b = (ipaddress.IPv4Address(x.strip()) for x in value.split("-", 1))
    except ValueError:
        raise InvalidRequest(f"Pool {value!r}: give an IPv4 range 'a.b.c.d-a.b.c.e'.") from None
    if int(a) > int(b):
        raise InvalidRequest(f"Pool {value!r}: the first address is after the last.")
    return a, b


def pool_blockers(pool: str, net: ipaddress.IPv4Interface | None, label: str) -> list[str]:
    """Why a pool can't go on an interface: no static address, outside the interface subnet, the
    interface's own address, the network or broadcast address, or bigger than the FTD allows."""
    a, b = parse_pool(pool)
    if net is None:
        return [f"{label} has no static IPv4 address; a DHCP server pool needs one (fmc_update_interface)."]
    out = []
    subnet = net.network
    if a not in subnet or b not in subnet:
        out.append(f"Pool {a}-{b} is not inside {label}'s subnet {subnet}.")
    elif subnet.prefixlen < 31 and (a == subnet.network_address or b == subnet.broadcast_address):
        out.append(f"Pool {a}-{b} includes the network or broadcast address of {subnet}.")
    if int(a) <= int(net.ip) <= int(b):
        out.append(f"Pool {a}-{b} includes {label}'s own address {net.ip}.")
    if int(b) - int(a) + 1 > MAX_POOL:
        out.append(f"Pool {a}-{b} has {int(b) - int(a) + 1} addresses; the FTD allows {MAX_POOL} per pool.")
    return out


def hw_name(i: dict[str, Any]) -> str:
    """An interface's hardware name as FMC lists it: a subinterface is its parent's name + '.' +
    subIntfId (Ethernet0/0.3020); the interface record itself names only the parent."""
    name = str(i.get("name") or "")
    if i.get("subIntfId") is not None and "." not in name:
        name = f"{name}.{i['subIntfId']}"
    return name


def iface_ref(i: dict[str, Any]) -> dict[str, Any]:
    """An interface reference in a DHCP body. FMC 10.0 names the interface by its hardware name there
    (Ethernet0/3, Ethernet0/0.3020) and refuses the logical name with 400 "Invalid 'name' ... for
    Interface"; its own GET of the settings returns the hardware name too."""
    return {"id": i["id"], "type": i.get("type"), "name": hw_name(i)}


def same_iface(ref: Any, i: dict[str, Any]) -> bool:
    """Whether a DHCP body's interface reference is this interface: by id, else by its hardware name or
    its logical name (older bodies and FMC releases carry the logical one). A subinterface's bare parent
    name (Ethernet0/0) is the parent's, not the subinterface's."""
    if not isinstance(ref, dict):
        return False
    if ref.get("id") and i.get("id"):
        return str(ref["id"]).lower() == str(i["id"]).lower()
    want = str(ref.get("name", "")).lower()
    return bool(want) and want in {str(i.get("ifname") or "").lower(), hw_name(i).lower()}


Placeholder = dict[str, Any]  # a host object to create on confirm: {name, type, value}


async def host_ref(
    app: FmcApp, value: str, purpose: str, domain: str | None
) -> tuple[dict[str, Any], Placeholder | None, str]:
    """(reference, host object to create or None, its IP) for a server given as an IPv4 address or a
    host object name. An IP no host object has becomes `dhcp-<purpose>-<ip>`, created on confirm."""
    v = value.strip()
    try:
        ip = str(ipaddress.IPv4Address(v))
    except ValueError:
        _, obj = await resolve_object(app, v, domain, ["host"])
        return ref_of(obj), None, str(obj.get("value") or "")
    found = await network_by_value(app, ip, domain)
    if found is not None and found.get("type") == "Host":
        return {"id": found["id"], "type": "Host", "name": found.get("name")}, None, ip
    name = f"{HOST_PREFIX}{purpose}-{ip}"
    return {"type": "Host", "name": name}, {"name": name, "type": "Host", "value": ip}, ip


def fill_hosts(body: Any, made: dict[str, dict[str, Any]]) -> Any:
    """`body` with each placeholder reference (a Host by name, no id) replaced by the created object."""
    if isinstance(body, dict):
        if body.get("type") == "Host" and not body.get("id") and body.get("name") in made:
            return made[str(body["name"])]
        return {k: fill_hosts(v, made) for k, v in body.items()}
    if isinstance(body, list):
        return [fill_hosts(v, made) for v in body]
    return body


def put_body(cur: dict[str, Any], desired: dict[str, Any]) -> dict[str, Any]:
    body = editable(desired)
    body.setdefault("id", cur.get("id"))
    body.setdefault("type", cur.get("type"))
    return body


# --- the tool -----------------------------------------------------------------------------------


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Configure DHCP server / relay")
    async def fmc_configure_dhcp(
        ctx: Context,
        device: DeviceRef,
        interface: Annotated[
            InterfaceRef, Field(description="The client-side interface (logical name, e.g. inside)")
        ],
        mode: Annotated[
            Literal["server", "relay", "off"],
            Field(
                description="server: a DHCP pool on the interface; relay: forward its clients' requests to "
                "relay_servers; off: remove the interface's pool and relay agent"
            ),
        ] = "server",
        pool: Annotated[
            str | None,
            Field(description="Server mode: the address range 'a.b.c.d-a.b.c.e' inside the interface subnet"),
        ] = None,
        dns_servers: Annotated[
            list[str] | None,
            Field(
                max_length=2,
                description="Server mode, device-wide: DNS servers handed out (IPv4 or host object names; "
                "primary first). An IP no host object has becomes host 'dhcp-dns-<ip>'. [] clears them",
            ),
        ] = None,
        search_domain: Annotated[
            str | None,
            Field(max_length=63, description="Server mode, device-wide: domain name handed out ('' clears)"),
        ] = None,
        lease_seconds: Annotated[
            int | None,
            Field(
                ge=LEASE_MIN,
                le=LEASE_MAX,
                description="Server mode, device-wide: lease length (default 3600)",
            ),
        ] = None,
        auto_config_interface: Annotated[
            str | None,
            Field(
                description="Server mode, device-wide: take DNS/WINS/domain from the DHCP or PPPoE client "
                "on this interface (usually outside); 'none' clears. Explicit dns_servers / search_domain "
                "win over it"
            ),
        ] = None,
        relay_servers: Annotated[
            list[str] | None,
            Field(
                max_length=4,
                description="Relay mode: DHCP servers (IPv4 or host object names); an IP no host object has "
                "becomes host 'dhcp-relay-<ip>'",
            ),
        ] = None,
        server_interface: Annotated[
            str | None,
            Field(
                description="Relay mode: the interface the relay servers are reached through (default: the "
                "interface whose subnet holds the server, else required)"
            ),
        ] = None,
        set_route: Annotated[
            bool,
            Field(description="Relay mode: the relay replies' default router is the interface address"),
        ] = False,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """DHCP on an FTD data interface, the branch-LAN way: mode='server' puts an address pool on the
        interface (with the DNS servers, domain, lease and auto-config the device hands out with every
        pool); mode='relay' makes it a DHCP relay agent forwarding to central servers; mode='off' removes
        the interface's pool and relay agent. The preview refuses a pool outside the interface subnet or
        holding its own address, and server and relay on one interface (switch with mode='off' first).
        Takes effect after fmc_deploy; check with fmc_run_show_command('show dhcpd state' / 'show dhcpd
        binding'). fmc_get_device and fmc_export_device_config show the current DHCP settings."""
        app: FmcApp = get_client(ctx)
        server_only = (pool, dns_servers, search_domain, lease_seconds, auto_config_interface)
        if mode != "server" and any(v is not None for v in server_only):
            raise InvalidRequest(
                "pool, dns_servers, search_domain, lease_seconds and auto_config_interface are server-mode "
                "settings."
            )
        if mode != "relay" and (relay_servers or server_interface or set_route):
            raise InvalidRequest("relay_servers, server_interface and set_route are relay-mode settings.")
        dev = await resolve_device(app, device, domain)
        label_dev = str(dev.get("name"))
        items = await device_interfaces(app, str(dev["id"]), domain, DHCP_KINDS)
        _, iface = pick_interface(items, interface, label_dev)
        if not iface.get("ifname"):
            raise InvalidRequest(
                f"{iface.get('name')} has no logical name; name it first (fmc_update_interface)."
            )
        label = f"{iface.get('ifname')} ({hw_name(iface)})"
        names = {str(i.get("id")): str(i.get("ifname") or hw_name(i)) for _, i in items}
        s_path, s_cur = await singleton(app, str(dev["id"]), SERVER, domain)
        r_path, r_cur = await singleton(app, str(dev["id"]), RELAY, domain)
        server = copy.deepcopy(editable(s_cur))
        relay = copy.deepcopy(editable(r_cur))
        pools = [dict(p) for p in server.get("dhcpServers") or []]
        agents = [dict(a) for a in relay.get("dhcpRelayAgent") or []]
        servers = [dict(x) for x in relay.get("dhcpRelayServers") or []]
        my_pool = next((p for p in pools if same_iface(p.get("interface"), iface)), None)
        my_agent = next((a for a in agents if same_iface(a.get("interface"), iface)), None)
        blockers: list[str] = []
        notes: list[str] = []
        create: list[Placeholder] = []

        if mode == "server":
            if my_agent is not None and my_agent.get("enableDHCPIPv4Relay", True):
                blockers.append(
                    f"{label} is a DHCP relay agent; an interface can't be DHCP server and relay. Remove "
                    "the relay first: fmc_configure_dhcp(mode='off') on it."
                )
            if pool is None and my_pool is None:
                raise InvalidRequest(f"Give the pool for {label} ('a.b.c.d-a.b.c.e').")
            if pool is not None:
                blockers += pool_blockers(pool, static_network(iface), label)
                a, b = parse_pool(pool)
                for p in pools:
                    if p is my_pool or not p.get("addressPool"):
                        continue
                    try:
                        pa, pb = parse_pool(str(p["addressPool"]))
                    except InvalidRequest:
                        continue
                    if int(a) <= int(pb) and int(pa) <= int(b):
                        blockers.append(
                            f"Pool {a}-{b} overlaps the pool {pa}-{pb} on "
                            f"{ref_label(p.get('interface') or {})}."
                        )
                entry = {"interface": iface_ref(iface), "addressPool": f"{a}-{b}", "enableDHCP": True}
                if my_pool is None:
                    pools.append(entry)
                else:
                    my_pool.pop("addressPoolVariable", None)
                    my_pool.update(entry)
            elif my_pool is not None:
                my_pool["enableDHCP"] = True
            server["dhcpServers"] = pools
            if dns_servers is not None:
                for k in ("primaryDNSServer", "secondaryDNSServer"):
                    server.pop(k, None)
                for k, v in zip(("primaryDNSServer", "secondaryDNSServer"), dns_servers, strict=False):
                    ref, ph, _ = await host_ref(app, v, "dns", domain)
                    server[k] = ref
                    if ph:
                        create.append(ph)
            if search_domain is not None:
                if search_domain.strip():
                    server["searchDomain"] = search_domain.strip()
                else:
                    server.pop("searchDomain", None)
            if lease_seconds is not None:
                server["leaseLengthInSec"] = str(lease_seconds)
            if auto_config_interface is not None:
                if auto_config_interface.strip().lower() in ("none", ""):
                    server.pop("autoConfigInterface", None)
                else:
                    _, auto = pick_interface(items, auto_config_interface, label_dev)
                    if same_iface(iface_ref(auto), iface):
                        blockers.append("auto_config_interface must be another interface than the pool's.")
                    elif not {"dhcp", "pppoe"} & set(auto.get("ipv4") or {}):
                        notes.append(
                            f"{auto.get('ifname') or auto.get('name')} is not a DHCP/PPPoE client; "
                            "auto-config learns nothing from a static interface."
                        )
                    server["autoConfigInterface"] = iface_ref(auto)
        elif mode == "relay":
            if my_pool is not None and my_pool.get("enableDHCP", True):
                blockers.append(
                    f"{label} has a DHCP server pool ({my_pool.get('addressPool')}); an interface can't be "
                    "DHCP server and relay. Remove the pool first: fmc_configure_dhcp(mode='off') on it."
                )
            if not relay_servers and not servers:
                raise InvalidRequest("Give relay_servers (the central DHCP servers).")
            if static_network(iface) is None:
                blockers.append(f"{label} has no static IPv4 address; a DHCP relay agent needs one.")
            via: dict[str, Any] | None = None
            if server_interface:
                _, via = pick_interface(items, server_interface, label_dev)
                if same_iface(iface_ref(via), iface):
                    blockers.append("server_interface must be another interface than the client side.")
            for v in relay_servers or []:
                ref, ph, ip = await host_ref(app, v, "relay", domain)
                if ph:
                    create.append(ph)
                out = via
                if out is None:
                    out = next(
                        (
                            i
                            for _, i in items
                            if static_network(i) is not None
                            and _in(ip, static_network(i))
                            and i.get("ifname")
                        ),
                        None,
                    )
                if out is None:
                    blockers.append(
                        f"No interface's subnet holds the relay server {v}; give server_interface (the "
                        "interface it is routed through)."
                    )
                    continue
                if same_iface(iface_ref(out), iface):
                    blockers.append(
                        f"The relay server {v} is on {label} itself; relay needs another interface."
                    )
                    continue
                exists = any(
                    _same_server(x.get("server") or {}, ref) and same_iface(x.get("interface"), out)
                    for x in servers
                )
                if not exists:
                    servers.append({"interface": iface_ref(out), "server": ref})
            if len(servers) > MAX_RELAY_SERVERS:
                blockers.append(f"The FTD takes at most {MAX_RELAY_SERVERS} DHCP relay servers.")
            agent = {
                "interface": iface_ref(iface),
                "enableDHCPIPv4Relay": True,
                "enableDHCPIPv6Relay": bool((my_agent or {}).get("enableDHCPIPv6Relay", False)),
                "setRoute": set_route,
            }
            if my_agent is None:
                agents.append(agent)
            else:
                my_agent.update(agent)
            relay["dhcpRelayAgent"] = agents
            relay["dhcpRelayServers"] = servers
        else:  # off
            if my_pool is None and my_agent is None:
                blockers.append(f"{label} has no DHCP server pool or relay agent; nothing to remove.")
            pools = [p for p in pools if p is not my_pool]
            agents = [a for a in agents if a is not my_agent]
            server["dhcpServers"] = pools
            relay["dhcpRelayAgent"] = agents
            if not agents and servers:
                relay["dhcpRelayServers"] = []
                notes.append("No relay agent is left, so the relay servers are removed too.")

        for cur, want in ((s_cur, server), (r_cur, relay)):
            for k in ("dhcpServers", "dhcpRelayAgent", "dhcpRelayServers"):
                if want.get(k) == [] and not cur.get(k):  # nothing there before: leave the field out
                    want.pop(k, None)
        s_changes = field_changes(editable(s_cur), server, replace=True)
        r_changes = field_changes(editable(r_cur), relay, replace=True)
        if not s_changes and not r_changes and not blockers:
            blockers.append("Nothing to change.")
        s_body, r_body = put_body(s_cur, server), put_body(r_cur, relay)

        async def apply() -> dict[str, Any]:
            made: dict[str, dict[str, Any]] = {}
            done: list[str] = []
            steps: list[tuple[str, Callable[[], Awaitable[Any]]]] = []
            hosts_path = await app.config_path("object/hosts", domain)
            for ph in create:

                async def mk(ph: Placeholder = ph) -> None:
                    obj = await app.api.post(hosts_path, ph)
                    made[ph["name"]] = {
                        "id": obj["id"],
                        "type": "Host",
                        "name": obj.get("name") or ph["name"],
                    }

                steps.append((f"host {ph['name']}", mk))
            # Off / relay frees the interface's pool before relay is added, and the relay before a pool.
            order = [("relay", r_changes, r_path, r_body), ("server", s_changes, s_path, s_body)]
            if mode == "relay":
                order.reverse()
            for name, changes, path, body in order:
                if changes:

                    async def put(path: str = path, body: dict[str, Any] = body) -> None:
                        await app.api.put(path, fill_hosts(body, made))

                    steps.append((f"dhcp {name}", put))
            try:
                for step, fn in steps:
                    try:
                        await fn()
                    except Exception as e:
                        rest = [n for n, _ in steps][len(done) :]
                        raise UpstreamError(
                            f"Step {step!r} failed ({e}). Applied: {done or 'none'}; not applied: {rest}. "
                            "Check with fmc_get_device, then repeat the call.",
                            getattr(e, "status_code", None),
                        ) from e
                    done.append(step)
            finally:
                app.invalidate_cache()
            return {
                "device": label_dev,
                "applied": done,
                "dhcp": dhcp_summary(fill_hosts(s_body, made), fill_hosts(r_body, made), names),
                "next": f"fmc_deploy to {label_dev}, then fmc_run_show_command('show dhcpd state')",
            }

        after = dhcp_summary(s_body, r_body, names)
        return await fmc_preview(
            ctx,
            tool="fmc_configure_dhcp",
            args={
                "device": device,
                "interface": interface,
                "mode": mode,
                "pool": pool,
                "dns_servers": dns_servers,
                "search_domain": search_domain,
                "lease_seconds": lease_seconds,
                "auto_config_interface": auto_config_interface,
                "relay_servers": relay_servers,
                "server_interface": server_interface,
                "set_route": set_route,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"DHCP {mode} on {label_dev} {label}",
                details={
                    "server_changes": s_changes or None,
                    "relay_changes": r_changes or None,
                    "after": after,
                    "creates_host_objects": create or None,
                    "notes": notes or None,
                },
                fingerprint={"server": s_cur, "relay": r_cur},
                blockers=blockers,
                side_effects=[
                    "DNS, domain, lease and auto-config are device-wide: every pool on the device hands "
                    "them out."
                    if mode == "server"
                    else "Clients on the interface stop getting addresses this way after the deploy."
                    if mode == "off"
                    else "Relayed requests need a route to the servers and the servers' scope for the "
                    "interface subnet.",
                    f"Takes effect on {label_dev} after the next deployment.",
                ],
                blast_radius=1,
            ),
            apply=apply,
        )


def _in(ip: str, net: ipaddress.IPv4Interface | None) -> bool:
    try:
        return net is not None and ipaddress.IPv4Address(ip) in net.network
    except ValueError:
        return False


def _same_server(a: dict[str, Any], b: dict[str, Any]) -> bool:
    if a.get("id") and b.get("id"):
        return str(a["id"]).lower() == str(b["id"]).lower()
    return str(a.get("name", "")).lower() == str(b.get("name", "")).lower()
