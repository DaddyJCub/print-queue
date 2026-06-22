# Print agent — security & network isolation

The agent runs at a **remote site** (next to the printer) and connects back toward
your network. This page is about the obvious worry: *if that remote network — or
the Pi itself — is compromised, can it pivot into my home network?* The short
answer is **no, if you apply the one ACL/firewall rule below** — and the design
already minimises the surface.

---

## Why the blast radius is small by design

- **Outbound-only.** The agent only makes outbound HTTPS calls to the server. It
  opens **no inbound ports** for the server side.
- **Pull-based management.** "Restart", "Reboot", "Update", "Flash", "Send file"
  are all queued on the server and the agent **polls** for them. Your network
  never dials into the Pi — so the Pi needs zero inbound reachability from home.
- **Authenticated + revocable.** Each agent has its own bearer token over TLS;
  revoke it from the Print Agents page and it's dead immediately.
- **Least privilege.** The agent runs as a normal user (not root) under a
  hardened systemd unit (see below).

The consequence: **the agent only ever needs to reach the print server on 443.**
Lock the tailnet to exactly that and a remote compromise has nowhere to go.

---

## Is Tailscale required?

**No — not for the agent↔server channel to be secure.** Provisioning, heartbeats,
jobs, remote management and OTA all run over **HTTPS with a per-agent bearer
token**. If your server has a public HTTPS endpoint with a valid certificate
(e.g. `print.jcubhub.com`), the agent connects securely from anywhere with no
Tailscale at all. Security there rests on TLS + the token + admin login, not on
the network path.

Use Tailscale/Headscale when you want one or more of:

- **Keep the server off the public internet** — don't expose the web app at all;
  the agent reaches it privately over the tailnet. (This is the biggest win.)
- **Reach the device page (`:7130`) remotely** — otherwise it's only on the
  printer's LAN.
- **Network-layer defense in depth** — confine the agent with an ACL so a remote
  compromise can't pivot (the rest of this page).

Rule of thumb: **public HTTPS server → Tailscale optional. Private/unexposed
server, or you want remote device-page access → use Tailscale.** Since you already
run Headscale + pfSense, keeping the server private behind the tailnet is a clean,
low-effort upgrade — but the agent is not insecure without it.

---

## 1. The control that matters — confine the agent to the server

### If the agent is on the tailnet (Headscale ACL)

Tag the agent and allow it to reach **only** the server. The guided-setup install
command already runs `tailscale up --advertise-tags=tag:print-agent`, so you just
need the matching ACL policy in Headscale:

```jsonc
{
  "tagOwners": {
    "tag:print-agent": ["your-headscale-user"]
  },
  "acls": [
    // The agent may reach ONLY the print server on 443 — nothing else.
    { "action": "accept", "src": ["tag:print-agent"], "dst": ["<server-tailscale-ip>:443"] },

    // (Optional) let YOUR admin devices open the agent's device page.
    { "action": "accept", "src": ["your-headscale-user"], "dst": ["tag:print-agent:7130"] }
  ]
}
```

Because there is **no rule** allowing `tag:print-agent` to reach your home subnets,
a compromised agent simply cannot route there. (Default-deny is the whole point —
don't add a broad `*` rule.)

Create the tagged pre-auth key:

```bash
headscale preauthkeys create --user your-headscale-user --reusable --expiration 24h
# then on the Pi:  tailscale up --login-server https://headscale.jcubhub.com \
#                    --advertise-tags=tag:print-agent --authkey <KEY>
```

### If you route via pfSense (subnet-router mode)

Don't advertise your whole LAN to the remote site. On pfSense, add a firewall rule
on the tailnet interface so the remote source can reach **only** the server:

- **Pass**: source = remote site/agent, dest = `‹server-ip›`, port = `443`
- **Block**: source = remote site/agent, dest = `‹your-LAN-subnets›` (RFC1918)

Put the block first/last as your rule order requires so anything other than the
server is denied.

---

## 2. Don't widen the Pi's reach

On the agent, **do not**:

- make it an **exit node** (`--advertise-exit-node`),
- **advertise routes** from it (`--advertise-routes`),
- **accept routes/DNS** you don't need (`--accept-routes` stays off by default).

The agent is a leaf node that talks to one server. Keep it that way.

---

## 3. The device page (printer control surface)

`http://‹agent›:7130` is the local device UI. Anyone who can reach it can drive the
printer (upload G-code, move axes, set temps). That's a **printer-safety** surface,
not a network-pivot one, but still:

- **Set an API key.** The guided setup generates `local_ui.api_key` for you and
  bakes it into `config.json`; mutating actions and slicer uploads require it.
- **Limit who can reach it.** Either keep it to the printer's LAN, or set
  `local_ui.host` to the Tailscale interface IP so it's only reachable over the
  tailnet (then the ACL above decides who). Set `local_ui.enabled: false` to turn
  it off entirely.

---

## 4. Host hardening (already applied by the wizard)

The generated systemd unit sandboxes the agent process:

```ini
PrivateTmp=true
ProtectSystem=full
ProtectControlGroups=true
ProtectKernelTunables=true
ProtectKernelModules=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
```

Plus the basics you should keep:

- Run the agent as a **non-root** user (the unit does).
- Keep Pi OS patched: `sudo apt update && sudo apt -y upgrade` (or unattended-upgrades).
- **SSH key-only**, no password login; change the default password.
- Only install what you need (avrdude only if you actually flash firmware; the
  `reboot` sudoers entry only if you use remote reboot).

> Note: the optional `NoNewPrivileges=true` directive is even stronger but blocks
> `sudo`, so it would break the remote **Reboot Pi** command and firmware flashing.
> Add it to the unit only if you don't use those.

---

## Quick checklist

- [ ] Headscale ACL (or pfSense rule) limits the agent to `‹server›:443` only.
- [ ] No rule lets the agent reach your home subnets.
- [ ] Agent is **not** an exit node and advertises **no** routes.
- [ ] `local_ui.api_key` is set (guided setup does this).
- [ ] Pi OS patched, SSH key-only, default password changed.
- [ ] Token revocation tested from the Print Agents page.
