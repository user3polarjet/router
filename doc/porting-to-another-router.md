# Building a typed, self-tested client for a TP-Link router, and repeating it on another one

This document records how the client in this repository was built for one router (TP-Link Archer C6 v2.0,
firmware 1.3.2 Build 20201126) and, more importantly, **the method**, so that another model or engineer can
repeat the process on a different router without redoing the research.

The method has four ideas. Everything else in this file is detail in service of them.

1. **Take the protocol from a reference implementation, not from guesswork.** One reverse-engineered Python
   client already describes how these routers log in and talk. Read it, port only the path your router uses.
2. **Discover the API by asking the router, read-only.** Do not trust the reference for *what endpoints and
   fields exist*. Probe the live device, save the real payloads, and design from them.
3. **Type strictly, then let the router prove the types.** Model every payload as a struct. Write tests that
   fetch the live payload, deserialize it, serialize it back and compare it to the raw JSON. Every mismatch is a
   fact about the router that your model got wrong.
4. **Never change router state while learning.** Learning is read-only by construction (see section 3).

Contents

1. [Result and layout](#1-result-and-layout)
2. [Step 0: pick the reference client and the right protocol branch](#2-step-0-pick-the-reference-client-and-the-right-protocol-branch)
3. [Safety rules for working against a real device](#3-safety-rules-for-working-against-a-real-device)
4. [The transport layer: how the protocol works](#4-the-transport-layer-how-the-protocol-works)
5. [Discovery: asking the router what it has](#5-discovery-asking-the-router-what-it-has)
6. [Strong typing: turning payloads into types](#6-strong-typing-turning-payloads-into-types)
7. [Tests: the router is the oracle](#7-tests-the-router-is-the-oracle)
8. [What the tests taught us (worked examples)](#8-what-the-tests-taught-us-worked-examples)
9. [Write operations](#9-write-operations)
10. [Playbook for a new router](#10-playbook-for-a-new-router)
11. [Pitfalls and tooling notes](#11-pitfalls-and-tooling-notes)
12. [Known gaps](#12-known-gaps)
13. [Appendix: facts about the Archer C6 v2 firmware 1.3.2](#13-appendix-facts-about-the-archer-c6-v2-firmware-132)
14. [Using the typed API to diagnose a real problem](#14-using-the-typed-api-to-diagnose-a-real-problem)

---

## 1. Result and layout

A Rust crate (library plus CLI) that logs in to the router's web API, reads everything the web UI can show,
and can change a defined set of settings. Style rules for this repository are in `doc/rust-style.md`
(no comments, no `use` inside code, data-oriented structs and free functions, enums over traits).

```
src/lib.rs        module list
src/crypto.rs     AES-128-CBC, RSA PKCS#1 v1.5, request signature       (protocol, router-family specific)
src/session.rs    handshake, login, request/response, logout, typed fetch helpers
src/scalar.rs     strict scalar types: Switch, YesNo, Mac, Ipv6Net, Channel, status enums, serde helpers
src/api.rs        one struct per discovered endpoint, field names exactly as the router sends them   (router specific)
src/router.rs     views built on top of the typed payloads (Status with merged client list), Topic enum, show()
src/changes.rs    write operations with validation and read-back verification
src/config.rs     secret.toml loader, default-gateway detection from /proc/net/route
src/diagnose.rs   read-only health analysis: DHCP log, pool/lease config, WAN, radio, CPU/traffic     (section 14)
src/watch.rs      long-running watcher that prints only changes (joins, IP jumps, conflicts, WAN)     (section 14)
src/main.rs       clap CLI
examples/discover.rs   read-only endpoint prober that saves masked payloads to disk                      (router specific list)
tests/live.rs     the real test suite: runs against the router
```

What is **portable across routers of the same login family** (`crypto`, `session`, `scalar`, `config`, most of
`changes`) and what is **router specific** (`api.rs`, the endpoint table in `router.rs::show`, the form list in
`discover.rs`, the assertions in `tests/live.rs`) is the central fact for porting. A new router of the same
family means: re-run discovery, regenerate `api.rs`, adjust tests. A different family means a new `crypto` and
`session::login` too.

CLI surface (all reads unless noted):

```
show <topic>            firmware internet system-mode time ipv4 ipv6 wan-ipv4 wan-ipv6 wan-pppoe lan-ipv4
                        lan-ipv6 dhcp-server leases reservations forwards access-control remote-admin ddns
                        nat vpn syslog
status                  merged view: WAN/LAN, CPU/memory, every client with connection type and packet counters
wifi [band]             host2g host5g guest2g guest5g
all                     everything above; a failing section becomes {"error": ...} instead of aborting
raw <path> [operation]  any endpoint, decrypted `data` block, untyped. The exploration tool.
diagnose [--samples N --interval S --json]   one-shot health report with findings by severity
watch [--interval S --minutes N]            print only changes: JOINED/LEFT/IP JUMP/CONFLICT/WAN IP/INTERNET/CPU/DHCP
reboot | wifi-set | reservation add/update/delete | forward add/update/delete | dhcp | wan   (writes)
```

Credentials come from `--password` / `ROUTER_PASSWORD`, else `secret.toml` (`ip`, `password`, `username`; the
file is git-ignored). If no IP is given the default gateway is read from `/proc/net/route`.

---

## 2. Step 0: pick the reference client and the right protocol branch

The reference is the Python library `TP-Link-Archer-C6U` (vendored under `doc/TP-Link-Archer-C6U/`). It supports
about thirty router families through one class per family. **Do not port all of it.** Port exactly the class
that matches your device, plus whatever it inherits.

How to choose the class:

* Look at `tplinkrouterc6u/provider.py`. `get_clients()` lists every client class; `get_client()` tries each
  one's `supports()` in turn. `discovery.py` documents the *login-free fingerprint* used to tell families apart:
  the RSA key size served by `/cgi-bin/luci/;stok=/login?form=keys` (256 hex chars = 1024-bit = classic LuCI,
  512+ = newer firmware) and `form=auth`. You can run that fingerprint yourself with plain `curl -X POST` against
  the router without sending any credentials.
* Match model and hardware/firmware version against the README "supported routers" list and against the class
  docstrings. For this device (C6 v2.0, fw 1.3.2, 2020) the right class was `TplinkRouter` in `client/c6u.py`:
  `TplinkEncryption` (AES + RSA login) mixed with `TplinkRouterJson` (JSON request bodies) over
  `TplinkBaseRouter` (the endpoint catalogue).
* A device with newer firmware (about 1.11+, 2048-bit password key) would instead use `TplinkRouterV1_11`
  (RSA only, no AES layer). Other families (MR, EX, VR, Deco, ...) use different URL schemes and ciphers
  (AES-GCM, ECIES). If your device is one of those, the transport section below does **not** apply and you
  must read the matching `client/*.py` and `common/encryption.py` class instead.

**Read the class hierarchy and the method resolution order, not just the method you want.** The single most
expensive trap in this protocol: `TplinkRouter` inherits `TplinkEncryption` *before* `TplinkRouterJson`, so
`_prepare_data` is the encrypting one, and **the login request body is AES-encrypted and signed too**, even
though `_get_login_data` returns a plain `operation=login&password=...` string. Reading only `_try_login` makes
it look like a plain form post. Always ask "which override wins?" before porting a method.

What to copy from the reference and what to distrust:

| Take from the reference | Verify on the device |
|---|---|
| Login handshake, cipher, signature construction | Whether it works at all (one `firmware` call proves it) |
| URL scheme (`/cgi-bin/luci/;stok=<token>/<path>`) | - |
| Endpoint paths as starting candidates | Whether each exists and what it returns |
| Field names as starting hints | Everything. Names, types and presence differ per firmware |
| Quirks documented in docstrings (full-table inserts reporting success, etc.) | Only matters for writes |

---

## 3. Safety rules for working against a real device

These were followed throughout and are the reason it was acceptable to run an automated prober on a home
router. Keep them.

1. **Reads only while learning.** The only operations sent during discovery and in the test suite are
   `read`, `load` and `list`. Writes exist in the CLI but have never been invoked by the tests.
2. **Deny-list in the prober.** `examples/discover.rs` skips any candidate whose path contains `reboot`,
   `logout`, `upgrade_start`, `restore`, `factory`, `reset`, `backup`, `ping`, `trace`, `renew`, `release`.
   Some "read-looking" endpoints start actions (a ping or traceroute form, a firmware check). When in doubt,
   leave the candidate out.
3. **One session per run.** Home routers commonly cap simultaneous web sessions (a precaution; the cap on this
   device was never measured). The prober and the test suite log in once, do everything, then **always log
   out** (collect failures first, log out, then assert). Do not run tests in parallel against the device: the
   suite is one `#[tokio::test]` on purpose.
4. **Never test wrong credentials.** Login lockout after repeated failures is common on consumer routers (again
   a precaution, not observed here). No test deliberately logs in with a bad password.
5. **Mask secrets before anything is written to disk or shown.** The prober masks values under keys containing
   `psk`, `pass`, `pwd`, `key`, `secret`, `token`. Credentials live only in `secret.toml` (git-ignored). Do not
   paste payloads containing Wi-Fi passwords into notes, issues or prompts. The CLI itself does print `psk_key`
   (it is the owner's data and the point of a Wi-Fi query); treat its output as sensitive.
6. **Prefer idempotent probing.** Throttle (`40 ms` between requests) so the device web server is not hammered.

---

## 4. The transport layer: how the protocol works

Implemented in `src/crypto.rs` and `src/session.rs`. This section is the port of `TplinkRouter` for
the 1024-bit-RSA LuCI family. If your router is the same family, this code works unchanged.

### 4.1 Endpoints

```
POST {host}/cgi-bin/luci/;stok=/login?form=keys&operation=read     -> data.password = [modulus_hex, exponent_hex]
POST {host}/cgi-bin/luci/;stok=/login?form=auth&operation=read     -> data.key = [modulus_hex, exponent_hex], data.seq = "<number>"
POST {host}/cgi-bin/luci/;stok=/login?form=login                   -> encrypted body (see below); response sets sysauth cookie
POST {host}/cgi-bin/luci/;stok=<stok>/<path>                        -> every later request
```

Two different RSA keys are involved: the **password key** (`form=keys`) encrypts the password; the **auth key**
(`form=auth`) signs every request. `seq` is a number the router issues; every signature includes
`seq + len(encrypted_body)`.

### 4.2 Cipher and signature

* The client invents a session AES key and IV: 8 random bytes each, hex-encoded, giving **16 ASCII characters
  used directly as the 16 key bytes** (not as 8 bytes of entropy decoded). AES-128-CBC with PKCS#7 padding,
  output base64.
* Login password: RSA PKCS#1 v1.5 with the password key, output hex.
* Signature, per request: the plaintext is
  * login: `k=<aes_key>&i=<aes_iv>&h=<md5(username+password)>&s=<seq + len(data)>`
  * later: `h=<md5(username+password)>&s=<seq + len(data)>`

  cut into **53-byte chunks**, each RSA-PKCS#1v1.5-encrypted with the *auth key* and hex-encoded, chunks
  concatenated. (53 is the chunk size the reference uses and the router accepts; it is well under the
  117-byte PKCS#1 v1.5 limit of a 1024-bit key. Do not change it without checking against the device.)
* Body of every request: `sign=<urlencoded signature>&data=<urlencoded base64 AES ciphertext>`.
* Login plaintext: `operation=login&password=<rsa hex>&confirm=true`.
* Request plaintext (this firmware uses the JSON variant): `{"operation":"read"}` (or more keys for writes).
* Responses: JSON `{"data": "<base64 AES>"}`; decrypt with the session key to get
  `{"success": true, "data": ...}`. On failure the decrypted JSON carries `errorcode`.
  The decrypted payload is padded with PKCS#7 but the reference unpads **leniently** (last byte value, no
  validation); do the same, and decode UTF-8 lossily because device names can contain invalid bytes.

Details that cost time and are easy to get wrong:

* Request `Content-Type` is `application/json` even though the body is urlencoded `sign=...&data=...`.
  The reference does exactly this and the router accepts it. Login uses
  `application/x-www-form-urlencoded`. Also send `Referer: {host}/webpages/index.html` and
  `Origin: {host}`.
* The session cookie is `sysauth=<value>` taken from `Set-Cookie` and sent back as `Cookie: sysauth=<value>`.
  The token in the URL (`stok`) comes from the decrypted login response, `data.stok`.
* **Parameters are repeated in the URL.** The JSON client moves every key of the form-style payload into the
  URL query string as well as the body, unless that key is already in the path:
  `admin/dhcps?form=reservation` + `{operation: insert, new: {...}}` becomes
  `.../admin/dhcps?form=reservation&operation=insert&new=<urlencoded json>` with the same keys in the JSON body.
  Read paths like `admin/status?form=all&operation=read` therefore already contain `operation=` and must not get
  it appended twice. `session::build_url` encodes this rule.
* Login retry: the reference retries the whole handshake once if the login response is not valid JSON or is a
  403. Implemented once, not in a loop.
* A password longer than 125 bytes cannot be RSA-encrypted; fail early with a clear message.
* Logout: POST `admin/system?form=logout` with `operation=write`. Fire and forget, the response is ignored.
  After logout, the old `stok` must be rejected, which the test suite asserts.

### 4.3 Typed fetch helpers

`session::request` returns the decrypted `data` block as `serde_json::Value`. On top of it:

* `session::typed::<T>(session, path, operation)` deserializes into a model, error message includes the path
  and serde's field-level message but **not the payload** (payloads can hold secrets).
* `session::typed_list::<T>(..., keys)` handles the three list shapes this firmware family produces: a bare
  array, an object wrapping the array under a known key (`dhcp_clients`, `list`, `data`), and `{}` meaning
  "empty table". `session::list_rows` implements this and is used by both the reads and the write path.

---

## 5. Discovery: asking the router what it has

This is the part that generalises best. The reference client tells you *some* endpoints; the web UI exposes
more; the firmware may omit some the reference knows. **The router is the only authority.**

### 5.1 The probe

`examples/discover.rs` logs in once, then for each candidate path sends `read`, `load` and `list`, and for
each success writes the **masked** decrypted payload to `<dir>/<sanitized path>__<operation>.json`. It prints
one line per success (path, operation, size) and one per *unusual* error. Errors containing
`no such callback` are filtered out because that is simply the router's way of saying "this form does not
exist".

Run it:

```
cargo run --example discover -- /some/scratch/dir
```

### 5.2 Where candidate names come from

The candidate list is a guess list. Good sources, in order of yield:

1. Every path in the reference client's endpoint catalogue (`TplinkBaseRouter.__init__` URL attributes and the
   literal paths in its methods).
2. The router's own web UI. Open the UI with browser dev tools and watch XHR calls: the path
   (`admin/<module>?form=<form>`) and the `operation` value are visible. The module/form vocabulary
   (`status`, `network`, `wireless`, `dhcps`, `nat`, `access_control`, `administration`, `ddns`, `syslog`,
   `time`, `system`, ...) is stable across firmware of this family.
3. Systematic variations of the above: for every module seen, try the forms its siblings have
   (`wireless_2g`, `wireless_5g`, `guest_2g`, `guest_5g`, `statistics`; `status_ipv4`, `status_ipv6`,
   `wan_ipv4_dynamic`, `wan_ipv6_dynamic`, ...).
4. Names you expect from the feature list (DDNS, VPN, access control, DMZ, ALG, IPTV, time, log).

For this device roughly 140 candidates yielded 26 responding forms. Expect a hit rate of about 20 percent; the
misses are cheap.

### 5.3 Reading the results

Observations about this firmware family that shaped everything downstream (verify each on yours):

* **The `operation` in the URL is mostly decorative.** Many forms answer identically to `read`, `load` and
  `list` (the status and network forms). Others only answer one of them (`dhcps?form=client` and `syslog`
  want `load`; most settings want `read`). Record which operation each endpoint truly needs; the model code
  hard-codes it.
* **Three kinds of "does not work":**
  * `{"errorcode":"no such callback","success":false}`: the form does not exist.
  * `{"errorcode":"not exist", ...}` or `{"success":false}`: the form exists but not for this operation.
  * A body that is not JSON at all (a short base64-looking blob): the module is not routed. Treat as absent.
* **Everything is a string.** Numbers (`"1480"`), booleans (`"on"`, `"On"`, `"yes"`), ports, channels, even
  `cpu_usage` sometimes. A few values are real JSON (`remote: false`, `ntp_success: true`, `cpu_usage: 0.76`).
  This is why scalar parsing needs to be lenient on input and exact on output (section 6).
* **Empty string means "no value"** for addresses and MACs. A single field can be `""` today and `"1.2.3.4"`
  tomorrow.
* **Open versus closed vocabularies.** `encryption` seen as `none` / `psk`; `conntype` as `dhcp` / `dhcp6c` /
  `none`. You rarely see the full set from one device, so enums for these must carry an `Other(String)` escape
  (section 6.3).
* **Tables are `[]`, `{}` or `{"list": [...]}`** depending on emptiness and firmware. Table metadata (for
  example `others.max_rules`) sits next to `data` in the envelope, not inside it, hence
  `session::request_envelope`.
* **Same data, several places.** The `status?form=all` response contains about 140 keys including every
  Wi-Fi key under a band prefix (`wireless_5g_ssid`) that is also available from the dedicated form
  (`wireless?form=wireless_5g` → `ssid`). That redundancy is a gift: it gives you free cross-checks (section 7.3).

### 5.4 Manual exploration with `raw`

Once the CLI exists, `archer_c6 raw "<path>" <operation>` is the quickest way to look at one endpoint, and
the best way to debug a typed failure (the typed errors deliberately omit payloads). Pipe it through a masking
filter when the form can contain secrets.

---

## 6. Strong typing: turning payloads into types

The goal is that **a successful deserialization means something**: addresses are addresses, switches are
switches, and anything the router sends that the model does not know is noticed (by tests, section 7), not
silently dropped.

### 6.1 One struct per endpoint, router's own field names

`src/api.rs` has one struct per form. Rules:

* **Field names are exactly the router's** (`wan_ipv4_ipaddr`, `wep_type1`), with `#[serde(rename = "type")]`
  only where the name is a Rust keyword. No renaming layer: it keeps the test comparison trivial and keeps the
  model greppable against raw payloads.
* **Required means "always observed present".** A field that was present in every sample is non-`Option`, so a
  firmware that drops it fails loudly. `Option` is for values that are legitimately empty or null (the
  `""`-as-none addresses, `access_devices_wireless_guest: null`) and for fields that differ between two
  forms of the same shape (`mumimo` and `txbf_enable` exist only on the 5 GHz form: `#[serde(default)]
  Option<_>`).
* **Derive both `Serialize` and `Deserialize`.** Serialization is not for output only. It is the other half
  of the round trip that the tests use to prove nothing was lost.
* **The library is lenient about unknown fields; the tests are strict.** Production deserialization ignores
  new fields so a firmware update does not take the tool down. The *test* fails when the router sends a field
  the model lacks. This gives both properties without `deny_unknown_fields` in shipping code.

### 6.2 Scalar types (`src/scalar.rs`)

| Type | Wire forms accepted | Serialized as | Why a type |
|---|---|---|---|
| `Switch` | `on`/`On`/`yes`/`true`/`1`, `off`/... , JSON bool, JSON number | `"on"`/`"off"` | one place for the many spellings |
| `YesNo` | `yes`/`no` | `"yes"`/`"no"` | **separate from `Switch`** because the router uses both vocabularies and fidelity demands we write back what we read |
| `Mac` (`[u8;6]`) | `AA-BB-..`, `aa:bb:..`, `aabb.ccdd.eeff`, bare hex | `AA-BB-CC-DD-EE-FF` | the router uses dash-uppercase; user input and other forms vary |
| `Ipv6Net` (`Ipv6Addr` + optional prefix) | `::`, `::/0`, `2001:db8::1/64` | same | the router sometimes appends `/len` to what is otherwise an address |
| `Channel` | `"auto"`, `"36"`, `36` | `"auto"` or the number | channel is genuinely either |
| `std::net::Ipv4Addr` / `Ipv6Addr` | strings | strings | std already does it right |
| `ConnStatus` | `connected`/`disconnected`/other | same | status strings, closed-ish, with fallback |
| `WireType` | `wired`/`2.4G`/`5G`/other | same | client list vocabulary |
| `RadioBand` | `2.4GHz`/`5GHz`/other | same | **distinct from `WireType`**: the statistics form uses a different spelling |
| `Encryption` | `none`/`psk`/other | same | open vocabulary with fallback |

Two helper functions are used with `#[serde(deserialize_with = ...)]`:

* `scalar::number::<T>` accepts a JSON string or number and parses it as `T` (`u16` ports, `f64` usage,
  `i32` timezone, ...). Needed because "1480" and 1480 both occur.
* `scalar::empty_as_none::<T>` (with `scalar::none_as_empty` on the serialize side) turns `""`/`null` into
  `None` for any `FromStr` type and writes `None` back as `""`.

The parse and format code for these types is one `FromStr` and one `Display` per type, plus a macro
(`text_serde!`) that derives `Serialize`/`Deserialize` from them. Adding a scalar type for a new router is
about twenty lines.

### 6.3 Open vocabularies: `Other(String)` fallback

For a field with a small set of known values and an unknown full set:

```rust
#[derive(Clone, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub enum ConnStatus {
    #[serde(rename = "connected")]
    Connected,
    #[serde(rename = "disconnected")]
    Disconnected,
    #[serde(untagged)]
    Other(String),
}
```

Known values get a variant you can `match` on; unseen values still deserialize and still round-trip. Do not
make a field an exhaustive enum unless you have evidence the set is closed, and do not leave it `String` if
the code will branch on it.

### 6.4 Raw types versus views

Keep two layers and do not mix them:

* **Raw payload types (`api.rs`)** mirror the wire. They stay faithful even when the wire is ugly (placeholder
  device names `*`, `--`, `UNKNOWN`; `leasetime` as `"1:35:31"`). The tests compare them to the raw JSON.
* **Views (`router.rs`)** are what a human or another program wants: `Status` merges the three client lists
  and the statistics, classifies each client (`Connection::Host5g`, ...), turns placeholder names into
  `None` (`router::device_name`), and exposes real numbers. Views may normalise; payload types may not.

If you normalise in the payload type, the fidelity test (section 7.2) fails, because the model no longer
reproduces what the router sent. That is the reason the placeholder handling (`*`, `--`, `UNKNOWN`) lives in
`router::device_name`, applied in the view, and not in `api::StatusClient` or `api::DhcpClient`.

### 6.5 Rows you cannot sample

Some tables were empty on the development router (DHCP reservations, port forwards). Their row types are
therefore **typed from the reference client, not from observation** (`DhcpReservation`, `PortForward`), with
lenient `Option` fields where the reference is vague. Mark such types clearly in your own notes as
"unverified against the device", and prefer to create one row, observe it, delete it, and verify the model if
you are permitted to write. See section 12.

---

## 7. Tests: the router is the oracle

The test suite is one integration test, `tests/live.rs::router_read_only`. It is deliberately **not** a unit
test suite. Synthetic unit tests were written first, passed, and told us nothing about whether the model
matches the device; they were deleted. A test earns its place only if the live router can falsify it.

The test skips itself when `secret.toml` has no password, so it is safe in CI without a router.

### 7.1 Structure

```
login once
  endpoints()                      -> per-endpoint fidelity checks
  wifi_forms_match_status()        -> cross-form: dedicated Wi-Fi forms vs status?form=all prefixed keys
  network_is_consistent()          -> cross-form: MACs, IPs, gateway, DNS, DHCP range inside the subnet
  clients_are_consistent()         -> client list vs wifi statistics vs DHCP leases
  values_are_sane()                -> ranges, formats, ordering, band-specific fields
  error_paths()                    -> unknown form, wrong operation, wrong payload shape
logout (always), then assert the session is dead
assert!(failures.is_empty())       -> one panic listing every failure, not just the first
```

Failures are **collected**, never `?`-propagated, until after logout. That is what keeps one failing check
from leaking a session and from hiding the other nine problems.

### 7.2 The fidelity test (the core idea)

For each endpoint, `faithful::<T>(session, path, operation, ignored_prefixes)` does:

1. Fetch the raw JSON (`session::request`).
2. Deserialize into `T`. If this fails, the model cannot represent the payload.
3. Serialize the model back to JSON (`typed`).
4. **Compare every leaf of the raw JSON against the same path in `typed`.**
   * Leaf missing in `typed` → "sent by the router but missing in the model". This is the unknown-field
     detector.
   * Leaf differs → the model misparsed or rewrote a value.
   Strings compare lower-cased (the router mixes `On`/`on`); numbers compare numerically
   (`1` vs `1.0`); empty arrays/objects compare as `[]`/`{}`.
5. Deserialize `typed` again and serialize once more; require it equal `typed`. This proves the scalar types
   serialize into a form they can read back.

`faithful_list::<T>` does the same for tables after normalising the three list shapes to an array.

Per-endpoint `ignored_prefixes` exist for exactly one case: `status?form=all` carries about 100
band-prefixed keys that are deliberately not modelled, because the Wi-Fi forms hold identical data. The test
ignores those prefixes *and compensates* with `wifi_forms_match_status`, which proves they are identical.
Never ignore a prefix without a compensating check.

### 7.3 Cross-form consistency (free checks from redundancy)

The router reports the same fact in several places. Each duplication is a test:

* Every key of `wireless?form=<band>` equals `status?form=all`'s `<band>_<key>` (all four bands).
* LAN MAC and IP agree across `status all`, `status_ipv4`, `lan_ipv4`; WAN IP, gateway, netmask and DNS agree
  between `status all` and `wan_ipv4_dynamic`.
* DHCP gateway equals the LAN IP; DHCP start ≤ end; both inside the LAN subnet; netmask contiguous.
* Every client in the wireless statistics exists in the merged client list, is not classified wired, and has
  its packet counters merged. Wired clients are not in the statistics.
* Every connected client's IP and (normalised) name agree with its DHCP lease, when it has one.

When a cross-check fails, one of three things is true: your model is wrong, your assumption about the router
is wrong (usually), or the router is inconsistent (rare, and then worth recording). All the interesting
discoveries in section 8 came from this class of test.

### 7.4 Sanity and error-path tests

* CPU and memory are fractions in `[0, 1]`; hardware string contains the expected model; time is `HH:MM:SS`,
  date is `MM/DD/YYYY`; the system log is non-empty, timestamps are fixed width and ordered newest-first;
  the 5 GHz form has the two extra fields and the 2.4 GHz form does not.
* An unknown form errors with `no such callback`; an unsupported operation errors; a payload of the wrong
  shape (`Perf` deserialized from the firmware form) fails to deserialize; after logout the session is rejected.

### 7.5 Live-test hygiene

* **Compare across requests only what cannot change.** Packet counters move between two requests; the test
  asserts "counters were merged", not "counters are equal". Leases expire; names can change. When a test
  flakes, ask first whether the assertion compared a moving target.
* **Assume the network is live.** A device joined during development and exposed a wrong assumption. Run the
  suite several times (three consecutive passes was the bar) before trusting it.
* **A failing test is information.** In this project every red run was a correction to the *understanding*
  of the router, not just to the code (section 8). Change the model, the view, or the assumption, in that order
  of preference, and write down what you learned.

---

## 8. What the tests taught us (worked examples)

Each of these was a first-draft model that "obviously worked" until the live router contradicted it. They are
worth reading as a catalogue of the kinds of surprise to expect.

| Symptom (failing check) | What was actually true | Fix |
|---|---|---|
| `.support: router "yes", model "on"` | Router uses both `on/off` and `yes/no`. One `Switch` type silently rewrote one as the other. | Added `YesNo`; fields assigned by observed vocabulary. |
| Statistics `type`: router `"2.4ghz"`, model `"2.4g"` | The client list says `2.4G`/`5G`, the statistics say `2.4GHz`/`5GHz`. A serde `alias` had hidden the difference by merging them. | Separate `WireType` and `RadioBand`. Never use `alias` to paper over two vocabularies. |
| 100+ `status all` fields "missing in the model" | The response embeds every Wi-Fi field under a band prefix. | Ignore the prefixes in the fidelity test and add the compensating cross-form equality test. |
| `channel` came back `null` in the CLI | Channel is `"auto"` or a number; the first model parsed an integer. | `Channel` enum with `Auto` / `Fixed(u16)`; also model `current_channel`. |
| Lease not in the connected-device list | The lease table keeps phones that already left. Leases are a *superset* of clients. | Flipped the assertion: connected ⊆ leases. |
| Connected device without a lease | A client (hostname `UNKNOWN`) is connected and in the client list but absent from the lease table. I first assumed a static IP. **That was wrong**: the router's own DHCP log shows it receiving ACKs for that address every few hours. The lease table is simply not authoritative; the DHCP log is a better source. | Test only requires such a device's IP to be inside the LAN subnet; `diagnose` reports it as "not in the lease table". |
| Name `"*"` in status, `"--"` in leases for one device | Three different placeholders for "no name": `*`, `--`, `UNKNOWN`. | `router::device_name` normalises in the *view* only. |
| `cpu_usage: router "1", model "1.0"` | The router sent integer `1` where it normally sends `0.76`; also confirms usage is a 0..1 fraction. | Compare numbers numerically in the test. |
| `model` always `null` | This firmware has no `model` key; `hardware_version` carries the model. | Dropped the field. The reference client's field list is a hint, not a spec. |
| Smart-network endpoint errors | The endpoint does not exist on this model (the reference supports it for others). | Removed that code path instead of leaving a silent `try`. |

General lessons:

1. **Do not let a lenient parse hide a vocabulary difference.** If two spellings differ, you want two types
   (or a failing test), not one clever alias.
2. **Round-trip tests catch scalar-type bugs that deserialization alone cannot.** A type that reads
   `"yes"` and writes `"on"` is wrong even though it never errors on input.
3. **The reference client is a map, not the territory.** Fields it reads may be absent; fields present may be
   unknown to it. Only the device decides.
4. **Test assumptions about the *world* the same way as assumptions about the *format*.** "Leases equal
   clients" was a world assumption. It failed twice for two different reasons.

---

## 9. Write operations

Implemented in `src/changes.rs`: reboot, Wi-Fi settings per band, DHCP reservations (add/update/delete), port
forwards (add/update/delete), DHCP server on/off, WAN DHCP renew/release.

They were ported from the reference with their documented guards, and **have not been exercised against the
device** (reads were the mandate). Notes for whoever tests them:

* **Wire format.** Inserts send `operation=insert` and `new=<json row>`; updates send `operation=update`,
  `key`, `new`, `old` (the previous full row, so unknown firmware fields survive the round trip, which is why
  writes work on raw `serde_json::Value` rows and not on the typed structs); removes send `operation=remove`,
  `key`, `index` (the row index from the freshly loaded list). All these keys are also appended to the URL
  (section 4.2).
* **Verify, do not trust `success`.** The reference documents a router that answers `success: true` to an
  insert into a full table without storing it. Add/update/delete re-read the table and fail if the change is
  not present (`--no-verify` skips it). Do the same for any new write you add.
* **Validate locally first.** MAC, IPv4, port range and protocol are parsed before anything is sent
  (`parse_mac` uses `scalar::Mac`).
* **Wi-Fi writes.** When only `enable` is sent the keys are bare; with any other setting every key is
  prefixed with the form name (`wireless_5g_ssid`). Changing SSID or password on the band your own client is on
  disconnects you.
* **A safe first write test** is reversible: add a reservation for a made-up MAC outside the DHCP pool, read it
  back through `show reservations`, delete it, read again. That also verifies the unverified
  `DhcpReservation` model (section 12).

---

## 10. Playbook for a new router

Follow in order. Do not skip step 1: choosing the wrong client wastes everything after it.

1. **Identify the family without logging in.** `curl -s -X POST "http://<ip>/cgi-bin/luci/;stok=/login?form=keys&operation=read"`
   and `...form=auth...`. Note modulus length. Match to `discovery.py` / `provider.py`; read the matching
   `client/*.py` class and its mixins (mind MRO, section 2). If it is not `TplinkRouter`, port the right login
   from the reference and replace `src/crypto.rs` + `session::login`.
2. **Bring up the transport and prove it with one read.** Implement or reuse `crypto`/`session`, then call
   `firmware`. Success is a decrypted `{"success":true,"data":{...}}`. Debug with the decrypted error JSON,
   not the HTTP status. Do not proceed until this works.
3. **Write the candidate list and run `discover`.** Seed it from the reference catalogue, the UI's XHR
   traffic, and sibling-form guesses. Keep the deny-list. Save masked payloads to a scratch directory.
4. **Tabulate.** For each responding form record: path, working operation(s), shape (object / list / `{}`),
   and whether it contains secrets. Note the three failure kinds (section 5.3).
5. **Design scalars from what you saw.** For each distinct *vocabulary* (on/off, yes/no, MAC format, IPv6 with
   or without prefix, number-as-string, enum-like strings) decide a type. New vocabulary = new type; do not
   merge on convenience.
6. **Write `api.rs` structs from the payloads**, router field names verbatim, required unless observed empty.
   Start with the small forms, do the big combined form (`status all`) last.
7. **Write `tests/live.rs` immediately, before the views.** Start with `faithful` for every endpoint. Expect
   the first run to fail in many places; each failure is step 5/6 feedback. Iterate until green.
8. **Add cross-form tests** for every duplicated fact you can find. They are where wrong assumptions surface.
9. **Build views** (merged client list, status) on the typed payloads, normalising there and only there.
10. **Add the CLI** (`show <topic>`, `all`, `raw`). Keep `raw` forever; it is the debugging tool.
11. **Only then consider writes**, with read-back verification and a reversible test.
12. **Repeat the live test several times at different moments** (devices come and go, counters move, leases
    expire) and fix assertions that depend on moving data.
13. **Write down the discoveries** as in section 13, for the next person.

What changes per router and what does not:

| Usually unchanged within a family | Changes per model/firmware |
|---|---|
| `crypto.rs`, `session.rs`, `scalar.rs`, `config.rs` | The set of existing forms and their `operation` |
| The three failure shapes, list shapes | Field sets (e.g. 5 GHz vs dual-band vs tri-band; 6 GHz, IoT, MLO bands) |
| Fidelity test machinery (`differences`, `faithful`) | Which prefixes are redundant, which cross-checks exist |
| URL and parameter-repetition rule | Hardware features (USB, modem, mesh), hence which forms exist |
| Safety rules | Vocabulary details (placeholders, enum members) |

---

## 11. Pitfalls and tooling notes

* **Crate versions matter for the crypto stack.** `cargo add` picked newer `aes`/`cbc`/`md-5` releases
  (cipher API 0.5) that are incompatible with the `rsa 0.9` generation. The known-good set is
  `aes 0.8`, `cbc 0.1` (feature `alloc`), `md-5 0.10`, `rsa 0.9`, `rand 0.8`. Pin them.
* **`rand 0.8` with `rsa 0.9`**: `Pkcs1v15Encrypt` needs an RNG implementing the old `rand_core 0.6` traits.
  Using a newer `rand` breaks the trait bounds.
* **`reqwest` and the content type.** Building the urlencoded body by hand (`sign=...&data=...`) avoids
  reqwest's `.form()` overriding or requiring the content-type you need. `urlencoding::encode` is enough.
* **Non-JSON "responses".** A body such as a short base64 blob from a non-routed module will make the typed
  path error with "response is not JSON". It means "absent", not "broken transport".
* **Sessions (precautions, not observed on this device).** Consumer routers often invalidate or cap sessions
  when another client logs in. If requests suddenly fail with an auth error, check for another logged-in
  session (the web UI in a browser counts). The CLI logs in per invocation and logs out; a crashed run may
  leave a session until it times out, so wait rather than hammering login.
* **Large payloads exist.** The system log was 77 KB masked; do not print it unfiltered in a prompt.
* **Style rules shape the code.** This repository bans comments and in-code imports (trait imports only), so
  names and structure carry the explanation, and this document is where the *why* lives.

---

## 12. Known gaps

Be explicit about what is **verified against the device** and what is not.

Verified (live test passes three times in a row): login and logout; every read endpoint listed in section 13
(26 forms) including strict field coverage and round-trip; the cross-form consistency checks; the merged client
view.

**Not verified:**

* Every **write** command (section 9).
* **Row shapes** of DHCP reservations and port forwards (tables were empty), and the reservation envelope
  (`others.max_rules` is read as 64 from the live response, but the rows themselves come from the reference).
* **IPv6 up.** The IPv6 WAN is disabled on the development router, so `Ipv6Net` values with a real prefix
  (`2001:db8::1/64`), a non-empty `prefix`, or non-`::` DNS never occurred. The types parse them by design but
  the live test has not seen one.
* **Enum members seen only once**: `ConnStatus`, `Encryption`, `WireType`, `RadioBand` carry `Other(String)`
  so unknown values do not break reads, but the "other" arms have never been hit.
* **Guest-network clients**: `access_devices_wireless_guest` was always `null`; the typed path for a populated
  list is unexercised.
* **PPPoE form**: the structure was typed from an unused saved profile. If the WAN type changes, re-run the live
  test.
* **Behaviour over firmware upgrades.** The library ignores new fields, but the test will (intentionally) fail
  and tell you which ones.
* Other **OS targets**: default-gateway detection reads `/proc/net/route` (Linux only). Elsewhere pass `--host`.

---

## 13. Appendix: facts about the Archer C6 v2 firmware 1.3.2

For calibration: this is what "done" looked like on one real device. Use it as a sanity reference for scale and
as a list of endpoints to try first on a sibling model.

Login family: classic LuCI, 1024-bit RSA (`TplinkRouter`), JSON request bodies, AES-128-CBC session.

Responding forms (all `admin/<module>?form=<form>`; operation in brackets):

```
status?form=all [read]            status?form=perf [read]          status?form=internet [read]
firmware?form=upgrade [read]      time?form=settings [read]        system?form=sysmode [read]
network?form=status_ipv4 [read]   network?form=status_ipv6 [read]
network?form=wan_ipv4_dynamic [read]   network?form=wan_ipv6_dynamic [read]   network?form=wan_ipv4_pppoe [read]
network?form=lan_ipv4 [read]      network?form=lan_ipv6 [read]
dhcps?form=setting [read]         dhcps?form=client [load]         dhcps?form=reservation [load]
wireless?form=wireless_2g|wireless_5g|guest_2g|guest_5g [read]     wireless?form=statistics [load]
nat?form=vs [load]  nat?form=alg [read]  nat?form=dmz [read]  nat?form=pt [load]
access_control?form=enable [read]  access_control?form=mode [read]  access_control?form=black_list|white_list [load]
administration?form=remote [read]  administration?form=local [load]
ddns?form=dyndns [read]  ddns?form=noip [read]  ddns?form=tplink [load]
openvpn?form=config [read]  pptpd?form=config [read]
syslog?form=log [load]            iptv?form=setting [read]  (answers; not modelled)
```

Absent on this model (answer "no such callback" or non-JSON): `dns`, `firewall`, `route`, `qos`, `upnp`, `usb`,
`parental_control`, `smart_network?form=game_accelerator`, `easymesh_network`, `network?form=lan`,
`system?form=time`, `led`, `traffic`/`statistics`, and the rest of the guess list in `examples/discover.rs`.

Facts that are easy to get wrong:

* `cpu_usage`/`mem_usage` are fractions 0..1, sometimes integers; `status all` omits them, `status?form=perf`
  has them.
* `status?form=all` lists clients under `access_devices_wired`, `access_devices_wireless_host`,
  `access_devices_wireless_guest` (can be `null`), each with `hostname`, `ipaddr`, `macaddr`, `wire_type`.
  Packet counters come only from `wireless?form=statistics`, and only for Wi-Fi clients.
* The 5 GHz form has `mumimo` and `txbf_enable`; the 2.4 GHz form does not.
* Guest forms have no channel of their own.
* `time?form=settings`: `date` is `MM/DD/YYYY`, `time` is `HH:MM:SS`, `timezone` is a string number.
* The system log (`syslog?form=log`, operation `load`) returns newest first, entries
  `{content, level, time: "YYYY-MM-DD HH:MM:SS", type}`.
* Placeholder device names: `*`, `--`, `UNKNOWN`.
* WAN here is DHCP (`conntype: dhcp`), so `wan_ipv4_dynamic` is the live WAN form; `wan_ipv4_pppoe` holds an
  inactive saved profile.
* DHCP reservation table capacity (`others.max_rules`) was 64.

---

*Method in one paragraph:* find the reference client for your family, prove the login with one read, probe the
device read-only with a throttled prober and a deny-list, save masked payloads, design strict types from
those payloads (one type per vocabulary, router field names verbatim, raw types faithful, views normalised),
and write tests that ask the live router, round-trip every payload, flag any field the model lacks, and
cross-check every fact the router reports twice. Treat each failing test as the router correcting your
understanding, and write the correction down.

---

## 14. Using the typed API to diagnose a real problem

The point of the typed client is to answer questions about the live network. This section records one real use,
because the *way* the investigation went is as instructive as the result.

**The question.** A user reported that the router "started working worse", that a device's IP address seemed to
change, and that the router sometimes did not hand out an address. The investigation is implemented as `src/diagnose.rs` (one-shot report) and `src/watch.rs` (catch it in the act),
both read-only.

### 14.1 Method

1. **Find the router's own evidence first.** The system log (`syslog?form=log`) turned out to hold only DHCP
   server events (`DHCPS`/`INFO`), 459 of them over about 52 hours: `receive discover`, `send offer`,
   `receive request`, `send ack`. That is exactly the evidence needed for an address problem. Always look at
   what the log actually contains before deciding what to analyse.
2. **Parse it into types, not regexes on the fly.** `DhcpEvent { Discover, Offer, Request, Ack, Other }` with a
   `parse_event` over slice patterns, and `epoch_seconds` for the timestamps. Anything not recognised becomes
   `Other` and is reported ("a NAK, decline or conflict line this tool does not know"). The live test asserts
   that no log line parses to `Other`, so a firmware that logs new line shapes fails loudly.
3. **Turn each hypothesis into a check that can say "no".** Each of these is a function over typed data
   returning `Finding { severity, area, message }`:
   * IP jumps: a MAC acknowledged with more than one address over the window.
   * Unanswered requests: a `Request` with no `Ack` for the same MAC within three seconds.
   * DHCP restarts: `Discover` rate per MAC per day; requests less than a minute apart.
   * Address conflicts: two clients (or leases) sharing an IP; any client holding the router's own address.
   * Pool and lease sanity: pool size versus leases, router address inside the pool, lease time, DHCP gateway
     equals router, pool inside the LAN subnet, DHCP enabled.
   * DNS handed out: `dns 0.0.0.0` in ACKs, per client.
   * WAN: cable and connection status, address private/CGNAT (10/8, 172.16/12, 192.168/16, 100.64/10),
     WAN/LAN subnet overlap, MTU, duplicate DNS servers.
   * Radio: channel, whether 2.4 GHz is on 1/6/11, TKIP/WPA1 allowed, no encryption, clients per band.
   * System: firmware age against the router's own clock, NTP success, remote administration, access control.
   * Load: CPU samples, memory, total and per-client packets per second.
4. **Check the checks.** Several first impressions were wrong and only the data corrected them (14.3).

### 14.2 The observer effect (the most transferable lesson)

**Measuring this router loads it.** The first CPU readings were 62 to 94 percent, which looked like a pegged
CPU on an almost idle network. They were caused by the investigation itself: every `status` call fires five
requests (RSA and AES on a small SoC), and `perf` was read right after them. Reading `perf` alone, in one
session, on a quiet interval gave **average 14 percent, minimum 1 percent**; the only high sample was the first
one after a heavy snapshot (0.71, then 0.09, 0.0, 0.05, ...).

Rules that follow:

* Sample load with the lightest possible request (`status?form=perf`) and **before** any heavy call in the same
  tick, never after one. `watch` reads `perf` first for exactly this reason.
* The first reading after login is also inflated (the RSA handshake). Discard it or treat it as polluted.
* Judge CPU against traffic, not alone. High CPU at low packet rate (the diagnosis flags `>= 70%` CPU with
  `< 1000` packets/s) points inside the router; high CPU at high packet rate is just forwarding.
* If you see a suspicious number, ask "did I cause it?" before reporting it. One wrong report to the user was
  made here and had to be retracted.

### 14.3 What the data corrected

| First impression | What the data showed |
|---|---|
| CPU is pegged | It was my own polling; idle CPU is 0 to 30 percent. |
| ACKs with `dns 0.0.0.0` mean the router hands out broken DNS | It happens for exactly one client (a wired embedded device), always, never mixed. It does not ask for a DNS option. Benign. |
| 7 unanswered messages | Four were an artefact of how the log orders a `discover` followed directly by `request`/`ack` (no `offer` line). Counting only `request` without `ack`: 3 of 184 (1.6 percent). |
| A device with no lease must be a static IP | It receives DHCP ACKs; the lease table omits it (section 8). |
| "IP jumps" is visible in the router | Not in this window: no client was ever given a second address across 52 hours. |

### 14.4 Findings on the development router (read-only, nothing was changed)

* DHCP server healthy: a small fraction of the pool was leased, no address changes, no conflicts, and under two
  percent of requests lacked an ACK.
* Configuration risk: **the router's own LAN address was inside its DHCP pool**. The factory layout keeps the
  router outside the pool, so the check flags it.
* The WAN address was in a private range (RFC 1918 or carrier-grade NAT) and obtained by DHCP: the router sat
  behind another NAT. The public address belongs to that upstream device and can change without any sign on this
  router.
* About half of the DHCP clients used randomised MAC addresses; they were stable over the window.
* Most clients sat on the crowded 2.4 GHz band; the firmware was several years old; no DHCP reservations existed.

None of these *proves* the user's symptom. The honest status was: the router-side evidence for an address
problem was absent, and the intermittent nature called for the watcher.

### 14.5 The watcher

`watch` takes a lightweight snapshot every N seconds (default 30) and prints **only differences**, with an
elapsed-time stamp: `JOINED`, `LEFT`, `IP JUMP` (same MAC, new address), `MOVED` (switched band, which was
observed on a phone), `CONFLICT`, `WAN IP`, `INTERNET`, `CPU` (rising edge over 80 percent), plus new DHCP log
lines that mean trouble (a client starting DHCP from scratch, or an unrecognised line). If the router stops
answering it reports `ROUTER request failed` and gives up after five failures, which is itself a finding.
It handles Ctrl-C and SIGTERM so it logs out instead of leaving a session open (a killed run earlier did leave
one). Run it during the time the problem appears and compare timestamps with what the user noticed.

### 14.6 Checklist for diagnosing on another router

1. Read what the log contains; do not assume it has what you need.
2. Type the log lines; keep an `Other` bucket and test that it stays empty.
3. Compare configuration with a known-good layout (router outside the pool, gateway equals router, pool in the
   subnet).
4. Measure load with the cheapest request, first in the tick, and never trust the first sample.
5. Cross-check every alarming number once by an independent route before calling it a fault.
6. For intermittent problems, build or run a watcher and correlate with the user's clock.
7. State clearly which conclusions are measured and which are hypotheses.
