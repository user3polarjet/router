#[derive(Clone, Copy, clap::ValueEnum)]
pub enum Protocol {
    Tcp,
    Udp,
    All,
}

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum WanAction {
    Renew,
    Release,
}

#[derive(clap::Args)]
pub struct WifiSettings {
    #[arg(long)]
    pub enable: Option<bool>,
    #[arg(long)]
    pub ssid: Option<String>,
    #[arg(long)]
    pub hidden: Option<bool>,
    #[arg(long)]
    pub encryption: Option<String>,
    #[arg(long)]
    pub psk_version: Option<String>,
    #[arg(long)]
    pub psk_cipher: Option<String>,
    #[arg(long)]
    pub psk_key: Option<String>,
    #[arg(long)]
    pub hwmode: Option<String>,
    #[arg(long)]
    pub htmode: Option<String>,
    #[arg(long)]
    pub channel: Option<String>,
    #[arg(long)]
    pub txpower: Option<String>,
}

const RESERVATION_PATH: &str = "admin/dhcps?form=reservation";
const FORWARD_PATH: &str = "admin/nat?form=vs";
const DHCP_SERVER_PATH: &str = "admin/dhcps?form=setting";
const WAN_DYNAMIC_PATH: &str = "admin/network?form=wan_ipv4_dynamic";

fn on_off(value: bool) -> &'static str {
    if value { "on" } else { "off" }
}

fn ok() -> serde_json::Value {
    serde_json::json!({ "ok": true })
}

fn text(value: &serde_json::Value, key: &str) -> Option<String> {
    match value.get(key)? {
        serde_json::Value::String(text) => Some(text.clone()),
        serde_json::Value::Number(number) => Some(number.to_string()),
        serde_json::Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

fn flag(value: &serde_json::Value, key: &str) -> Option<bool> {
    text(value, key).and_then(|text| text.parse::<crate::scalar::Switch>().ok()).map(crate::scalar::Switch::is_on)
}

fn reservation_name(row: &serde_json::Value) -> Option<String> {
    text(row, "comment")
        .filter(|name| !name.is_empty())
        .or_else(|| text(row, "hostname"))
}

fn parse_mac(text: &str) -> anyhow::Result<String> {
    Ok(text.parse::<crate::scalar::Mac>()?.to_string())
}

fn parse_ip(text: &str) -> anyhow::Result<std::net::Ipv4Addr> {
    text.trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid IPv4 address: {text}"))
}

fn parse_port(text: &str, allow_range: bool) -> anyhow::Result<String> {
    let parts: Vec<&str> = text.split('-').map(str::trim).collect();
    if parts.len() > if allow_range { 2 } else { 1 } {
        anyhow::bail!("invalid port format: {text}");
    }
    let numbers = parts
        .iter()
        .map(|part| match part.parse::<u16>() {
            Ok(number) if number >= 1 => Ok(number),
            _ => Err(anyhow::anyhow!("invalid port: {text}")),
        })
        .collect::<anyhow::Result<Vec<u16>>>()?;
    match numbers.as_slice() {
        [single] => Ok(single.to_string()),
        [start, end] if start <= end => Ok(format!("{start}-{end}")),
        _ => anyhow::bail!("invalid descending port range: {text}"),
    }
}

fn protocol_label(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "TCP",
        Protocol::Udp => "UDP",
        Protocol::All => "ALL",
    }
}

fn row_mac(row: &serde_json::Value, key: &str) -> Option<String> {
    text(row, key).and_then(|text| text.parse::<crate::scalar::Mac>().ok()).map(|mac| mac.to_string())
}

fn find_reservation(rows: &[serde_json::Value], mac: &str) -> Option<(usize, serde_json::Value)> {
    rows.iter()
        .enumerate()
        .find(|(_, row)| row_mac(row, "mac").as_deref() == Some(mac))
        .map(|(index, row)| (index, row.clone()))
}

fn row_ip(row: &serde_json::Value) -> Option<String> {
    text(row, "ip").map(|ip| ip.trim().to_string())
}

fn check_conflicts(
    rows: &[serde_json::Value],
    mac: &str,
    ip: &str,
    ignore_mac: Option<&str>,
) -> anyhow::Result<()> {
    for row in rows {
        let existing = row_mac(row, "mac");
        if ignore_mac.is_some() && existing.as_deref() == ignore_mac {
            continue;
        }
        if existing.as_deref() == Some(mac) {
            anyhow::bail!("a reservation for MAC {mac} already exists");
        }
        if row_ip(row).as_deref() == Some(ip) {
            anyhow::bail!("IP {ip} is already reserved for {}", existing.unwrap_or_default());
        }
    }
    Ok(())
}

fn parse_reservation_ip(text: &str) -> anyhow::Result<String> {
    let ip = parse_ip(text)?;
    if ip.is_unspecified() {
        anyhow::bail!("invalid IP address: {text}");
    }
    Ok(ip.to_string())
}

pub async fn reboot(session: &crate::session::Session) -> anyhow::Result<serde_json::Value> {
    crate::session::fire_and_forget(session, "admin/system?form=reboot", "write").await?;
    Ok(ok())
}

pub async fn set_wifi(
    session: &crate::session::Session,
    band: crate::router::WifiBand,
    settings: &WifiSettings,
) -> anyhow::Result<serde_json::Value> {
    let form = crate::router::wifi_band_form(band);
    let enable_only = settings.ssid.is_none()
        && settings.hidden.is_none()
        && settings.encryption.is_none()
        && settings.psk_version.is_none()
        && settings.psk_cipher.is_none()
        && settings.psk_key.is_none()
        && settings.hwmode.is_none()
        && settings.htmode.is_none()
        && settings.channel.is_none()
        && settings.txpower.is_none();
    if enable_only && settings.enable.is_none() {
        anyhow::bail!("at least one wireless setting must be provided");
    }
    let key = |name: &str| if enable_only { name.to_string() } else { format!("{form}_{name}") };

    let mut params: Vec<(String, String)> = vec![("operation".into(), "write".into())];
    let fields = [
        ("enable", settings.enable.map(|v| on_off(v).to_string())),
        ("ssid", settings.ssid.clone()),
        ("hidden", settings.hidden.map(|v| on_off(v).to_string())),
        ("encryption", settings.encryption.clone()),
        ("psk_version", settings.psk_version.clone()),
        ("psk_cipher", settings.psk_cipher.clone()),
        ("psk_key", settings.psk_key.clone()),
        ("hwmode", settings.hwmode.clone()),
        ("htmode", settings.htmode.clone()),
        ("channel", settings.channel.clone()),
        ("txpower", settings.txpower.clone()),
    ];
    for (name, value) in fields {
        if let Some(value) = value {
            params.push((key(name), value));
        }
    }
    let borrowed: Vec<(&str, &str)> = params.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    crate::session::request_params(session, &format!("admin/wireless?form={form}"), &borrowed).await?;
    Ok(ok())
}

pub async fn add_reservation(
    session: &crate::session::Session,
    mac: &str,
    ip: &str,
    name: &str,
    enable: bool,
    verify: bool,
) -> anyhow::Result<serde_json::Value> {
    let mac = parse_mac(mac)?;
    let ip = parse_reservation_ip(ip)?;
    if verify {
        let (rows, max_rules) = crate::router::reservation_rows(session).await?;
        if let Some(max) = max_rules
            && rows.len() as u64 >= max
        {
            anyhow::bail!("IPv4 reservation table is full ({}/{max})", rows.len());
        }
        check_conflicts(&rows, &mac, &ip, None)?;
    }
    let new = serde_json::json!({
        "mac": mac,
        "ip": ip,
        "comment": name,
        "hostname": name,
        "enable": on_off(enable),
    })
    .to_string();
    crate::session::request_params(session, RESERVATION_PATH, &[("operation", "insert"), ("new", &new)]).await?;
    if verify {
        let (rows, _) = crate::router::reservation_rows(session).await?;
        let stored = find_reservation(&rows, &mac).and_then(|(_, row)| row_ip(&row));
        if stored.as_deref() != Some(ip.as_str()) {
            anyhow::bail!("router accepted the reservation {mac} -> {ip} but did not store it");
        }
    }
    Ok(ok())
}

pub async fn update_reservation(
    session: &crate::session::Session,
    old_mac: &str,
    new_mac: Option<&str>,
    ip: Option<&str>,
    name: Option<&str>,
    enable: Option<bool>,
    verify: bool,
) -> anyhow::Result<serde_json::Value> {
    let (rows, _) = crate::router::reservation_rows(session).await?;
    let old_mac = parse_mac(old_mac)?;
    let (_, target) =
        find_reservation(&rows, &old_mac).ok_or_else(|| anyhow::anyhow!("reservation not found for MAC: {old_mac}"))?;
    let target_key = text(&target, "mac").unwrap_or_default();
    let new_mac = match new_mac {
        Some(mac) => parse_mac(mac)?,
        None => old_mac.clone(),
    };
    let new_ip = match ip {
        Some(ip) => parse_reservation_ip(ip)?,
        None => row_ip(&target).unwrap_or_default(),
    };
    if verify {
        check_conflicts(&rows, &new_mac, &new_ip, Some(&old_mac))?;
    }

    let mut new = target.clone();
    let fields = new
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("reservation row is not an object: {target}"))?;
    if new_mac != old_mac {
        fields.insert("mac".into(), new_mac.clone().into());
    }
    fields.insert("ip".into(), new_ip.clone().into());
    if let Some(name) = name {
        fields.insert("comment".into(), name.into());
        fields.insert("hostname".into(), name.into());
    }
    if let Some(enable) = enable {
        fields.insert("enable".into(), on_off(enable).into());
    }
    let new_json = new.to_string();
    let old_json = target.to_string();
    crate::session::request_params(
        session,
        RESERVATION_PATH,
        &[("operation", "update"), ("key", &target_key), ("new", &new_json), ("old", &old_json)],
    )
    .await?;

    if !verify {
        return Ok(serde_json::to_value(serde_json::from_value::<crate::api::DhcpReservation>(new).ok())?);
    }
    let (rows, _) = crate::router::reservation_rows(session).await?;
    let (_, stored) = find_reservation(&rows, &new_mac).ok_or_else(|| {
        anyhow::anyhow!("router accepted the update of reservation {old_mac} but did not store it")
    })?;
    let stored_reservation = serde_json::from_value::<crate::api::DhcpReservation>(stored.clone()).ok();
    let ip_ok = row_ip(&stored).as_deref() == Some(new_ip.as_str());
    let enable_ok = enable.is_none_or(|wanted| flag(&stored, "enable") == Some(wanted));
    let name_ok = name.is_none_or(|wanted| reservation_name(&stored).unwrap_or_default() == wanted);
    if !(ip_ok && enable_ok && name_ok) {
        anyhow::bail!("router accepted the update of reservation {old_mac} but did not store it");
    }
    if new_mac != old_mac && find_reservation(&rows, &old_mac).is_some() {
        anyhow::bail!("router kept the old reservation {old_mac} after the update");
    }
    Ok(serde_json::to_value(stored_reservation)?)
}

pub async fn delete_reservation(
    session: &crate::session::Session,
    mac: &str,
    verify: bool,
) -> anyhow::Result<serde_json::Value> {
    let mac = parse_mac(mac)?;
    let (rows, _) = crate::router::reservation_rows(session).await?;
    let (index, target) =
        find_reservation(&rows, &mac).ok_or_else(|| anyhow::anyhow!("reservation not found for MAC: {mac}"))?;
    let key = text(&target, "mac").unwrap_or_default();
    crate::session::request_params(
        session,
        RESERVATION_PATH,
        &[("operation", "remove"), ("key", &key), ("index", &index.to_string())],
    )
    .await?;
    if verify {
        let (rows, _) = crate::router::reservation_rows(session).await?;
        if find_reservation(&rows, &mac).is_some() {
            anyhow::bail!("router accepted the removal of reservation {mac} but kept it");
        }
    }
    Ok(ok())
}

fn forward_row(
    name: &str,
    external_port: &str,
    internal_port: &str,
    ip: &str,
    protocol: &str,
) -> anyhow::Result<serde_json::Map<String, serde_json::Value>> {
    if name.trim().is_empty() {
        anyhow::bail!("port forward name must not be empty");
    }
    let mut row = serde_json::Map::new();
    row.insert("name".into(), name.trim().into());
    row.insert("ipaddr".into(), parse_ip(ip)?.to_string().into());
    row.insert("external_port".into(), parse_port(external_port, true)?.into());
    row.insert("internal_port".into(), parse_port(internal_port, false)?.into());
    row.insert("protocol".into(), protocol.into());
    Ok(row)
}

fn find_forward(rows: &[serde_json::Value], name: &str) -> Option<(usize, serde_json::Value)> {
    rows.iter()
        .enumerate()
        .find(|(_, row)| text(row, "name").as_deref() == Some(name))
        .map(|(index, row)| (index, row.clone()))
}

pub async fn add_forward(
    session: &crate::session::Session,
    name: &str,
    external_port: &str,
    internal_port: &str,
    ip: &str,
    protocol: Protocol,
    enable: bool,
) -> anyhow::Result<serde_json::Value> {
    let mut row = forward_row(name, external_port, internal_port, ip, protocol_label(protocol))?;
    row.insert("enable".into(), on_off(enable).into());
    let new = serde_json::Value::Object(row).to_string();
    crate::session::request_params(session, FORWARD_PATH, &[("operation", "insert"), ("new", &new)]).await?;
    Ok(ok())
}

#[allow(clippy::too_many_arguments)]
pub async fn update_forward(
    session: &crate::session::Session,
    name: &str,
    new_name: Option<&str>,
    external_port: Option<&str>,
    internal_port: Option<&str>,
    ip: Option<&str>,
    protocol: Option<Protocol>,
    enable: Option<bool>,
) -> anyhow::Result<serde_json::Value> {
    let rows = crate::router::port_forward_rows(session).await?;
    let (_, target) = find_forward(&rows, name).ok_or_else(|| anyhow::anyhow!("port forward not found: {name}"))?;
    let current = |key: &str| text(&target, key).unwrap_or_default();
    let protocol_text = match protocol {
        Some(protocol) => protocol_label(protocol).to_string(),
        None => current("protocol").to_uppercase(),
    };
    let merged = forward_row(
        new_name.unwrap_or(name),
        external_port.unwrap_or(&current("external_port")),
        internal_port.unwrap_or(&current("internal_port")),
        ip.unwrap_or(&current("ipaddr")),
        &protocol_text,
    )?;

    let mut new = target.clone();
    let fields = new
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("port forward row is not an object: {target}"))?;
    fields.extend(merged);
    let enable_text = match enable {
        Some(enable) => on_off(enable).to_string(),
        None if target.get("enable").is_some() => current("enable"),
        None => "on".to_string(),
    };
    fields.insert("enable".into(), enable_text.into());

    let new_json = new.to_string();
    let old_json = target.to_string();
    crate::session::request_params(
        session,
        FORWARD_PATH,
        &[("operation", "update"), ("key", name), ("new", &new_json), ("old", &old_json)],
    )
    .await?;
    Ok(ok())
}

pub async fn delete_forward(session: &crate::session::Session, name: &str) -> anyhow::Result<serde_json::Value> {
    let rows = crate::router::port_forward_rows(session).await?;
    let (index, _) = find_forward(&rows, name).ok_or_else(|| anyhow::anyhow!("port forward not found: {name}"))?;
    crate::session::request_params(
        session,
        FORWARD_PATH,
        &[("operation", "remove"), ("key", name), ("index", &index.to_string())],
    )
    .await?;
    Ok(ok())
}

pub async fn set_dhcp_server(session: &crate::session::Session, enable: bool) -> anyhow::Result<serde_json::Value> {
    let current = crate::session::request(session, DHCP_SERVER_PATH, "read").await?;
    let mut params: Vec<(String, String)> = vec![
        ("operation".into(), "write".into()),
        ("enable".into(), on_off(enable).into()),
    ];
    for key in ["leasetime", "pri_dns", "snd_dns", "gateway", "ipaddr_start", "ipaddr_end", "domain"] {
        if let Some(value) = text(&current, key).filter(|value| !value.is_empty()) {
            params.push((key.into(), value));
        }
    }
    let borrowed: Vec<(&str, &str)> = params.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    crate::session::request_params(session, DHCP_SERVER_PATH, &borrowed).await?;
    Ok(ok())
}

pub async fn wan(session: &crate::session::Session, action: WanAction) -> anyhow::Result<serde_json::Value> {
    let operation = match action {
        WanAction::Renew => "renew",
        WanAction::Release => "release",
    };
    crate::session::request(session, WAN_DYNAMIC_PATH, operation).await?;
    Ok(ok())
}
