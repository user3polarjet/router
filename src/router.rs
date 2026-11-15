#[derive(Clone, Copy, PartialEq, Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Connection {
    Unknown,
    Wired,
    Host2g,
    Host5g,
    Guest2g,
    Guest5g,
}

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum WifiBand {
    Host2g,
    Host5g,
    Guest2g,
    Guest5g,
}

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum Topic {
    Firmware,
    Internet,
    SystemMode,
    Time,
    Ipv4,
    Ipv6,
    WanIpv4,
    WanIpv6,
    WanPppoe,
    LanIpv4,
    LanIpv6,
    DhcpServer,
    Leases,
    Reservations,
    Forwards,
    AccessControl,
    RemoteAdmin,
    Ddns,
    Nat,
    Vpn,
    Syslog,
}

#[derive(serde::Serialize)]
pub struct Device {
    pub connection: Connection,
    pub macaddr: crate::scalar::Mac,
    pub ipaddr: Option<std::net::Ipv4Addr>,
    pub hostname: Option<String>,
    pub packets_sent: Option<u64>,
    pub packets_received: Option<u64>,
}

#[derive(serde::Serialize)]
pub struct ClientTotals {
    pub total: usize,
    pub wired: usize,
    pub wifi: usize,
    pub guest: usize,
    pub unknown: usize,
}

#[derive(serde::Serialize)]
pub struct Status {
    pub wan_macaddr: crate::scalar::Mac,
    pub lan_macaddr: crate::scalar::Mac,
    pub wan_ipv4_addr: std::net::Ipv4Addr,
    pub lan_ipv4_addr: std::net::Ipv4Addr,
    pub wan_ipv4_gateway: std::net::Ipv4Addr,
    pub wan_ipv4_conntype: String,
    pub wan_link_status: Option<String>,
    pub wan_conn_status: Option<crate::scalar::ConnStatus>,
    pub internet_status: crate::scalar::ConnStatus,
    pub internet_v6_status: crate::scalar::ConnStatus,
    pub wan_ipv6_enable: crate::scalar::Switch,
    pub wan_ipv6_addr: crate::scalar::Ipv6Net,
    pub lan_ipv4_dhcp_enable: crate::scalar::Switch,
    pub cpu_usage: f64,
    pub mem_usage: f64,
    pub wifi_2g_enable: crate::scalar::Switch,
    pub wifi_5g_enable: crate::scalar::Switch,
    pub guest_2g_enable: crate::scalar::Switch,
    pub guest_5g_enable: crate::scalar::Switch,
    pub clients: ClientTotals,
    pub devices: Vec<Device>,
}

#[derive(serde::Serialize)]
pub struct Reservations {
    pub max_rules: Option<u64>,
    pub rules: Vec<crate::api::DhcpReservation>,
}

pub fn wifi_band_form(band: WifiBand) -> &'static str {
    match band {
        WifiBand::Host2g => "wireless_2g",
        WifiBand::Host5g => "wireless_5g",
        WifiBand::Guest2g => "guest_2g",
        WifiBand::Guest5g => "guest_5g",
    }
}

pub fn connection_from_wire_type(wire_type: &crate::scalar::WireType, host: bool) -> Connection {
    match wire_type {
        crate::scalar::WireType::Wired => Connection::Wired,
        crate::scalar::WireType::Ghz24 if host => Connection::Host2g,
        crate::scalar::WireType::Ghz24 => Connection::Guest2g,
        crate::scalar::WireType::Ghz5 if host => Connection::Host5g,
        crate::scalar::WireType::Ghz5 => Connection::Guest5g,
        crate::scalar::WireType::Other(_) => Connection::Unknown,
    }
}

pub fn device_name(raw: &str) -> Option<String> {
    let name = raw.trim();
    if matches!(name, "" | "*" | "--") || name.eq_ignore_ascii_case("unknown") { None } else { Some(name.to_string()) }
}

pub fn connection_from_radio_band(band: &crate::scalar::RadioBand) -> Connection {
    match band {
        crate::scalar::RadioBand::Ghz24 => Connection::Host2g,
        crate::scalar::RadioBand::Ghz5 => Connection::Host5g,
        crate::scalar::RadioBand::Other(_) => Connection::Unknown,
    }
}

pub fn client_totals(devices: &[Device]) -> ClientTotals {
    let count = |predicate: fn(Connection) -> bool| devices.iter().filter(|d| predicate(d.connection)).count();
    ClientTotals {
        total: devices.len(),
        wired: count(|c| c == Connection::Wired),
        wifi: count(|c| matches!(c, Connection::Host2g | Connection::Host5g)),
        guest: count(|c| matches!(c, Connection::Guest2g | Connection::Guest5g)),
        unknown: count(|c| c == Connection::Unknown),
    }
}

pub async fn status(session: &crate::session::Session) -> anyhow::Result<Status> {
    let all: crate::api::StatusAll = crate::session::typed(session, "admin/status?form=all", "read").await?;
    let perf: crate::api::Perf = crate::session::typed(session, "admin/status?form=perf", "read").await?;
    let internet: crate::api::InternetStatus =
        crate::session::typed(session, "admin/status?form=internet", "read").await?;
    let wan: Option<crate::api::WanIpv4Dynamic> = if all.wan_ipv4_conntype == "dhcp" {
        crate::session::typed(session, "admin/network?form=wan_ipv4_dynamic", "read").await.ok()
    } else {
        None
    };
    let clients: Vec<crate::api::WirelessClient> =
        crate::session::typed_list(session, "admin/wireless?form=statistics", "load", &[]).await?;

    let mut devices: Vec<Device> = Vec::new();
    let groups = [
        (Some(&all.access_devices_wired), true),
        (Some(&all.access_devices_wireless_host), true),
        (all.access_devices_wireless_guest.as_ref(), false),
    ];
    for (list, host) in groups {
        for client in list.into_iter().flatten() {
            let device = Device {
                connection: connection_from_wire_type(&client.wire_type, host),
                macaddr: client.macaddr,
                ipaddr: client.ipaddr,
                hostname: device_name(&client.hostname),
                packets_sent: None,
                packets_received: None,
            };
            match devices.iter().position(|d| d.macaddr == client.macaddr) {
                Some(index) => devices[index] = device,
                None => devices.push(device),
            }
        }
    }
    for client in &clients {
        let index = match devices.iter().position(|d| d.macaddr == client.mac) {
            Some(index) => index,
            None => {
                devices.push(Device {
                    connection: connection_from_radio_band(&client.kind),
                    macaddr: client.mac,
                    ipaddr: None,
                    hostname: None,
                    packets_sent: None,
                    packets_received: None,
                });
                devices.len() - 1
            }
        };
        devices[index].packets_sent = Some(client.txpkts);
        devices[index].packets_received = Some(client.rxpkts);
    }

    Ok(Status {
        wan_macaddr: all.wan_macaddr,
        lan_macaddr: all.lan_macaddr,
        wan_ipv4_addr: all.wan_ipv4_ipaddr,
        lan_ipv4_addr: all.lan_ipv4_ipaddr,
        wan_ipv4_gateway: all.wan_ipv4_gateway,
        wan_ipv4_conntype: all.wan_ipv4_conntype,
        wan_link_status: wan.as_ref().map(|w| w.link_status.clone()),
        wan_conn_status: wan.map(|w| w.conn_status),
        internet_status: internet.internet_status,
        internet_v6_status: internet.internet_v6_status,
        wan_ipv6_enable: all.wan_ipv6_enable,
        wan_ipv6_addr: all.wan_ipv6_ip6addr,
        lan_ipv4_dhcp_enable: all.lan_ipv4_dhcp_enable,
        cpu_usage: perf.cpu_usage,
        mem_usage: perf.mem_usage,
        wifi_2g_enable: all.wireless_2g_enable,
        wifi_5g_enable: all.wireless_5g_enable,
        guest_2g_enable: all.guest_2g_enable,
        guest_5g_enable: all.guest_5g_enable,
        clients: client_totals(&devices),
        devices,
    })
}

pub async fn wifi(session: &crate::session::Session, band: WifiBand) -> anyhow::Result<serde_json::Value> {
    let path = format!("admin/wireless?form={}", wifi_band_form(band));
    Ok(match band {
        WifiBand::Host2g | WifiBand::Host5g => {
            serde_json::to_value(crate::session::typed::<crate::api::WirelessHost>(session, &path, "read").await?)?
        }
        WifiBand::Guest2g | WifiBand::Guest5g => {
            serde_json::to_value(crate::session::typed::<crate::api::WirelessGuest>(session, &path, "read").await?)?
        }
    })
}

pub async fn reservation_rows(
    session: &crate::session::Session,
) -> anyhow::Result<(Vec<serde_json::Value>, Option<u64>)> {
    let envelope = crate::session::request_envelope(session, "admin/dhcps?form=reservation", "load").await?;
    let rows = crate::session::list_rows(&envelope["data"], &["list"], "IPv4 reservation")?;
    let max_rules = envelope["others"]["max_rules"]
        .as_u64()
        .or_else(|| envelope["others"]["max_rules"].as_str().and_then(|text| text.trim().parse().ok()));
    Ok((rows, max_rules))
}

pub async fn port_forward_rows(session: &crate::session::Session) -> anyhow::Result<Vec<serde_json::Value>> {
    let data = crate::session::request(session, "admin/nat?form=vs", "load").await?;
    crate::session::list_rows(&data, &["data", "list"], "IPv4 port forward")
}

pub async fn reservations(session: &crate::session::Session) -> anyhow::Result<Reservations> {
    let (rows, max_rules) = reservation_rows(session).await?;
    let rules = rows
        .into_iter()
        .map(|row| serde_json::from_value(row).map_err(|e| anyhow::anyhow!("reservation row: {e}")))
        .collect::<anyhow::Result<Vec<crate::api::DhcpReservation>>>()?;
    Ok(Reservations { max_rules, rules })
}

async fn fetch<T: serde::de::DeserializeOwned + serde::Serialize>(
    session: &crate::session::Session,
    path: &str,
    operation: &str,
) -> anyhow::Result<serde_json::Value> {
    Ok(serde_json::to_value(crate::session::typed::<T>(session, path, operation).await?)?)
}

async fn fetch_list<T: serde::de::DeserializeOwned + serde::Serialize>(
    session: &crate::session::Session,
    path: &str,
    operation: &str,
    keys: &[&str],
) -> anyhow::Result<serde_json::Value> {
    Ok(serde_json::to_value(
        crate::session::typed_list::<T>(session, path, operation, keys).await?,
    )?)
}

pub async fn show(session: &crate::session::Session, topic: Topic) -> anyhow::Result<serde_json::Value> {
    Ok(match topic {
        Topic::Firmware => fetch::<crate::api::Firmware>(session, "admin/firmware?form=upgrade", "read").await?,
        Topic::Internet => {
            fetch::<crate::api::InternetStatus>(session, "admin/status?form=internet", "read").await?
        }
        Topic::SystemMode => fetch::<crate::api::SystemMode>(session, "admin/system?form=sysmode", "read").await?,
        Topic::Time => fetch::<crate::api::TimeSettings>(session, "admin/time?form=settings", "read").await?,
        Topic::Ipv4 => fetch::<crate::api::Ipv4Status>(session, "admin/network?form=status_ipv4", "read").await?,
        Topic::Ipv6 => fetch::<crate::api::Ipv6Status>(session, "admin/network?form=status_ipv6", "read").await?,
        Topic::WanIpv4 => {
            fetch::<crate::api::WanIpv4Dynamic>(session, "admin/network?form=wan_ipv4_dynamic", "read").await?
        }
        Topic::WanIpv6 => {
            fetch::<crate::api::WanIpv6Dynamic>(session, "admin/network?form=wan_ipv6_dynamic", "read").await?
        }
        Topic::WanPppoe => {
            fetch::<crate::api::WanIpv4Pppoe>(session, "admin/network?form=wan_ipv4_pppoe", "read").await?
        }
        Topic::LanIpv4 => fetch::<crate::api::LanIpv4>(session, "admin/network?form=lan_ipv4", "read").await?,
        Topic::LanIpv6 => fetch::<crate::api::LanIpv6>(session, "admin/network?form=lan_ipv6", "read").await?,
        Topic::DhcpServer => fetch::<crate::api::DhcpServer>(session, "admin/dhcps?form=setting", "read").await?,
        Topic::Leases => {
            fetch_list::<crate::api::DhcpClient>(session, "admin/dhcps?form=client", "load", &["dhcp_clients"])
                .await?
        }
        Topic::Reservations => serde_json::to_value(reservations(session).await?)?,
        Topic::Forwards => {
            fetch_list::<crate::api::PortForward>(session, "admin/nat?form=vs", "load", &["data", "list"]).await?
        }
        Topic::AccessControl => serde_json::json!({
            "enable": fetch::<crate::api::AccessControlEnable>(session, "admin/access_control?form=enable", "read").await?,
            "mode": fetch::<crate::api::AccessControlMode>(session, "admin/access_control?form=mode", "read").await?,
        }),
        Topic::RemoteAdmin => {
            fetch::<crate::api::RemoteAdmin>(session, "admin/administration?form=remote", "read").await?
        }
        Topic::Ddns => serde_json::json!({
            "dyndns": fetch::<crate::api::DdnsDyndns>(session, "admin/ddns?form=dyndns", "read").await?,
            "noip": fetch::<crate::api::DdnsNoip>(session, "admin/ddns?form=noip", "read").await?,
        }),
        Topic::Nat => serde_json::json!({
            "alg": fetch::<crate::api::NatAlg>(session, "admin/nat?form=alg", "read").await?,
            "dmz": fetch::<crate::api::NatDmz>(session, "admin/nat?form=dmz", "read").await?,
        }),
        Topic::Vpn => serde_json::json!({
            "openvpn": fetch::<crate::api::OpenVpn>(session, "admin/openvpn?form=config", "read").await?,
            "pptpd": fetch::<crate::api::Pptpd>(session, "admin/pptpd?form=config", "read").await?,
        }),
        Topic::Syslog => {
            fetch_list::<crate::api::SyslogEntry>(session, "admin/syslog?form=log", "load", &[]).await?
        }
    })
}
