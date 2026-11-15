fn leaves(path: &str, value: &serde_json::Value, out: &mut std::collections::BTreeMap<String, String>) {
    match value {
        serde_json::Value::Object(map) if !map.is_empty() => {
            for (key, inner) in map {
                leaves(&format!("{path}.{key}"), inner, out);
            }
        }
        serde_json::Value::Array(items) if !items.is_empty() => {
            for (index, inner) in items.iter().enumerate() {
                leaves(&format!("{path}[{index}]"), inner, out);
            }
        }
        serde_json::Value::Object(_) => {
            out.insert(path.to_string(), "{}".to_string());
        }
        serde_json::Value::Array(_) => {
            out.insert(path.to_string(), "[]".to_string());
        }
        serde_json::Value::String(text) => {
            out.insert(path.to_string(), text.to_lowercase());
        }
        serde_json::Value::Number(number) => {
            out.insert(path.to_string(), number.as_f64().map(|f| f.to_string()).unwrap_or_else(|| number.to_string()));
        }
        other => {
            out.insert(path.to_string(), other.to_string());
        }
    }
}

fn differences(raw: &serde_json::Value, typed: &serde_json::Value, ignored: &[&str]) -> Vec<String> {
    let mut raw_leaves = std::collections::BTreeMap::new();
    let mut typed_leaves = std::collections::BTreeMap::new();
    leaves("", raw, &mut raw_leaves);
    leaves("", typed, &mut typed_leaves);
    raw_leaves
        .iter()
        .filter(|(path, _)| !ignored.iter().any(|prefix| path.starts_with(prefix)))
        .filter_map(|(path, expected)| match typed_leaves.get(path) {
            None => Some(format!("{path} is sent by the router but missing in the model")),
            Some(actual) if actual != expected => Some(format!("{path}: router {expected:?}, model {actual:?}")),
            Some(_) => None,
        })
        .collect()
}

fn verdict(
    path: &str,
    raw: &serde_json::Value,
    typed: serde_json::Value,
    again: serde_json::Value,
    ignored: &[&str],
) -> anyhow::Result<()> {
    let problems = differences(raw, &typed, ignored);
    anyhow::ensure!(problems.is_empty(), "{path}: {}", problems.join("; "));
    anyhow::ensure!(typed == again, "{path}: serialize/deserialize round trip changed the value");
    Ok(())
}

async fn faithful<T: serde::de::DeserializeOwned + serde::Serialize>(
    session: &archer_c6::session::Session,
    path: &str,
    operation: &str,
    ignored: &[&str],
) -> anyhow::Result<()> {
    let raw = archer_c6::session::request(session, path, operation).await?;
    let model: T = serde_json::from_value(raw.clone()).map_err(|e| anyhow::anyhow!("{path}: {e}"))?;
    let typed = serde_json::to_value(&model)?;
    let again = serde_json::to_value(serde_json::from_value::<T>(typed.clone())?)?;
    verdict(path, &raw, typed, again, ignored)
}

async fn faithful_list<T: serde::de::DeserializeOwned + serde::Serialize>(
    session: &archer_c6::session::Session,
    path: &str,
    operation: &str,
    keys: &[&str],
) -> anyhow::Result<usize> {
    let raw = archer_c6::session::request(session, path, operation).await?;
    let rows = serde_json::Value::Array(archer_c6::session::list_rows(&raw, keys, path)?);
    let models: Vec<T> = serde_json::from_value(rows.clone()).map_err(|e| anyhow::anyhow!("{path}: {e}"))?;
    let typed = serde_json::to_value(&models)?;
    let again = serde_json::to_value(serde_json::from_value::<Vec<T>>(typed.clone())?)?;
    verdict(path, &rows, typed, again, &[])?;
    Ok(models.len())
}

async fn raw(session: &archer_c6::session::Session, path: &str) -> anyhow::Result<serde_json::Value> {
    archer_c6::session::request(session, path, "read").await
}

async fn endpoints(session: &archer_c6::session::Session, failures: &mut Vec<String>) {
    let mut record = |name: &str, result: anyhow::Result<()>| {
        if let Err(error) = result {
            failures.push(format!("{name}: {error:#}"));
        }
    };
    record("firmware", faithful::<archer_c6::api::Firmware>(session, "admin/firmware?form=upgrade", "read", &[]).await);
    record("perf", faithful::<archer_c6::api::Perf>(session, "admin/status?form=perf", "read", &[]).await);
    record("internet", faithful::<archer_c6::api::InternetStatus>(session, "admin/status?form=internet", "read", &[]).await);
    record("sysmode", faithful::<archer_c6::api::SystemMode>(session, "admin/system?form=sysmode", "read", &[]).await);
    record("time", faithful::<archer_c6::api::TimeSettings>(session, "admin/time?form=settings", "read", &[]).await);
    record("ipv4", faithful::<archer_c6::api::Ipv4Status>(session, "admin/network?form=status_ipv4", "read", &[]).await);
    record("ipv6", faithful::<archer_c6::api::Ipv6Status>(session, "admin/network?form=status_ipv6", "read", &[]).await);
    record("wan4", faithful::<archer_c6::api::WanIpv4Dynamic>(session, "admin/network?form=wan_ipv4_dynamic", "read", &[]).await);
    record("wan6", faithful::<archer_c6::api::WanIpv6Dynamic>(session, "admin/network?form=wan_ipv6_dynamic", "read", &[]).await);
    record("pppoe", faithful::<archer_c6::api::WanIpv4Pppoe>(session, "admin/network?form=wan_ipv4_pppoe", "read", &[]).await);
    record("lan4", faithful::<archer_c6::api::LanIpv4>(session, "admin/network?form=lan_ipv4", "read", &[]).await);
    record("lan6", faithful::<archer_c6::api::LanIpv6>(session, "admin/network?form=lan_ipv6", "read", &[]).await);
    record("dhcp server", faithful::<archer_c6::api::DhcpServer>(session, "admin/dhcps?form=setting", "read", &[]).await);
    record("access enable", faithful::<archer_c6::api::AccessControlEnable>(session, "admin/access_control?form=enable", "read", &[]).await);
    record("access mode", faithful::<archer_c6::api::AccessControlMode>(session, "admin/access_control?form=mode", "read", &[]).await);
    record("remote admin", faithful::<archer_c6::api::RemoteAdmin>(session, "admin/administration?form=remote", "read", &[]).await);
    record("dyndns", faithful::<archer_c6::api::DdnsDyndns>(session, "admin/ddns?form=dyndns", "read", &[]).await);
    record("noip", faithful::<archer_c6::api::DdnsNoip>(session, "admin/ddns?form=noip", "read", &[]).await);
    record("alg", faithful::<archer_c6::api::NatAlg>(session, "admin/nat?form=alg", "read", &[]).await);
    record("dmz", faithful::<archer_c6::api::NatDmz>(session, "admin/nat?form=dmz", "read", &[]).await);
    record("openvpn", faithful::<archer_c6::api::OpenVpn>(session, "admin/openvpn?form=config", "read", &[]).await);
    record("pptpd", faithful::<archer_c6::api::Pptpd>(session, "admin/pptpd?form=config", "read", &[]).await);
    record("wifi 2g", faithful::<archer_c6::api::WirelessHost>(session, "admin/wireless?form=wireless_2g", "read", &[]).await);
    record("wifi 5g", faithful::<archer_c6::api::WirelessHost>(session, "admin/wireless?form=wireless_5g", "read", &[]).await);
    record("guest 2g", faithful::<archer_c6::api::WirelessGuest>(session, "admin/wireless?form=guest_2g", "read", &[]).await);
    record("guest 5g", faithful::<archer_c6::api::WirelessGuest>(session, "admin/wireless?form=guest_5g", "read", &[]).await);
    record("status all", faithful::<archer_c6::api::StatusAll>(
            session,
            "admin/status?form=all",
            "read",
            &[".wireless_2g_", ".wireless_5g_", ".guest_2g_", ".guest_5g_"],
        ).await);

    let lists = [
        faithful_list::<archer_c6::api::DhcpClient>(session, "admin/dhcps?form=client", "load", &["dhcp_clients"]).await,
        faithful_list::<archer_c6::api::WirelessClient>(session, "admin/wireless?form=statistics", "load", &[]).await,
        faithful_list::<archer_c6::api::DhcpReservation>(session, "admin/dhcps?form=reservation", "load", &["list"]).await,
        faithful_list::<archer_c6::api::PortForward>(session, "admin/nat?form=vs", "load", &["data", "list"]).await,
        faithful_list::<archer_c6::api::SyslogEntry>(session, "admin/syslog?form=log", "load", &[]).await,
    ];
    for (name, result) in ["leases", "wifi clients", "reservations", "forwards", "syslog"].iter().zip(lists) {
        record(name, result.map(|_| ()));
    }
}

async fn wifi_forms_match_status(session: &archer_c6::session::Session) -> anyhow::Result<()> {
    let all = raw(session, "admin/status?form=all").await?;
    let mut problems = Vec::new();
    for form in ["wireless_2g", "wireless_5g", "guest_2g", "guest_5g"] {
        let dedicated = raw(session, &format!("admin/wireless?form={form}")).await?;
        let object = dedicated.as_object().ok_or_else(|| anyhow::anyhow!("{form}: not an object"))?;
        for (key, value) in object {
            let combined = &all[format!("{form}_{key}")];
            if combined != value {
                problems.push(format!("{form}_{key}: status {combined}, form {value}"));
            }
        }
    }
    anyhow::ensure!(problems.is_empty(), "{}", problems.join("; "));
    Ok(())
}

async fn network_is_consistent(session: &archer_c6::session::Session) -> anyhow::Result<()> {
    let all: archer_c6::api::StatusAll = archer_c6::session::typed(session, "admin/status?form=all", "read").await?;
    let ipv4: archer_c6::api::Ipv4Status = archer_c6::session::typed(session, "admin/network?form=status_ipv4", "read").await?;
    let ipv6: archer_c6::api::Ipv6Status = archer_c6::session::typed(session, "admin/network?form=status_ipv6", "read").await?;
    let lan: archer_c6::api::LanIpv4 = archer_c6::session::typed(session, "admin/network?form=lan_ipv4", "read").await?;
    let wan: archer_c6::api::WanIpv4Dynamic = archer_c6::session::typed(session, "admin/network?form=wan_ipv4_dynamic", "read").await?;
    let dhcp: archer_c6::api::DhcpServer = archer_c6::session::typed(session, "admin/dhcps?form=setting", "read").await?;

    anyhow::ensure!(all.lan_macaddr == ipv4.lan_macaddr && ipv4.lan_macaddr == lan.macaddr, "lan mac differs between forms");
    anyhow::ensure!(all.wan_macaddr == ipv4.wan_macaddr, "wan mac differs");
    anyhow::ensure!(all.lan_ipv4_ipaddr == ipv4.lan_ipv4_ipaddr && ipv4.lan_ipv4_ipaddr == lan.ipaddr, "lan ip differs");
    anyhow::ensure!(all.wan_ipv4_ipaddr == ipv4.wan_ipv4_ipaddr, "wan ip differs between status forms");
    anyhow::ensure!(all.wan_ipv6_ip6addr == ipv6.wan_ipv6_ip6addr && all.wan_ipv6_enable == ipv6.wan_ipv6_enable, "wan ipv6 differs");
    anyhow::ensure!(dhcp.gateway == lan.ipaddr, "dhcp gateway is not the lan address");
    anyhow::ensure!(all.lan_ipv4_dhcp_enable == dhcp.enable, "dhcp enable differs between forms");

    if all.wan_ipv4_conntype == "dhcp" {
        anyhow::ensure!(wan.ipaddr == all.wan_ipv4_ipaddr, "dynamic wan ip differs from status");
        anyhow::ensure!(wan.gateway == all.wan_ipv4_gateway, "dynamic wan gateway differs from status");
        anyhow::ensure!(wan.netmask == all.wan_ipv4_netmask, "dynamic wan netmask differs from status");
        anyhow::ensure!(wan.pri_dns == all.wan_ipv4_pridns && wan.snd_dns == all.wan_ipv4_snddns, "dynamic wan dns differs");
    }

    let mask = u32::from(all.lan_ipv4_netmask);
    let network = u32::from(all.lan_ipv4_ipaddr) & mask;
    let start = u32::from(dhcp.ipaddr_start);
    let end = u32::from(dhcp.ipaddr_end);
    anyhow::ensure!(start <= end, "dhcp range is reversed");
    anyhow::ensure!(start & mask == network && end & mask == network, "dhcp range is outside the lan subnet");
    anyhow::ensure!(mask.leading_ones() + mask.trailing_zeros() == 32, "lan netmask is not contiguous");
    Ok(())
}

async fn clients_are_consistent(session: &archer_c6::session::Session) -> anyhow::Result<()> {
    let status = archer_c6::router::status(session).await?;
    let leases: Vec<archer_c6::api::DhcpClient> =
        archer_c6::session::typed_list(session, "admin/dhcps?form=client", "load", &["dhcp_clients"]).await?;
    let stats: Vec<archer_c6::api::WirelessClient> =
        archer_c6::session::typed_list(session, "admin/wireless?form=statistics", "load", &[]).await?;

    let c = &status.clients;
    anyhow::ensure!(c.total == status.devices.len(), "client total differs from device list");
    anyhow::ensure!(c.wired + c.wifi + c.guest + c.unknown == c.total, "client categories do not add up");
    anyhow::ensure!(c.unknown == 0, "{} clients have an unknown connection type", c.unknown);

    let mut macs: Vec<_> = status.devices.iter().map(|d| d.macaddr).collect();
    macs.sort();
    macs.dedup();
    anyhow::ensure!(macs.len() == status.devices.len(), "duplicate device MACs");

    for client in &stats {
        let device = status.devices.iter().find(|d| d.macaddr == client.mac);
        let device = device.ok_or_else(|| anyhow::anyhow!("wifi statistics client {} is not in status", client.mac))?;
        anyhow::ensure!(device.connection != archer_c6::router::Connection::Wired, "{} is wired but has wifi stats", client.mac);
        anyhow::ensure!(device.packets_sent.is_some() && device.packets_received.is_some(), "{} packet counters not merged", client.mac);
    }
    for device in status.devices.iter().filter(|d| d.connection == archer_c6::router::Connection::Wired) {
        anyhow::ensure!(!stats.iter().any(|s| s.mac == device.macaddr), "{} is wired but in wifi statistics", device.macaddr);
    }

    let lan: archer_c6::api::Ipv4Status = archer_c6::session::typed(session, "admin/network?form=status_ipv4", "read").await?;
    let mask = u32::from(lan.lan_ipv4_netmask);
    let network = u32::from(lan.lan_ipv4_ipaddr) & mask;
    for device in &status.devices {
        match leases.iter().find(|l| l.macaddr == device.macaddr) {
            Some(lease) => {
                anyhow::ensure!(Some(lease.ipaddr) == device.ipaddr, "{}: status ip {:?}, lease ip {}", device.macaddr, device.ipaddr, lease.ipaddr);
                anyhow::ensure!(
                    archer_c6::router::device_name(&lease.name) == device.hostname,
                    "{}: status name {:?}, lease name {:?}",
                    device.macaddr,
                    device.hostname,
                    lease.name
                );
            }
            None => {
                let ip = device.ipaddr.ok_or_else(|| anyhow::anyhow!("{} has neither a lease nor an ip", device.macaddr))?;
                anyhow::ensure!(u32::from(ip) & mask == network, "{} ({ip}) has no lease and is outside the lan", device.macaddr);
            }
        }
    }
    Ok(())
}

async fn values_are_sane(session: &archer_c6::session::Session) -> anyhow::Result<()> {
    let perf: archer_c6::api::Perf = archer_c6::session::typed(session, "admin/status?form=perf", "read").await?;
    anyhow::ensure!((0.0..=1.0).contains(&perf.cpu_usage) && (0.0..=1.0).contains(&perf.mem_usage), "usage outside 0..1");

    let firmware: archer_c6::api::Firmware = archer_c6::session::typed(session, "admin/firmware?form=upgrade", "read").await?;
    anyhow::ensure!(firmware.hardware_version.contains("C6"), "unexpected hardware {}", firmware.hardware_version);

    let time: archer_c6::api::TimeSettings = archer_c6::session::typed(session, "admin/time?form=settings", "read").await?;
    let clock: Vec<&str> = time.time.split(':').collect();
    anyhow::ensure!(
        clock.len() == 3 && clock.iter().all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_digit())),
        "bad router time {}",
        time.time
    );
    let date: Vec<&str> = time.date.split('/').collect();
    anyhow::ensure!(date.len() == 3 && date[2].len() == 4, "bad router date {}", time.date);

    let log: Vec<archer_c6::api::SyslogEntry> =
        archer_c6::session::typed_list(session, "admin/syslog?form=log", "load", &[]).await?;
    anyhow::ensure!(!log.is_empty(), "system log is empty");
    anyhow::ensure!(log.iter().all(|e| e.time.len() == 19), "bad log timestamps");
    anyhow::ensure!(log.windows(2).all(|pair| pair[0].time >= pair[1].time), "system log is not newest-first");

    let band: archer_c6::api::WirelessHost = archer_c6::session::typed(session, "admin/wireless?form=wireless_5g", "read").await?;
    anyhow::ensure!(band.mumimo.is_some() && band.txbf_enable.is_some(), "5 GHz form lost its band-specific fields");
    let band: archer_c6::api::WirelessHost = archer_c6::session::typed(session, "admin/wireless?form=wireless_2g", "read").await?;
    anyhow::ensure!(band.mumimo.is_none() && band.txbf_enable.is_none(), "2.4 GHz form gained 5 GHz fields");
    Ok(())
}

async fn error_paths(session: &archer_c6::session::Session) -> anyhow::Result<()> {
    let unknown = archer_c6::session::request(session, "admin/network?form=lan", "read").await;
    let message = format!("{:#}", unknown.err().ok_or_else(|| anyhow::anyhow!("unknown form was accepted"))?);
    anyhow::ensure!(message.contains("no such callback"), "unexpected error for an unknown form: {message}");

    let wrong_operation = archer_c6::session::request(session, "admin/firmware?form=upgrade", "load").await;
    anyhow::ensure!(wrong_operation.is_err(), "unsupported operation was accepted");

    let wrong_type = archer_c6::session::typed::<archer_c6::api::Perf>(session, "admin/firmware?form=upgrade", "read").await;
    anyhow::ensure!(wrong_type.is_err(), "a payload of the wrong shape deserialized");
    Ok(())
}

async fn diagnosis_is_sound(session: &archer_c6::session::Session) -> anyhow::Result<()> {
    let options = archer_c6::diagnose::Options {
        samples: 3,
        interval: std::time::Duration::from_secs(2),
    };
    let report = archer_c6::diagnose::run(session, &options).await?;
    anyhow::ensure!(!report.findings.is_empty(), "the diagnosis produced no findings");
    anyhow::ensure!(report.load.cpu_samples.len() == 3, "wrong number of cpu samples");
    anyhow::ensure!(report.load.cpu_samples.iter().all(|c| (0.0..=1.0).contains(c)), "cpu sample outside 0..1");
    anyhow::ensure!(
        report.findings.windows(2).all(|pair| pair[0].severity >= pair[1].severity),
        "findings are not ordered by severity"
    );
    anyhow::ensure!(report.load.top_clients.len() <= 5, "too many top clients");
    anyhow::ensure!(
        report.load.top_clients.windows(2).all(|pair| pair[0].packets_per_second >= pair[1].packets_per_second),
        "top clients are not sorted"
    );

    let log: Vec<archer_c6::api::SyslogEntry> =
        archer_c6::session::typed_list(session, "admin/syslog?form=log", "load", &[]).await?;
    let dhcp_lines = log.iter().filter(|entry| entry.kind == "DHCPS").count();
    let events = archer_c6::diagnose::timeline(&log);
    anyhow::ensure!(events.len() == dhcp_lines, "{} of {dhcp_lines} DHCP log lines have an unreadable timestamp", dhcp_lines - events.len());
    anyhow::ensure!(events.windows(2).all(|pair| pair[0].seconds <= pair[1].seconds), "timeline is not chronological");
    let unknown: Vec<&str> = events
        .iter()
        .filter(|event| event.event == archer_c6::diagnose::DhcpEvent::Other)
        .map(|event| event.content.as_str())
        .take(3)
        .collect();
    anyhow::ensure!(unknown.is_empty(), "DHCP log lines in a form the parser does not know: {unknown:?}");
    Ok(())
}

#[tokio::test]
async fn router_read_only() {
    let secret = archer_c6::config::load_secret("secret.toml").unwrap();
    let Some(password) = secret.password else {
        eprintln!("skipped: no password in secret.toml");
        return;
    };
    let host = match secret.ip {
        Some(host) => host,
        None => archer_c6::config::default_gateway().unwrap().to_string(),
    };
    let username = secret.username.unwrap_or_else(|| "admin".to_string());
    let session = archer_c6::session::login(&host, &username, &password, 30).await.unwrap();

    let mut failures = Vec::new();
    endpoints(&session, &mut failures).await;
    let checks = [
        ("wifi forms vs status", wifi_forms_match_status(&session).await),
        ("network consistency", network_is_consistent(&session).await),
        ("client consistency", clients_are_consistent(&session).await),
        ("value sanity", values_are_sane(&session).await),
        ("error paths", error_paths(&session).await),
        ("diagnosis", diagnosis_is_sound(&session).await),
    ];
    for (name, result) in checks {
        if let Err(error) = result {
            failures.push(format!("{name}: {error:#}"));
        }
    }

    let logout = archer_c6::session::logout(&session).await;
    let after_logout = archer_c6::session::request(&session, "admin/firmware?form=upgrade", "read").await;
    if after_logout.is_ok() {
        failures.push("session still works after logout".to_string());
    }
    if let Err(error) = logout {
        failures.push(format!("logout: {error:#}"));
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}
