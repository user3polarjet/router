pub struct Options {
    pub interval: std::time::Duration,
    pub duration: Option<std::time::Duration>,
}

#[derive(Clone, PartialEq)]
pub struct Client {
    pub ip: Option<std::net::Ipv4Addr>,
    pub name: Option<String>,
    pub connection: crate::router::Connection,
}

pub struct Snapshot {
    pub clients: std::collections::BTreeMap<crate::scalar::Mac, Client>,
    pub wan_ip: std::net::Ipv4Addr,
    pub internet: crate::scalar::ConnStatus,
    pub cpu: f64,
}

fn describe(mac: crate::scalar::Mac, client: &Client) -> String {
    format!(
        "{mac} {} {:?} {}",
        client.name.clone().unwrap_or_else(|| "-".into()),
        client.connection,
        client.ip.map(|ip| ip.to_string()).unwrap_or_else(|| "no ip".into())
    )
}

pub fn clients_of(all: &crate::api::StatusAll) -> std::collections::BTreeMap<crate::scalar::Mac, Client> {
    let groups = [
        (Some(&all.access_devices_wired), true),
        (Some(&all.access_devices_wireless_host), true),
        (all.access_devices_wireless_guest.as_ref(), false),
    ];
    let mut clients = std::collections::BTreeMap::new();
    for (list, host) in groups {
        for client in list.into_iter().flatten() {
            clients.insert(
                client.macaddr,
                Client {
                    ip: client.ipaddr,
                    name: crate::router::device_name(&client.hostname),
                    connection: crate::router::connection_from_wire_type(&client.wire_type, host),
                },
            );
        }
    }
    clients
}

pub fn differences(previous: &Snapshot, current: &Snapshot, cpu_alarm: f64) -> Vec<String> {
    let mut lines = Vec::new();
    for (mac, client) in &current.clients {
        match previous.clients.get(mac) {
            None => lines.push(format!("JOINED   {}", describe(*mac, client))),
            Some(before) if before.ip != client.ip => lines.push(format!(
                "IP JUMP  {} {} changed address {} -> {}",
                mac,
                client.name.clone().unwrap_or_else(|| "-".into()),
                before.ip.map(|ip| ip.to_string()).unwrap_or_else(|| "no ip".into()),
                client.ip.map(|ip| ip.to_string()).unwrap_or_else(|| "no ip".into())
            )),
            Some(before) if before.connection != client.connection => lines.push(format!(
                "MOVED    {} {} {:?} -> {:?}",
                mac,
                client.name.clone().unwrap_or_else(|| "-".into()),
                before.connection,
                client.connection
            )),
            Some(_) => {}
        }
    }
    for (mac, client) in &previous.clients {
        if !current.clients.contains_key(mac) {
            lines.push(format!("LEFT     {}", describe(*mac, client)));
        }
    }
    let mut by_ip: std::collections::BTreeMap<std::net::Ipv4Addr, Vec<crate::scalar::Mac>> = std::collections::BTreeMap::new();
    for (mac, client) in &current.clients {
        if let Some(ip) = client.ip {
            by_ip.entry(ip).or_default().push(*mac);
        }
    }
    for (ip, macs) in by_ip.iter().filter(|(_, macs)| macs.len() > 1) {
        let names: Vec<String> = macs.iter().map(|mac| mac.to_string()).collect();
        lines.push(format!("CONFLICT {ip} is used by {}", names.join(" and ")));
    }
    if previous.wan_ip != current.wan_ip {
        lines.push(format!("WAN IP   changed {} -> {}", previous.wan_ip, current.wan_ip));
    }
    if previous.internet != current.internet {
        lines.push(format!("INTERNET {:?} -> {:?}", previous.internet, current.internet));
    }
    if current.cpu >= cpu_alarm && previous.cpu < cpu_alarm {
        lines.push(format!("CPU      rose to {:.0}%", current.cpu * 100.0));
    }
    lines
}

async fn take(session: &crate::session::Session) -> anyhow::Result<Snapshot> {
    let perf: crate::api::Perf = crate::session::typed(session, "admin/status?form=perf", "read").await?;
    let all: crate::api::StatusAll = crate::session::typed(session, "admin/status?form=all", "read").await?;
    let internet: crate::api::InternetStatus =
        crate::session::typed(session, "admin/status?form=internet", "read").await?;
    Ok(Snapshot {
        clients: clients_of(&all),
        wan_ip: all.wan_ipv4_ipaddr,
        internet: internet.internet_status,
        cpu: perf.cpu_usage,
    })
}

fn stamp(started: std::time::Instant) -> String {
    let seconds = started.elapsed().as_secs();
    format!("+{:02}:{:02}:{:02}", seconds / 3600, seconds / 60 % 60, seconds % 60)
}

async fn new_dhcp_events(
    session: &crate::session::Session,
    last_seen: &mut i64,
    clients: &std::collections::BTreeMap<crate::scalar::Mac, Client>,
) -> anyhow::Result<Vec<String>> {
    let log: Vec<crate::api::SyslogEntry> =
        crate::session::typed_list(session, "admin/syslog?form=log", "load", &[]).await?;
    let events = crate::diagnose::timeline(&log);
    let newest = events.last().map(|event| event.seconds).unwrap_or(*last_seen);
    let name = |mac: crate::scalar::Mac| match clients.get(&mac).and_then(|c| c.name.clone()) {
        Some(name) => format!("{mac} ({name})"),
        None => mac.to_string(),
    };
    let lines = events
        .iter()
        .filter(|event| event.seconds > *last_seen)
        .filter_map(|event| match &event.event {
            crate::diagnose::DhcpEvent::Discover { mac } => {
                Some(format!("DHCP     {} {} started DHCP from scratch (no valid lease)", event.time, name(*mac)))
            }
            crate::diagnose::DhcpEvent::Other => Some(format!("DHCP     {} {}", event.time, event.content)),
            _ => None,
        })
        .collect();
    *last_seen = newest;
    Ok(lines)
}

pub async fn run(session: &crate::session::Session, options: &Options) -> anyhow::Result<()> {
    let started = std::time::Instant::now();
    let mut previous = take(session).await?;
    println!(
        "[{}] watching: {} clients, WAN {}, internet {:?}, CPU {:.0}%",
        stamp(started),
        previous.clients.len(),
        previous.wan_ip,
        previous.internet,
        previous.cpu * 100.0
    );
    for (mac, client) in &previous.clients {
        println!("           {}", describe(*mac, client));
    }
    let mut last_seen = {
        let log: Vec<crate::api::SyslogEntry> =
            crate::session::typed_list(session, "admin/syslog?form=log", "load", &[]).await?;
        crate::diagnose::timeline(&log).last().map(|event| event.seconds).unwrap_or(0)
    };

    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut failures = 0;
    let mut tick = 0u32;
    loop {
        let stop = tokio::select! {
            _ = tokio::time::sleep(options.interval) => false,
            _ = tokio::signal::ctrl_c() => true,
            _ = terminate.recv() => true,
        };
        if stop || options.duration.is_some_and(|limit| started.elapsed() >= limit) {
            println!("[{}] stopped", stamp(started));
            return Ok(());
        }
        tick += 1;
        match take(session).await {
            Ok(current) => {
                failures = 0;
                for line in differences(&previous, &current, 0.8) {
                    println!("[{}] {line}", stamp(started));
                }
                if tick.is_multiple_of(2) {
                    match new_dhcp_events(session, &mut last_seen, &current.clients).await {
                        Ok(lines) => {
                            for line in lines {
                                println!("[{}] {line}", stamp(started));
                            }
                        }
                        Err(error) => println!("[{}] log read failed: {error:#}", stamp(started)),
                    }
                }
                previous = current;
            }
            Err(error) => {
                failures += 1;
                println!("[{}] ROUTER  request failed ({failures}): {error:#}", stamp(started));
                if failures >= 5 {
                    anyhow::bail!("the router stopped answering");
                }
            }
        }
    }
}
