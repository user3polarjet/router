#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Problem,
}

#[derive(Debug, serde::Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub area: &'static str,
    pub message: String,
}

#[derive(Debug, serde::Serialize)]
pub struct ClientRate {
    pub macaddr: crate::scalar::Mac,
    pub hostname: Option<String>,
    pub connection: crate::router::Connection,
    pub packets_per_second: f64,
}

#[derive(Debug, serde::Serialize)]
pub struct Load {
    pub cpu_samples: Vec<f64>,
    pub memory: f64,
    pub window_seconds: f64,
    pub total_packets_per_second: f64,
    pub top_clients: Vec<ClientRate>,
}

#[derive(Debug, serde::Serialize)]
pub struct Report {
    pub findings: Vec<Finding>,
    pub load: Load,
}

pub struct Options {
    pub samples: u32,
    pub interval: std::time::Duration,
}

#[derive(Clone, Debug, PartialEq)]
pub enum DhcpEvent {
    Discover { mac: crate::scalar::Mac },
    Offer { mac: crate::scalar::Mac, ip: std::net::Ipv4Addr, dns: std::net::Ipv4Addr },
    Request { mac: crate::scalar::Mac, ip: std::net::Ipv4Addr },
    Ack { mac: crate::scalar::Mac, ip: std::net::Ipv4Addr, dns: std::net::Ipv4Addr },
    Other,
}

pub struct TimedEvent {
    pub seconds: i64,
    pub time: String,
    pub event: DhcpEvent,
    pub content: String,
}

fn finding(severity: Severity, area: &'static str, message: String) -> Finding {
    Finding { severity, area, message }
}

pub fn parse_event(content: &str) -> DhcpEvent {
    let text = content.split_once("] ").map(|(_, rest)| rest).unwrap_or(content);
    let words: Vec<&str> = text.split_whitespace().collect();
    let parsed = match words.as_slice() {
        ["receive", "discover", "from", mac] => mac.parse().ok().map(|mac| DhcpEvent::Discover { mac }),
        ["receive", "request", "ip", ip, "from", mac] => match (mac.parse(), ip.parse()) {
            (Ok(mac), Ok(ip)) => Some(DhcpEvent::Request { mac, ip }),
            _ => None,
        },
        ["send", kind @ ("offer" | "ack"), "ip", ip, "and", "dns", dns, "to", mac] => {
            match (mac.parse(), ip.parse(), dns.parse()) {
                (Ok(mac), Ok(ip), Ok(dns)) if *kind == "offer" => Some(DhcpEvent::Offer { mac, ip, dns }),
                (Ok(mac), Ok(ip), Ok(dns)) => Some(DhcpEvent::Ack { mac, ip, dns }),
                _ => None,
            }
        }
        _ => None,
    };
    parsed.unwrap_or(DhcpEvent::Other)
}

pub fn epoch_seconds(time: &str) -> Option<i64> {
    let (date, clock) = time.split_once(' ')?;
    let mut date = date.split('-').map(|part| part.parse::<i64>());
    let mut clock = clock.split(':').map(|part| part.parse::<i64>());
    let (year, month, day) = (date.next()?.ok()?, date.next()?.ok()?, date.next()?.ok()?);
    let (hour, minute, second) = (clock.next()?.ok()?, clock.next()?.ok()?, clock.next()?.ok()?);
    let shifted_year = if month <= 2 { year - 1 } else { year };
    let era = shifted_year.div_euclid(400);
    let year_of_era = shifted_year - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146097 + day_of_era - 719468;
    Some(days * 86400 + hour * 3600 + minute * 60 + second)
}

pub fn timeline(log: &[crate::api::SyslogEntry]) -> Vec<TimedEvent> {
    let mut events: Vec<TimedEvent> = log
        .iter()
        .filter(|entry| entry.kind == "DHCPS")
        .filter_map(|entry| {
            Some(TimedEvent {
                seconds: epoch_seconds(&entry.time)?,
                time: entry.time.clone(),
                event: parse_event(&entry.content),
                content: entry.content.clone(),
            })
        })
        .collect();
    events.reverse();
    events.sort_by_key(|event| event.seconds);
    events
}

fn event_mac(event: &DhcpEvent) -> Option<crate::scalar::Mac> {
    match event {
        DhcpEvent::Discover { mac }
        | DhcpEvent::Offer { mac, .. }
        | DhcpEvent::Request { mac, .. }
        | DhcpEvent::Ack { mac, .. } => Some(*mac),
        DhcpEvent::Other => None,
    }
}

fn is_random_mac(mac: crate::scalar::Mac) -> bool {
    mac.0[0] & 0x02 != 0
}

pub fn is_shared_or_private(ip: std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_private() || (octets[0] == 100 && octets[1] & 0xC0 == 64)
}

fn label(mac: crate::scalar::Mac, leases: &[crate::api::DhcpClient], devices: &[crate::router::Device]) -> String {
    let name = leases
        .iter()
        .find(|lease| lease.macaddr == mac)
        .and_then(|lease| crate::router::device_name(&lease.name))
        .or_else(|| devices.iter().find(|d| d.macaddr == mac).and_then(|d| d.hostname.clone()));
    match name {
        Some(name) => format!("{mac} ({name})"),
        None => mac.to_string(),
    }
}

pub fn analyze_dhcp_log(
    events: &[TimedEvent],
    leases: &[crate::api::DhcpClient],
    devices: &[crate::router::Device],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let (Some(first), Some(last)) = (events.first(), events.last()) else {
        findings.push(finding(Severity::Warning, "dhcp-log", "the router log holds no DHCP events".into()));
        return findings;
    };
    let hours = (last.seconds - first.seconds) as f64 / 3600.0;
    findings.push(finding(
        Severity::Info,
        "dhcp-log",
        format!("{} DHCP events between {} and {} ({hours:.1} hours)", events.len(), first.time, last.time),
    ));

    let other: Vec<&TimedEvent> = events.iter().filter(|e| e.event == DhcpEvent::Other).collect();
    if !other.is_empty() {
        let sample: Vec<&str> = other.iter().take(3).map(|e| e.content.as_str()).collect();
        findings.push(finding(
            Severity::Warning,
            "dhcp-log",
            format!("{} DHCP log lines have a form this tool does not know (NAK, decline, conflict?): {sample:?}", other.len()),
        ));
    }

    let mut macs: Vec<crate::scalar::Mac> = events.iter().filter_map(|e| event_mac(&e.event)).collect();
    macs.sort();
    macs.dedup();

    let mut unanswered_total = 0;
    let mut request_total = 0;
    for mac in &macs {
        let own: Vec<&TimedEvent> = events.iter().filter(|e| event_mac(&e.event) == Some(*mac)).collect();
        let name = label(*mac, leases, devices);

        let mut acked: Vec<(&str, std::net::Ipv4Addr)> = Vec::new();
        for event in &own {
            if let DhcpEvent::Ack { ip, .. } = event.event
                && acked.last().map(|(_, previous)| *previous) != Some(ip)
            {
                acked.push((event.time.as_str(), ip));
            }
        }
        if acked.len() > 1 {
            let history: Vec<String> = acked.iter().map(|(time, ip)| format!("{ip} at {time}")).collect();
            findings.push(finding(
                Severity::Problem,
                "ip-jumps",
                format!("{name} was given different addresses: {}", history.join(" -> ")),
            ));
        }

        let requests: Vec<&&TimedEvent> = own.iter().filter(|e| matches!(e.event, DhcpEvent::Request { .. })).collect();
        request_total += requests.len();
        let unanswered: Vec<&str> = own
            .iter()
            .enumerate()
            .filter(|(_, e)| matches!(e.event, DhcpEvent::Request { .. }))
            .filter(|(index, e)| {
                !own[*index..]
                    .iter()
                    .take(6)
                    .any(|later| matches!(later.event, DhcpEvent::Ack { .. }) && later.seconds - e.seconds <= 3)
            })
            .map(|(_, e)| e.time.as_str())
            .collect();
        unanswered_total += unanswered.len();
        if unanswered.len() >= 3 {
            findings.push(finding(
                Severity::Warning,
                "dhcp-unanswered",
                format!("{name}: {} of {} DHCP requests got no ACK, at {:?}", unanswered.len(), requests.len(), unanswered),
            ));
        }

        let discovers: Vec<&&TimedEvent> = own.iter().filter(|e| matches!(e.event, DhcpEvent::Discover { .. })).collect();
        let per_day = discovers.len() as f64 / (hours / 24.0).max(1.0);
        if per_day > 30.0 {
            findings.push(finding(
                Severity::Warning,
                "dhcp-storm",
                format!("{name} restarts DHCP from scratch {per_day:.0} times a day (it keeps losing its connection or lease)"),
            ));
        }

        let rapid = requests.windows(2).filter(|pair| pair[1].seconds - pair[0].seconds < 60).count();
        if rapid > 5 {
            findings.push(finding(
                Severity::Warning,
                "dhcp-storm",
                format!("{name} sent {rapid} DHCP requests less than a minute apart"),
            ));
        }
    }
    if request_total > 0 {
        let share = unanswered_total as f64 * 100.0 / request_total as f64;
        let severity = if share >= 5.0 { Severity::Problem } else if share >= 2.0 { Severity::Warning } else { Severity::Info };
        findings.push(finding(
            severity,
            "dhcp-unanswered",
            format!("{unanswered_total} of {request_total} DHCP requests ({share:.1}%) were not followed by an ACK"),
        ));
    }

    let random: Vec<&crate::scalar::Mac> = macs.iter().filter(|m| is_random_mac(**m)).collect();
    if !random.is_empty() {
        findings.push(finding(
            Severity::Info,
            "mac-privacy",
            format!(
                "{} of {} DHCP clients use a randomised (private) MAC address. A phone that rotates its MAC shows up as a new device and can receive a new IP",
                random.len(),
                macs.len()
            ),
        ));
    }

    let mut no_dns: Vec<crate::scalar::Mac> = events
        .iter()
        .filter_map(|e| match e.event {
            DhcpEvent::Ack { mac, dns, .. } if dns.is_unspecified() => Some(mac),
            _ => None,
        })
        .collect();
    no_dns.sort();
    no_dns.dedup();
    for mac in no_dns {
        let also_with_dns = events
            .iter()
            .any(|e| matches!(e.event, DhcpEvent::Ack { mac: m, dns, .. } if m == mac && !dns.is_unspecified()));
        findings.push(finding(
            if also_with_dns { Severity::Warning } else { Severity::Info },
            "dns-handout",
            format!(
                "{} is always answered with DNS 0.0.0.0{}",
                label(mac, leases, devices),
                if also_with_dns { ", but sometimes with a real DNS server" } else { " (it probably does not ask for a DNS option)" }
            ),
        ));
    }
    findings
}

pub fn analyze_dhcp_config(
    server: &crate::api::DhcpServer,
    lan: &crate::api::Ipv4Status,
    leases: &[crate::api::DhcpClient],
    devices: &[crate::router::Device],
    reservations: &crate::router::Reservations,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let start = u32::from(server.ipaddr_start);
    let end = u32::from(server.ipaddr_end);
    let router = u32::from(lan.lan_ipv4_ipaddr);
    let pool = end.saturating_sub(start) + 1;
    let in_pool = |ip: std::net::Ipv4Addr| (start..=end).contains(&u32::from(ip));

    findings.push(finding(
        Severity::Info,
        "dhcp-config",
        format!(
            "DHCP server is {}, pool {}-{} ({pool} addresses), lease time {} min, router {}",
            server.enable, server.ipaddr_start, server.ipaddr_end, server.leasetime, lan.lan_ipv4_ipaddr
        ),
    ));
    if !server.enable.is_on() {
        findings.push(finding(Severity::Problem, "dhcp-config", "the DHCP server is switched off".into()));
    }
    if server.gateway != lan.lan_ipv4_ipaddr {
        findings.push(finding(
            Severity::Problem,
            "dhcp-config",
            format!("DHCP hands out gateway {} but the router is {}", server.gateway, lan.lan_ipv4_ipaddr),
        ));
    }
    if (start..=end).contains(&router) {
        findings.push(finding(
            Severity::Warning,
            "dhcp-config",
            format!(
                "the router's own address {} lies inside its DHCP pool; the default setup keeps the router outside the pool, and a client ending up with the router's address breaks the whole network",
                lan.lan_ipv4_ipaddr
            ),
        ));
    }
    let used = leases.iter().filter(|lease| in_pool(lease.ipaddr)).count();
    let share = used as f64 * 100.0 / pool as f64;
    findings.push(finding(
        if share >= 80.0 { Severity::Problem } else if share >= 50.0 { Severity::Warning } else { Severity::Info },
        "dhcp-pool",
        format!("{used} of {pool} pool addresses are leased ({share:.0}%)"),
    ));
    if server.leasetime < 60 {
        findings.push(finding(
            Severity::Warning,
            "dhcp-config",
            format!("lease time is only {} minutes; clients renew very often and drift when the router is busy", server.leasetime),
        ));
    }
    if server.pri_dns.is_none() && server.snd_dns.is_none() {
        findings.push(finding(
            Severity::Info,
            "dhcp-config",
            "no DNS servers are configured in the DHCP server, so clients use the router as their DNS proxy".into(),
        ));
    }
    let mask = u32::from(lan.lan_ipv4_netmask);
    if u32::from(server.ipaddr_start) & mask != router & mask || u32::from(server.ipaddr_end) & mask != router & mask {
        findings.push(finding(Severity::Problem, "dhcp-config", "the DHCP pool is outside the LAN subnet".into()));
    }

    let mut by_ip: std::collections::BTreeMap<std::net::Ipv4Addr, Vec<crate::scalar::Mac>> = std::collections::BTreeMap::new();
    for lease in leases {
        by_ip.entry(lease.ipaddr).or_default().push(lease.macaddr);
    }
    for device in devices {
        if let Some(ip) = device.ipaddr {
            let macs = by_ip.entry(ip).or_default();
            if !macs.contains(&device.macaddr) {
                macs.push(device.macaddr);
            }
        }
    }
    for (ip, macs) in by_ip.iter().filter(|(_, macs)| macs.len() > 1) {
        let names: Vec<String> = macs.iter().map(|m| label(*m, leases, devices)).collect();
        findings.push(finding(
            Severity::Problem,
            "ip-conflict",
            format!("{ip} is claimed by {} devices: {}", macs.len(), names.join(", ")),
        ));
    }
    for device in devices {
        if device.ipaddr == Some(lan.lan_ipv4_ipaddr) {
            findings.push(finding(
                Severity::Problem,
                "ip-conflict",
                format!("{} uses the router's own address", label(device.macaddr, leases, devices)),
            ));
        }
        if device.ipaddr.is_some() && !leases.iter().any(|lease| lease.macaddr == device.macaddr) {
            findings.push(finding(
                Severity::Info,
                "dhcp-config",
                format!(
                    "{} is connected with {} but is not in the lease table",
                    label(device.macaddr, leases, devices),
                    device.ipaddr.map(|ip| ip.to_string()).unwrap_or_default()
                ),
            ));
        }
    }
    findings.push(finding(
        Severity::Info,
        "dhcp-config",
        format!(
            "{} address reservations of {} possible; devices without a reservation can change address when their lease expires",
            reservations.rules.len(),
            reservations.max_rules.map(|n| n.to_string()).unwrap_or_else(|| "?".into())
        ),
    ));
    findings
}

pub fn analyze_wan(
    status: &crate::router::Status,
    lan: &crate::api::Ipv4Status,
    wan: Option<&crate::api::WanIpv4Dynamic>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.push(finding(
        Severity::Info,
        "wan",
        format!(
            "WAN is {} with address {}, gateway {}, DNS {} and {}",
            lan.wan_ipv4_conntype, lan.wan_ipv4_ipaddr, lan.wan_ipv4_gateway, lan.wan_ipv4_pridns, lan.wan_ipv4_snddns
        ),
    ));
    if status.internet_status != crate::scalar::ConnStatus::Connected {
        findings.push(finding(Severity::Problem, "wan", format!("internet status is {:?}", status.internet_status)));
    }
    if let Some(wan) = wan {
        if wan.link_status != "plugged" {
            findings.push(finding(Severity::Problem, "wan", format!("WAN cable status is {:?}", wan.link_status)));
        }
        if wan.conn_status != crate::scalar::ConnStatus::Connected {
            findings.push(finding(Severity::Problem, "wan", format!("WAN connection is {:?}", wan.conn_status)));
        }
        if wan.mtu != 1500 {
            findings.push(finding(Severity::Info, "wan", format!("WAN MTU is {}", wan.mtu)));
        }
    }
    if is_shared_or_private(lan.wan_ipv4_ipaddr) {
        findings.push(finding(
            Severity::Info,
            "wan",
            format!(
                "the WAN address {} is private or carrier-grade NAT: this router sits behind another NAT (ISP or modem). The public address belongs to that device and can change without this router noticing, and port forwarding from outside cannot work",
                lan.wan_ipv4_ipaddr
            ),
        ));
    }
    let wan_mask = u32::from(lan.wan_ipv4_netmask);
    let lan_mask = u32::from(lan.lan_ipv4_netmask);
    let overlap_mask = wan_mask.min(lan_mask);
    if u32::from(lan.wan_ipv4_ipaddr) & overlap_mask == u32::from(lan.lan_ipv4_ipaddr) & overlap_mask {
        findings.push(finding(Severity::Problem, "wan", "the WAN and LAN subnets overlap, routing will be broken".into()));
    }
    if lan.wan_ipv4_pridns == lan.wan_ipv4_snddns {
        findings.push(finding(Severity::Warning, "wan", "both WAN DNS servers are the same address".into()));
    }
    findings
}

pub fn analyze_radio(
    band2: &crate::api::WirelessHost,
    band5: &crate::api::WirelessHost,
    devices: &[crate::router::Device],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let on_2g = devices.iter().filter(|d| d.connection == crate::router::Connection::Host2g).count();
    let on_5g = devices.iter().filter(|d| d.connection == crate::router::Connection::Host5g).count();
    findings.push(finding(
        Severity::Info,
        "wifi",
        format!(
            "2.4 GHz: channel {} (now {}), {} {}, power {}, {on_2g} clients; 5 GHz: channel {} (now {}), {} {}, power {}, {on_5g} clients",
            band2.channel, band2.current_channel, band2.hwmode, band2.htmode, band2.txpower,
            band5.channel, band5.current_channel, band5.hwmode, band5.htmode, band5.txpower
        ),
    ));
    if !matches!(band2.current_channel, 1 | 6 | 11) {
        findings.push(finding(
            Severity::Warning,
            "wifi",
            format!("2.4 GHz is on channel {}, which overlaps the common channels 1, 6 and 11", band2.current_channel),
        ));
    }
    if on_2g > 2 * on_5g.max(1) {
        findings.push(finding(
            Severity::Info,
            "wifi",
            format!("{on_2g} clients sit on the crowded 2.4 GHz band against {on_5g} on 5 GHz"),
        ));
    }
    for (name, band) in [("2.4 GHz", band2), ("5 GHz", band5)] {
        if band.encryption == crate::scalar::Encryption::None {
            findings.push(finding(Severity::Problem, "wifi", format!("the {name} network has no encryption")));
        }
        if band.psk_cipher.to_lowercase().contains("tkip") || band.psk_version.to_lowercase() == "wpa" {
            findings.push(finding(
                Severity::Warning,
                "wifi",
                format!("the {name} network allows TKIP or WPA1 ({} / {}), which is slow and weak", band.psk_version, band.psk_cipher),
            ));
        }
    }
    findings
}

pub fn analyze_system(
    firmware: &crate::api::Firmware,
    time: &crate::api::TimeSettings,
    remote: &crate::api::RemoteAdmin,
    access: &crate::api::AccessControlEnable,
    mode: &crate::api::AccessControlMode,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.push(finding(
        Severity::Info,
        "system",
        format!("{} running {}, router clock {} {}", firmware.hardware_version, firmware.firmware_version, time.date, time.time),
    ));
    let build_year = firmware
        .firmware_version
        .split("Build ")
        .nth(1)
        .and_then(|rest| rest.get(..4))
        .and_then(|year| year.parse::<i32>().ok());
    let now_year = time.date.split('/').nth(2).and_then(|year| year.parse::<i32>().ok());
    if let (Some(build), Some(now)) = (build_year, now_year)
        && now - build >= 3
    {
        findings.push(finding(
            Severity::Warning,
            "system",
            format!("the firmware was built in {build}, {} years ago; it is unlikely to receive fixes", now - build),
        ));
    }
    if !time.ntp_success {
        findings.push(finding(Severity::Warning, "system", "the router could not synchronise its clock over NTP".into()));
    }
    if remote.enable.is_on() {
        findings.push(finding(Severity::Warning, "security", format!("remote administration is enabled ({})", remote.web_address)));
    }
    if access.enable.is_on() {
        findings.push(finding(
            Severity::Warning,
            "access-control",
            format!("access control is on in {:?} mode: a device that is not allowed gets no network at all", mode.access_mode),
        ));
    }
    findings
}

pub fn analyze_load(cpu: &[f64], memory: f64, total_pps: f64) -> Vec<Finding> {
    let mut findings = Vec::new();
    if cpu.is_empty() {
        return findings;
    }
    let average = cpu.iter().sum::<f64>() / cpu.len() as f64;
    let peak = cpu.iter().cloned().fold(f64::MIN, f64::max);
    let low = cpu.iter().cloned().fold(f64::MAX, f64::min);
    findings.push(finding(
        Severity::Info,
        "load",
        format!(
            "CPU {:.0}% average (min {:.0}%, max {:.0}%) over {} samples, memory {:.0}%, wifi traffic {total_pps:.0} packets/s",
            average * 100.0, low * 100.0, peak * 100.0, cpu.len(), memory * 100.0
        ),
    ));
    if average >= 0.7 && total_pps < 1000.0 {
        findings.push(finding(
            Severity::Problem,
            "load",
            format!(
                "the CPU is at {:.0}% while the network moves only {total_pps:.0} packets/s. Forwarding that little traffic needs a few percent on this hardware, so something inside the router (a stuck process, a flood of broadcast/management traffic, or a failing unit) is using the CPU. A busy CPU answers DHCP and DNS late, which looks like dropped addresses and a slow network",
                average * 100.0
            ),
        ));
    } else if average >= 0.7 {
        findings.push(finding(Severity::Warning, "load", format!("the CPU is at {:.0}% under real traffic", average * 100.0)));
    }
    if memory >= 0.85 {
        findings.push(finding(Severity::Problem, "load", format!("memory is {:.0}% full", memory * 100.0)));
    }
    findings
}

pub async fn run(session: &crate::session::Session, options: &Options) -> anyhow::Result<Report> {
    let first = crate::router::status(session).await?;
    let started = std::time::Instant::now();
    let mut cpu_samples = Vec::new();
    let mut memory = first.mem_usage;
    for index in 0..options.samples {
        if index > 0 {
            tokio::time::sleep(options.interval).await;
        }
        let perf: crate::api::Perf = crate::session::typed(session, "admin/status?form=perf", "read").await?;
        cpu_samples.push(perf.cpu_usage);
        memory = perf.mem_usage;
    }
    let status = crate::router::status(session).await?;
    let window_seconds = started.elapsed().as_secs_f64().max(1.0);

    let mut rates: Vec<ClientRate> = status
        .devices
        .iter()
        .filter_map(|device| {
            let before = first.devices.iter().find(|d| d.macaddr == device.macaddr)?;
            let sent = device.packets_sent?.checked_sub(before.packets_sent?)?;
            let received = device.packets_received?.checked_sub(before.packets_received?)?;
            Some(ClientRate {
                macaddr: device.macaddr,
                hostname: device.hostname.clone(),
                connection: device.connection,
                packets_per_second: (sent + received) as f64 / window_seconds,
            })
        })
        .collect();
    rates.sort_by(|a, b| b.packets_per_second.total_cmp(&a.packets_per_second));
    let total_packets_per_second = rates.iter().map(|rate| rate.packets_per_second).sum();
    rates.truncate(5);

    let server: crate::api::DhcpServer = crate::session::typed(session, "admin/dhcps?form=setting", "read").await?;
    let lan: crate::api::Ipv4Status = crate::session::typed(session, "admin/network?form=status_ipv4", "read").await?;
    let leases: Vec<crate::api::DhcpClient> =
        crate::session::typed_list(session, "admin/dhcps?form=client", "load", &["dhcp_clients"]).await?;
    let log: Vec<crate::api::SyslogEntry> =
        crate::session::typed_list(session, "admin/syslog?form=log", "load", &[]).await?;
    let reservations = crate::router::reservations(session).await?;
    let wan: Option<crate::api::WanIpv4Dynamic> = if lan.wan_ipv4_conntype == "dhcp" {
        crate::session::typed(session, "admin/network?form=wan_ipv4_dynamic", "read").await.ok()
    } else {
        None
    };
    let band2: crate::api::WirelessHost = crate::session::typed(session, "admin/wireless?form=wireless_2g", "read").await?;
    let band5: crate::api::WirelessHost = crate::session::typed(session, "admin/wireless?form=wireless_5g", "read").await?;
    let firmware: crate::api::Firmware = crate::session::typed(session, "admin/firmware?form=upgrade", "read").await?;
    let time: crate::api::TimeSettings = crate::session::typed(session, "admin/time?form=settings", "read").await?;
    let remote: crate::api::RemoteAdmin = crate::session::typed(session, "admin/administration?form=remote", "read").await?;
    let access: crate::api::AccessControlEnable = crate::session::typed(session, "admin/access_control?form=enable", "read").await?;
    let mode: crate::api::AccessControlMode = crate::session::typed(session, "admin/access_control?form=mode", "read").await?;

    let events = timeline(&log);
    let mut findings = Vec::new();
    findings.extend(analyze_load(&cpu_samples, memory, total_packets_per_second));
    findings.extend(analyze_dhcp_config(&server, &lan, &leases, &status.devices, &reservations));
    findings.extend(analyze_dhcp_log(&events, &leases, &status.devices));
    findings.extend(analyze_wan(&status, &lan, wan.as_ref()));
    findings.extend(analyze_radio(&band2, &band5, &status.devices));
    findings.extend(analyze_system(&firmware, &time, &remote, &access, &mode));
    findings.sort_by_key(|finding| std::cmp::Reverse(finding.severity));

    Ok(Report {
        findings,
        load: Load {
            cpu_samples,
            memory,
            window_seconds,
            total_packets_per_second,
            top_clients: rates,
        },
    })
}

pub fn render(report: &Report) -> String {
    let mut text = String::new();
    for severity in [Severity::Problem, Severity::Warning, Severity::Info] {
        let group: Vec<&Finding> = report.findings.iter().filter(|f| f.severity == severity).collect();
        if group.is_empty() {
            continue;
        }
        text.push_str(&format!("== {} ({}) ==\n", format!("{severity:?}").to_uppercase(), group.len()));
        for finding in group {
            text.push_str(&format!("[{}] {}\n", finding.area, finding.message));
        }
        text.push('\n');
    }
    if !report.load.top_clients.is_empty() {
        text.push_str(&format!("top clients by packets/s over {:.0}s:\n", report.load.window_seconds));
        for client in &report.load.top_clients {
            text.push_str(&format!(
                "  {:6.1}  {}  {}\n",
                client.packets_per_second,
                client.macaddr,
                client.hostname.clone().unwrap_or_else(|| "-".into())
            ));
        }
    }
    text
}
