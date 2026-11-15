const FORMS: &[&str] = &[
    "admin/status?form=all",
    "admin/status?form=perf",
    "admin/status?form=internet",
    "admin/firmware?form=upgrade",
    "admin/time?form=settings",
    "admin/time?form=time",
    "admin/system?form=sysmode",
    "admin/system?form=time",
    "admin/system?form=timezone",
    "admin/system?form=name",
    "admin/system?form=info",
    "admin/network?form=status_ipv4",
    "admin/network?form=status_ipv6",
    "admin/network?form=wan_ipv4_dynamic",
    "admin/network?form=wan_ipv6_dynamic",
    "admin/network?form=wan_ipv4_static",
    "admin/network?form=wan_ipv4_pppoe",
    "admin/network?form=lan",
    "admin/network?form=lan_ipv4",
    "admin/network?form=lan_ipv6",
    "admin/network?form=internet",
    "admin/network?form=iptv",
    "admin/network?form=wan_type",
    "admin/network?form=wan_ipv4_conntype",
    "admin/network?form=mac_clone",
    "admin/network?form=wan_ipv6_conntype",
    "admin/dhcps?form=setting",
    "admin/dhcps?form=client",
    "admin/dhcps?form=reservation",
    "admin/dhcpc?form=setting",
    "admin/dns?form=setting",
    "admin/wireless?form=wireless_2g",
    "admin/wireless?form=wireless_5g",
    "admin/wireless?form=guest_2g",
    "admin/wireless?form=guest_5g",
    "admin/wireless?form=statistics",
    "admin/wireless?form=wps",
    "admin/wireless?form=wds",
    "admin/wireless?form=schedule",
    "admin/wireless?form=advanced",
    "admin/wireless?form=mac_filter",
    "admin/wireless?form=wireless_advanced",
    "admin/wireless?form=wireless_basic",
    "admin/wireless?form=wireless_schedule",
    "admin/wireless?form=wireless_2g_advanced",
    "admin/wireless?form=wireless_5g_advanced",
    "admin/wireless?form=wireless_mac",
    "admin/wireless?form=wireless_wps",
    "admin/wireless?form=guest_schedule",
    "admin/nat?form=vs",
    "admin/nat?form=dmz",
    "admin/nat?form=pt",
    "admin/nat?form=alg",
    "admin/nat?form=upnp",
    "admin/nat?form=upnp_list",
    "admin/nat?form=ft",
    "admin/upnp?form=setting",
    "admin/upnp?form=list",
    "admin/firewall?form=setting",
    "admin/firewall?form=dos",
    "admin/firewall?form=security",
    "admin/ddns?form=setting",
    "admin/ddns?form=ddns",
    "admin/ddns?form=tplink",
    "admin/ddns?form=noip",
    "admin/ddns?form=dyndns",
    "admin/route?form=static",
    "admin/route?form=setting",
    "admin/route?form=table",
    "admin/route?form=system",
    "admin/staticrouting?form=setting",
    "admin/access_control?form=setting",
    "admin/access_control?form=black_list",
    "admin/access_control?form=white_list",
    "admin/access_control?form=enable",
    "admin/access_control?form=mode",
    "admin/access_control?form=device",
    "admin/parental_control?form=setting",
    "admin/parental_control?form=client",
    "admin/parental_control?form=devices",
    "admin/qos?form=setting",
    "admin/qos?form=rules",
    "admin/qos?form=bandwidth",
    "admin/smart_network?form=game_accelerator",
    "admin/openvpn?form=config",
    "admin/pptpd?form=config",
    "admin/vpnconn?form=config",
    "admin/vpn?form=enable",
    "admin/usb?form=setting",
    "admin/storage?form=setting",
    "admin/ipv6?form=setting",
    "admin/cloud_account?form=bind",
    "admin/cloud_account?form=setting",
    "admin/device?form=device_list",
    "admin/device?form=setting",
    "admin/syslog?form=setting",
    "admin/syslog?form=log",
    "admin/log?form=log",
    "admin/log?form=setting",
    "admin/led?form=setting",
    "admin/reboot_schedule?form=setting",
    "admin/administration?form=setting",
    "admin/administration?form=remote",
    "admin/administration?form=manage",
    "admin/administration?form=local",
    "admin/easymesh_network?form=get_mesh_device_list_all",
    "admin/ethernet?form=setting",
    "admin/ethernet?form=port",
    "admin/wan?form=status",
    "admin/lan?form=setting",
    "admin/lan?form=status",
    "admin/traffic?form=statistics",
    "admin/traffic?form=setting",
    "admin/stat?form=traffic",
    "admin/stat?form=setting",
    "admin/statistics?form=traffic",
    "admin/dev_name?form=setting",
    "admin/tr069?form=setting",
    "admin/snmp?form=setting",
    "admin/diagnostic?form=setting",
    "admin/mac_clone?form=setting",
    "admin/ap?form=setting",
    "admin/sysmode?form=mode",
    "admin/sysmode?form=setting",
    "admin/syslog?form=server",
    "admin/language?form=setting",
    "admin/locale?form=setting",
    "admin/timesetting?form=setting",
    "admin/wan_ipv4?form=setting",
    "admin/internet?form=setting",
    "admin/ap_mode?form=setting",
    "admin/vlan?form=setting",
    "admin/iptv?form=setting",
    "admin/ipv6_tunnel?form=setting",
    "admin/lan_ipv6?form=setting",
    "admin/bandwidth?form=setting",
    "admin/network_map?form=setting",
    "admin/sysinfo?form=setting",
    "admin/homecare?form=setting",
    "admin/antivirus?form=setting",
    "admin/onemesh?form=setting",
];

const FORBIDDEN: &[&str] = &[
    "reboot", "logout", "upgrade_start", "restore", "factory", "reset", "backup", "ping", "trace", "renew", "release",
];

const OPERATIONS: &[&str] = &["read", "load", "list"];

fn masked(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.into_iter()
                .map(|(key, value)| {
                    let lower = key.to_lowercase();
                    let secret = ["psk", "pass", "pwd", "key", "secret", "token"].iter().any(|s| lower.contains(s));
                    let hide = secret && matches!(&value, serde_json::Value::String(text) if !text.is_empty());
                    let value = if hide { serde_json::Value::String("***".into()) } else { masked(value) };
                    (key, value)
                })
                .collect(),
        ),
        serde_json::Value::Array(items) => serde_json::Value::Array(items.into_iter().map(masked).collect()),
        other => other,
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let out_dir = std::env::args().nth(1).ok_or_else(|| anyhow::anyhow!("usage: discover <output-dir>"))?;
    std::fs::create_dir_all(&out_dir)?;
    let secret = archer_c6::config::load_secret("secret.toml")?;
    let host = match secret.ip {
        Some(host) => host,
        None => archer_c6::config::default_gateway()?.to_string(),
    };
    let password = secret.password.ok_or_else(|| anyhow::anyhow!("no password in secret.toml"))?;
    let username = secret.username.unwrap_or_else(|| "admin".to_string());
    let session = archer_c6::session::login(&host, &username, &password, 30).await?;

    let mut summary = Vec::new();
    for form in FORMS {
        if FORBIDDEN.iter().any(|word| form.contains(word)) {
            continue;
        }
        for operation in OPERATIONS {
            let result = archer_c6::session::request(&session, form, operation).await;
            tokio::time::sleep(std::time::Duration::from_millis(40)).await;
            match result {
                Ok(data) => {
                    let name = format!("{}__{}.json", form.replace(['/', '?', '='], "_"), operation);
                    let text = serde_json::to_string_pretty(&masked(data))?;
                    std::fs::write(std::path::Path::new(&out_dir).join(&name), &text)?;
                    summary.push(format!("OK   {form} [{operation}] {} bytes", text.len()));
                }
                Err(error) => {
                    let message = format!("{error:#}");
                    if !message.contains("no such callback") {
                        summary.push(format!("ERR  {form} [{operation}] {message}"));
                    }
                }
            }
        }
    }
    archer_c6::session::logout(&session).await?;
    println!("{}", summary.join("\n"));
    Ok(())
}
