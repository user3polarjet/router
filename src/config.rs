#[derive(serde::Deserialize, Default)]
pub struct Secret {
    pub ip: Option<String>,
    pub password: Option<String>,
    pub username: Option<String>,
}

pub fn load_secret(path: &str) -> anyhow::Result<Secret> {
    match std::fs::read_to_string(path) {
        Ok(text) => toml::from_str(&text).map_err(|e| anyhow::anyhow!("{path}: {e}")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Secret::default()),
        Err(error) => Err(anyhow::anyhow!("{path}: {error}")),
    }
}

pub fn parse_gateway(table: &str) -> Option<std::net::Ipv4Addr> {
    table.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let destination = u32::from_str_radix(fields.get(1)?, 16).ok()?;
        let gateway = u32::from_str_radix(fields.get(2)?, 16).ok()?;
        let flags = u32::from_str_radix(fields.get(3)?, 16).ok()?;
        (destination == 0 && gateway != 0 && flags & 0x2 != 0)
            .then(|| std::net::Ipv4Addr::from(gateway.to_ne_bytes()))
    })
}

pub fn default_gateway() -> anyhow::Result<std::net::Ipv4Addr> {
    let table = std::fs::read_to_string("/proc/net/route")
        .map_err(|e| anyhow::anyhow!("cannot read the routing table to find the router: {e}"))?;
    parse_gateway(&table).ok_or_else(|| anyhow::anyhow!("no default gateway found, pass --host or set ip in secret.toml"))
}
