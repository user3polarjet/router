#[derive(clap::Parser)]
#[command(about = "Client for the TP-Link Archer C6 v2 web API")]
struct Cli {
    #[arg(long, env = "ROUTER_HOST")]
    host: Option<String>,
    #[arg(long, env = "ROUTER_USERNAME")]
    username: Option<String>,
    #[arg(long, env = "ROUTER_PASSWORD", hide_env_values = true)]
    password: Option<String>,
    #[arg(long, default_value = "secret.toml")]
    config: String,
    #[arg(long, default_value_t = 30)]
    timeout: u64,
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand)]
enum ReservationAction {
    Add {
        mac: String,
        ip: String,
        #[arg(long, default_value = "")]
        name: String,
        #[arg(long)]
        disabled: bool,
        #[arg(long)]
        no_verify: bool,
    },
    Update {
        mac: String,
        #[arg(long)]
        new_mac: Option<String>,
        #[arg(long)]
        ip: Option<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        enable: Option<bool>,
        #[arg(long)]
        no_verify: bool,
    },
    Delete {
        mac: String,
        #[arg(long)]
        no_verify: bool,
    },
}

#[derive(clap::Subcommand)]
enum ForwardAction {
    Add {
        name: String,
        external_port: String,
        internal_port: String,
        ip: String,
        #[arg(long, value_enum, default_value = "tcp")]
        protocol: archer_c6::changes::Protocol,
        #[arg(long)]
        disabled: bool,
    },
    Update {
        name: String,
        #[arg(long)]
        new_name: Option<String>,
        #[arg(long)]
        external_port: Option<String>,
        #[arg(long)]
        internal_port: Option<String>,
        #[arg(long)]
        ip: Option<String>,
        #[arg(long, value_enum)]
        protocol: Option<archer_c6::changes::Protocol>,
        #[arg(long)]
        enable: Option<bool>,
    },
    Delete {
        name: String,
    },
}

#[derive(clap::Subcommand)]
enum Command {
    Show {
        #[arg(value_enum)]
        topic: archer_c6::router::Topic,
    },
    Status,
    Wifi {
        #[arg(value_enum)]
        band: Option<archer_c6::router::WifiBand>,
    },
    All,
    Raw {
        path: String,
        #[arg(default_value = "read")]
        operation: String,
    },
    Diagnose {
        #[arg(long, default_value_t = 8)]
        samples: u32,
        #[arg(long, default_value_t = 5)]
        interval: u64,
        #[arg(long)]
        json: bool,
    },
    Watch {
        #[arg(long, default_value_t = 30)]
        interval: u64,
        #[arg(long)]
        minutes: Option<u64>,
    },
    Reboot,
    WifiSet {
        #[arg(value_enum)]
        band: archer_c6::router::WifiBand,
        #[command(flatten)]
        settings: archer_c6::changes::WifiSettings,
    },
    Reservation {
        #[command(subcommand)]
        action: ReservationAction,
    },
    Forward {
        #[command(subcommand)]
        action: ForwardAction,
    },
    Dhcp {
        enable: bool,
    },
    Wan {
        #[arg(value_enum)]
        action: archer_c6::changes::WanAction,
    },
}

fn section<T: serde::Serialize>(result: anyhow::Result<T>) -> serde_json::Value {
    match result.and_then(|value| Ok(serde_json::to_value(value)?)) {
        Ok(value) => value,
        Err(error) => serde_json::json!({ "error": format!("{error:#}") }),
    }
}

async fn wifi_all(session: &archer_c6::session::Session) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for band in <archer_c6::router::WifiBand as clap::ValueEnum>::value_variants() {
        map.insert(
            archer_c6::router::wifi_band_form(*band).to_string(),
            section(archer_c6::router::wifi(session, *band).await),
        );
    }
    serde_json::Value::Object(map)
}

async fn all(session: &archer_c6::session::Session) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert("status".into(), section(archer_c6::router::status(session).await));
    for topic in <archer_c6::router::Topic as clap::ValueEnum>::value_variants() {
        let name = clap::ValueEnum::to_possible_value(topic).map(|value| value.get_name().to_string());
        map.insert(
            name.unwrap_or_default(),
            section(archer_c6::router::show(session, *topic).await),
        );
    }
    map.insert("wifi".into(), wifi_all(session).await);
    serde_json::Value::Object(map)
}

async fn run(session: &archer_c6::session::Session, command: &Command) -> anyhow::Result<serde_json::Value> {
    Ok(match command {
        Command::Show { topic } => archer_c6::router::show(session, *topic).await?,
        Command::Status => serde_json::to_value(archer_c6::router::status(session).await?)?,
        Command::Wifi { band: Some(band) } => serde_json::to_value(archer_c6::router::wifi(session, *band).await?)?,
        Command::Wifi { band: None } => wifi_all(session).await,
        Command::All => all(session).await,
        Command::Raw { path, operation } => archer_c6::session::request(session, path, operation).await?,
        Command::Diagnose { samples, interval, json } => {
            let options = archer_c6::diagnose::Options {
                samples: *samples,
                interval: std::time::Duration::from_secs(*interval),
            };
            let report = archer_c6::diagnose::run(session, &options).await?;
            if *json {
                serde_json::to_value(&report)?
            } else {
                serde_json::Value::String(archer_c6::diagnose::render(&report))
            }
        }
        Command::Watch { interval, minutes } => {
            let options = archer_c6::watch::Options {
                interval: std::time::Duration::from_secs(*interval),
                duration: minutes.map(|minutes| std::time::Duration::from_secs(minutes * 60)),
            };
            archer_c6::watch::run(session, &options).await?;
            serde_json::Value::String(String::new())
        }
        Command::Reboot => archer_c6::changes::reboot(session).await?,
        Command::WifiSet { band, settings } => archer_c6::changes::set_wifi(session, *band, settings).await?,
        Command::Reservation { action } => match action {
            ReservationAction::Add { mac, ip, name, disabled, no_verify } => {
                archer_c6::changes::add_reservation(session, mac, ip, name, !*disabled, !*no_verify).await?
            }
            ReservationAction::Update { mac, new_mac, ip, name, enable, no_verify } => {
                archer_c6::changes::update_reservation(
                    session,
                    mac,
                    new_mac.as_deref(),
                    ip.as_deref(),
                    name.as_deref(),
                    *enable,
                    !*no_verify,
                )
                .await?
            }
            ReservationAction::Delete { mac, no_verify } => {
                archer_c6::changes::delete_reservation(session, mac, !*no_verify).await?
            }
        },
        Command::Forward { action } => match action {
            ForwardAction::Add { name, external_port, internal_port, ip, protocol, disabled } => {
                archer_c6::changes::add_forward(session, name, external_port, internal_port, ip, *protocol, !*disabled).await?
            }
            ForwardAction::Update { name, new_name, external_port, internal_port, ip, protocol, enable } => {
                archer_c6::changes::update_forward(
                    session,
                    name,
                    new_name.as_deref(),
                    external_port.as_deref(),
                    internal_port.as_deref(),
                    ip.as_deref(),
                    *protocol,
                    *enable,
                )
                .await?
            }
            ForwardAction::Delete { name } => archer_c6::changes::delete_forward(session, name).await?,
        },
        Command::Dhcp { enable } => archer_c6::changes::set_dhcp_server(session, *enable).await?,
        Command::Wan { action } => archer_c6::changes::wan(session, *action).await?,
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = <Cli as clap::Parser>::parse();
    let secret = archer_c6::config::load_secret(&cli.config)?;
    let host = match cli.host.or(secret.ip) {
        Some(host) => host,
        None => archer_c6::config::default_gateway()?.to_string(),
    };
    let username = cli.username.or(secret.username).unwrap_or_else(|| "admin".to_string());
    let password = cli
        .password
        .or(secret.password)
        .ok_or_else(|| anyhow::anyhow!("no password: set it in {}, ROUTER_PASSWORD or --password", cli.config))?;

    let session = archer_c6::session::login(&host, &username, &password, cli.timeout).await?;
    let result = run(&session, &cli.command).await;
    if let Command::Reboot = cli.command {
        println!("{}", serde_json::to_string_pretty(&result?)?);
        return Ok(());
    }
    if let Err(error) = archer_c6::session::logout(&session).await {
        eprintln!("logout failed: {error:#}");
    }
    match result? {
        serde_json::Value::String(text) => println!("{text}"),
        other => println!("{}", serde_json::to_string_pretty(&other)?),
    }
    Ok(())
}
