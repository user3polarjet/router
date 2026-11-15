#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Firmware {
    pub firmware_version: String,
    pub hardware_version: String,
    pub is_default: bool,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub totaltime: u32,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Perf {
    #[serde(deserialize_with = "crate::scalar::number")]
    pub cpu_usage: f64,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub mem_usage: f64,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct InternetStatus {
    pub internet_status: crate::scalar::ConnStatus,
    pub internet_v6_status: crate::scalar::ConnStatus,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SystemMode {
    pub mode: String,
    pub support: crate::scalar::YesNo,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct TimeSettings {
    pub date: String,
    pub day: String,
    pub factory_setting: crate::scalar::YesNo,
    pub hour24_enable: crate::scalar::Switch,
    pub hour24_support: crate::scalar::YesNo,
    pub ntp_success: bool,
    pub ntp_svr1: String,
    pub ntp_svr2: String,
    pub quicksetup: crate::scalar::YesNo,
    pub time: String,
    pub time_format: String,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub timezone: i32,
    pub timezone_select_permission: crate::scalar::YesNo,
    #[serde(rename = "type")]
    pub kind: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Ipv4Status {
    pub lan_ipv4_dhcp_enable: crate::scalar::Switch,
    pub lan_ipv4_ipaddr: std::net::Ipv4Addr,
    pub lan_ipv4_netmask: std::net::Ipv4Addr,
    pub lan_macaddr: crate::scalar::Mac,
    pub remote: bool,
    pub wan_ipv4_conntype: String,
    pub wan_ipv4_gateway: std::net::Ipv4Addr,
    pub wan_ipv4_ipaddr: std::net::Ipv4Addr,
    pub wan_ipv4_netmask: std::net::Ipv4Addr,
    pub wan_ipv4_pridns: std::net::Ipv4Addr,
    pub wan_ipv4_snddns: std::net::Ipv4Addr,
    pub wan_macaddr: crate::scalar::Mac,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Ipv6Status {
    pub lan_ipv6_assign_type: String,
    pub lan_ipv6_ipaddr: crate::scalar::Ipv6Net,
    #[serde(
        deserialize_with = "crate::scalar::empty_as_none",
        serialize_with = "crate::scalar::none_as_empty"
    )]
    pub lan_ipv6_link_local_addr: Option<crate::scalar::Ipv6Net>,
    pub wan_ipv6_conntype: String,
    pub wan_ipv6_enable: crate::scalar::Switch,
    pub wan_ipv6_gateway: std::net::Ipv6Addr,
    pub wan_ipv6_ip6addr: crate::scalar::Ipv6Net,
    pub wan_ipv6_pridns: std::net::Ipv6Addr,
    pub wan_ipv6_snddns: std::net::Ipv6Addr,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct WanIpv4Dynamic {
    pub conn_status: crate::scalar::ConnStatus,
    pub conntype: String,
    pub dns_mode: String,
    pub dyn_pridns: std::net::Ipv4Addr,
    pub dyn_snddns: std::net::Ipv4Addr,
    pub gateway: std::net::Ipv4Addr,
    pub hostname: String,
    pub ipaddr: std::net::Ipv4Addr,
    pub link_status: String,
    pub mac_clone_type: String,
    pub mac_custom: String,
    #[serde(
        deserialize_with = "crate::scalar::empty_as_none",
        serialize_with = "crate::scalar::none_as_empty"
    )]
    pub manual_pridns: Option<std::net::Ipv4Addr>,
    #[serde(
        deserialize_with = "crate::scalar::empty_as_none",
        serialize_with = "crate::scalar::none_as_empty"
    )]
    pub manual_snddns: Option<std::net::Ipv4Addr>,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub mtu: u32,
    pub netmask: std::net::Ipv4Addr,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub nonaddress_support: u32,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub pppshare: u32,
    pub pri_dns: std::net::Ipv4Addr,
    pub snd_dns: std::net::Ipv4Addr,
    pub unicast: crate::scalar::Switch,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct WanIpv6Dynamic {
    pub conn_status: crate::scalar::ConnStatus,
    pub conntype: String,
    pub dns_mode: String,
    pub dyn_pridns: std::net::Ipv6Addr,
    pub dyn_snddns: std::net::Ipv6Addr,
    pub ip6addr: crate::scalar::Ipv6Net,
    pub ip_config: String,
    pub ip_mode: String,
    pub link_status: String,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub nonaddress_support: u32,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub pppshare: u32,
    #[serde(
        deserialize_with = "crate::scalar::empty_as_none",
        serialize_with = "crate::scalar::none_as_empty"
    )]
    pub prefix: Option<crate::scalar::Ipv6Net>,
    pub pri_dns: std::net::Ipv6Addr,
    pub snd_dns: std::net::Ipv6Addr,
    #[serde(
        deserialize_with = "crate::scalar::empty_as_none",
        serialize_with = "crate::scalar::none_as_empty"
    )]
    pub static_pridns: Option<std::net::Ipv6Addr>,
    #[serde(
        deserialize_with = "crate::scalar::empty_as_none",
        serialize_with = "crate::scalar::none_as_empty"
    )]
    pub static_snddns: Option<std::net::Ipv6Addr>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct WanIpv4Pppoe {
    pub access: String,
    pub conn_mode: String,
    pub conn_status: crate::scalar::ConnStatus,
    pub conntype: String,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub demand_idle: u32,
    pub dns_mode: String,
    pub dyn_ip: std::net::Ipv4Addr,
    pub dyn_netmask: std::net::Ipv4Addr,
    pub dyn_pridns: std::net::Ipv4Addr,
    pub dyn_snddns: std::net::Ipv4Addr,
    pub inet_ip: std::net::Ipv4Addr,
    pub inet_pridns: std::net::Ipv4Addr,
    pub inet_snddns: std::net::Ipv4Addr,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub interval: u32,
    pub ip_mode: String,
    pub link_status: String,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub manual_idle: u32,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub mtu: u32,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub nonaddress_support: u32,
    pub password: String,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub pppshare: u32,
    pub server: String,
    pub snd_conn: String,
    pub specific_ip: std::net::Ipv4Addr,
    #[serde(
        deserialize_with = "crate::scalar::empty_as_none",
        serialize_with = "crate::scalar::none_as_empty"
    )]
    pub static_ip: Option<std::net::Ipv4Addr>,
    #[serde(
        deserialize_with = "crate::scalar::empty_as_none",
        serialize_with = "crate::scalar::none_as_empty"
    )]
    pub static_netmask: Option<std::net::Ipv4Addr>,
    #[serde(
        deserialize_with = "crate::scalar::empty_as_none",
        serialize_with = "crate::scalar::none_as_empty"
    )]
    pub static_pridns: Option<std::net::Ipv4Addr>,
    #[serde(
        deserialize_with = "crate::scalar::empty_as_none",
        serialize_with = "crate::scalar::none_as_empty"
    )]
    pub static_snddns: Option<std::net::Ipv4Addr>,
    pub time_end: String,
    pub time_start: String,
    pub username: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct LanIpv4 {
    pub custom_value: String,
    pub igmp: crate::scalar::Switch,
    pub ipaddr: std::net::Ipv4Addr,
    pub macaddr: crate::scalar::Mac,
    pub mask_type: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct LanIpv6 {
    pub address: crate::scalar::Ipv6Net,
    pub assign_type: String,
    #[serde(
        deserialize_with = "crate::scalar::empty_as_none",
        serialize_with = "crate::scalar::none_as_empty"
    )]
    pub dhcp_prefix: Option<crate::scalar::Ipv6Net>,
    #[serde(
        deserialize_with = "crate::scalar::empty_as_none",
        serialize_with = "crate::scalar::none_as_empty"
    )]
    pub rdnss_prefix: Option<crate::scalar::Ipv6Net>,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub release_time: u32,
    #[serde(
        deserialize_with = "crate::scalar::empty_as_none",
        serialize_with = "crate::scalar::none_as_empty"
    )]
    pub slaac_prefix: Option<crate::scalar::Ipv6Net>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct DhcpServer {
    pub domain: String,
    pub enable: crate::scalar::Switch,
    pub gateway: std::net::Ipv4Addr,
    pub ipaddr_end: std::net::Ipv4Addr,
    pub ipaddr_start: std::net::Ipv4Addr,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub leasetime: u32,
    #[serde(
        deserialize_with = "crate::scalar::empty_as_none",
        serialize_with = "crate::scalar::none_as_empty"
    )]
    pub pri_dns: Option<std::net::Ipv4Addr>,
    #[serde(
        deserialize_with = "crate::scalar::empty_as_none",
        serialize_with = "crate::scalar::none_as_empty"
    )]
    pub snd_dns: Option<std::net::Ipv4Addr>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct DhcpClient {
    pub ipaddr: std::net::Ipv4Addr,
    pub leasetime: String,
    pub macaddr: crate::scalar::Mac,
    pub name: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct DhcpReservation {
    pub mac: crate::scalar::Mac,
    pub ip: std::net::Ipv4Addr,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    pub enable: crate::scalar::Switch,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct PortForward {
    pub name: String,
    pub ipaddr: std::net::Ipv4Addr,
    pub external_port: String,
    pub internal_port: String,
    pub protocol: String,
    pub enable: crate::scalar::Switch,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ExtInfo {
    pub dual_band: crate::scalar::YesNo,
    pub support_band: String,
    pub wds2g_wds5g_compatible: crate::scalar::YesNo,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct WirelessHost {
    pub atf: crate::scalar::Switch,
    pub channel: crate::scalar::Channel,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub current_channel: u16,
    pub disabled: crate::scalar::Switch,
    pub disabled_all: crate::scalar::Switch,
    pub enable: crate::scalar::Switch,
    pub encryption: crate::scalar::Encryption,
    pub extinfo: ExtInfo,
    pub hidden: crate::scalar::Switch,
    pub htmode: String,
    pub hwmode: String,
    pub macaddr: crate::scalar::Mac,
    #[serde(default)]
    pub mumimo: Option<crate::scalar::Switch>,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub port: u16,
    pub psk_cipher: String,
    pub psk_key: String,
    pub psk_version: String,
    pub server: String,
    pub ssid: String,
    #[serde(default)]
    pub txbf_enable: Option<crate::scalar::Switch>,
    pub txpower: String,
    pub wds_status: String,
    pub wep_format1: String,
    pub wep_format2: String,
    pub wep_format3: String,
    pub wep_format4: String,
    pub wep_key1: String,
    pub wep_key2: String,
    pub wep_key3: String,
    pub wep_key4: String,
    pub wep_mode: String,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub wep_select: u8,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub wep_type1: u16,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub wep_type2: u16,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub wep_type3: u16,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub wep_type4: u16,
    pub wpa_cipher: String,
    pub wpa_key: String,
    pub wpa_version: String,
    pub wps_state: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct WirelessGuest {
    pub disabled: crate::scalar::Switch,
    pub enable: crate::scalar::Switch,
    pub encryption: crate::scalar::Encryption,
    pub extinfo: ExtInfo,
    pub hidden: crate::scalar::Switch,
    pub psk_cipher: String,
    pub psk_key: String,
    pub psk_version: String,
    pub ssid: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct WirelessClient {
    pub encryption: String,
    pub mac: crate::scalar::Mac,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub rxpkts: u64,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub txpkts: u64,
    #[serde(rename = "type")]
    pub kind: crate::scalar::RadioBand,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct StatusClient {
    pub hostname: String,
    #[serde(
        deserialize_with = "crate::scalar::empty_as_none",
        serialize_with = "crate::scalar::none_as_empty"
    )]
    pub ipaddr: Option<std::net::Ipv4Addr>,
    pub macaddr: crate::scalar::Mac,
    pub wire_type: crate::scalar::WireType,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct StatusAll {
    pub access_devices_wired: Vec<StatusClient>,
    pub access_devices_wireless_host: Vec<StatusClient>,
    pub access_devices_wireless_guest: Option<Vec<StatusClient>>,
    pub conn_type: String,
    pub guest_access: crate::scalar::Switch,
    pub guest_isolate: crate::scalar::Switch,
    pub guest_2g_enable: crate::scalar::Switch,
    pub guest_5g_enable: crate::scalar::Switch,
    pub wireless_2g_enable: crate::scalar::Switch,
    pub wireless_5g_enable: crate::scalar::Switch,
    pub lan_ipv4_dhcp_enable: crate::scalar::Switch,
    pub lan_ipv4_ipaddr: std::net::Ipv4Addr,
    pub lan_ipv4_netmask: std::net::Ipv4Addr,
    pub lan_ipv6_assign_type: String,
    pub lan_ipv6_ipaddr: crate::scalar::Ipv6Net,
    #[serde(
        deserialize_with = "crate::scalar::empty_as_none",
        serialize_with = "crate::scalar::none_as_empty"
    )]
    pub lan_ipv6_link_local_addr: Option<crate::scalar::Ipv6Net>,
    pub lan_macaddr: crate::scalar::Mac,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub modem_available: u32,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub modem_connstatus: u32,
    pub modem_gateway: std::net::Ipv4Addr,
    pub modem_ipaddr: std::net::Ipv4Addr,
    pub modem_netmask: std::net::Ipv4Addr,
    pub modem_pridns: std::net::Ipv4Addr,
    pub modem_signal: String,
    pub modem_snddns: std::net::Ipv4Addr,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub printer_count: u32,
    pub printer_name: String,
    pub remote: bool,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub storage_available: u64,
    pub storage_available_unit: String,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub storage_capacity: u64,
    pub storage_capacity_unit: String,
    pub storage_vendor: String,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub usb_available: u32,
    pub wan_ipv4_conntype: String,
    pub wan_ipv4_gateway: std::net::Ipv4Addr,
    pub wan_ipv4_ipaddr: std::net::Ipv4Addr,
    pub wan_ipv4_netmask: std::net::Ipv4Addr,
    pub wan_ipv4_pridns: std::net::Ipv4Addr,
    pub wan_ipv4_snddns: std::net::Ipv4Addr,
    pub wan_ipv6_conntype: String,
    pub wan_ipv6_enable: crate::scalar::Switch,
    pub wan_ipv6_gateway: std::net::Ipv6Addr,
    pub wan_ipv6_ip6addr: crate::scalar::Ipv6Net,
    pub wan_ipv6_pridns: std::net::Ipv6Addr,
    pub wan_ipv6_snddns: std::net::Ipv6Addr,
    pub wan_macaddr: crate::scalar::Mac,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AccessControlEnable {
    pub enable: crate::scalar::Switch,
    pub host_mac: crate::scalar::Mac,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AccessControlMode {
    pub access_mode: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct RemoteAdmin {
    pub enable: crate::scalar::Switch,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub http_port: u16,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub https_port: u16,
    pub managers: String,
    pub remote: bool,
    pub web_address: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct DdnsDyndns {
    pub domain: String,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub logined: u32,
    pub password: String,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub status: u32,
    pub update_time: String,
    pub username: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct DdnsNoip {
    pub domain: String,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub logined: u32,
    pub password: String,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub status: u32,
    pub update_time: String,
    pub username: String,
    pub wan_bind: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct NatAlg {
    pub ftp: crate::scalar::Switch,
    pub h323: crate::scalar::Switch,
    pub ipsec: crate::scalar::Switch,
    pub l2tp: crate::scalar::Switch,
    pub pptp: crate::scalar::Switch,
    pub rtsp: crate::scalar::Switch,
    pub sip: crate::scalar::Switch,
    pub tftp: crate::scalar::Switch,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct NatDmz {
    pub enable: crate::scalar::Switch,
    #[serde(
        deserialize_with = "crate::scalar::empty_as_none",
        serialize_with = "crate::scalar::none_as_empty"
    )]
    pub ipaddr: Option<std::net::Ipv4Addr>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct OpenVpn {
    pub access: String,
    pub cert_exist: bool,
    pub enabled: crate::scalar::Switch,
    pub mask: std::net::Ipv4Addr,
    #[serde(deserialize_with = "crate::scalar::number")]
    pub port: u16,
    pub proto: String,
    pub serverip: std::net::Ipv4Addr,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Pptpd {
    pub enabled: crate::scalar::Switch,
    pub netbios_pass: String,
    pub remoteip: String,
    pub samba_access: crate::scalar::Switch,
    pub unencrypted_access: crate::scalar::Switch,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SyslogEntry {
    pub content: String,
    pub level: String,
    pub time: String,
    #[serde(rename = "type")]
    pub kind: String,
}
