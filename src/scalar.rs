#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Switch {
    On,
    Off,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum YesNo {
    Yes,
    No,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct Mac(pub [u8; 6]);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ipv6Net {
    pub addr: std::net::Ipv6Addr,
    pub prefix: Option<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Channel {
    Auto,
    Fixed(u16),
}

#[derive(Clone, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub enum ConnStatus {
    #[serde(rename = "connected")]
    Connected,
    #[serde(rename = "disconnected")]
    Disconnected,
    #[serde(untagged)]
    Other(String),
}

#[derive(Clone, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub enum WireType {
    #[serde(rename = "wired")]
    Wired,
    #[serde(rename = "2.4G")]
    Ghz24,
    #[serde(rename = "5G")]
    Ghz5,
    #[serde(untagged)]
    Other(String),
}

#[derive(Clone, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub enum RadioBand {
    #[serde(rename = "2.4GHz")]
    Ghz24,
    #[serde(rename = "5GHz")]
    Ghz5,
    #[serde(untagged)]
    Other(String),
}

#[derive(Clone, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub enum Encryption {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "psk")]
    Psk,
    #[serde(untagged)]
    Other(String),
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum Raw {
    Flag(bool),
    Integer(i64),
    Float(f64),
    Text(String),
}

fn raw_text(raw: Raw) -> String {
    match raw {
        Raw::Flag(flag) => flag.to_string(),
        Raw::Integer(number) => number.to_string(),
        Raw::Float(number) => number.to_string(),
        Raw::Text(text) => text,
    }
}

impl std::str::FromStr for Switch {
    type Err = anyhow::Error;

    fn from_str(text: &str) -> anyhow::Result<Self> {
        match text.trim().to_lowercase().as_str() {
            "on" | "yes" | "true" | "1" => Ok(Switch::On),
            "off" | "no" | "false" | "0" => Ok(Switch::Off),
            other => anyhow::bail!("not a switch value: {other:?}"),
        }
    }
}

impl std::fmt::Display for Switch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Switch::On => "on",
            Switch::Off => "off",
        })
    }
}

impl Switch {
    pub fn is_on(self) -> bool {
        self == Switch::On
    }

    pub fn from_bool(value: bool) -> Switch {
        if value { Switch::On } else { Switch::Off }
    }
}

impl std::str::FromStr for YesNo {
    type Err = anyhow::Error;

    fn from_str(text: &str) -> anyhow::Result<Self> {
        match text.trim().to_lowercase().as_str() {
            "yes" => Ok(YesNo::Yes),
            "no" => Ok(YesNo::No),
            other => anyhow::bail!("not a yes/no value: {other:?}"),
        }
    }
}

impl std::fmt::Display for YesNo {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            YesNo::Yes => "yes",
            YesNo::No => "no",
        })
    }
}

impl std::str::FromStr for Mac {
    type Err = anyhow::Error;

    fn from_str(text: &str) -> anyhow::Result<Self> {
        let digits: String = text.chars().filter(|c| !matches!(c, ':' | '-' | '.')).collect();
        if digits.len() != 12 || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
            anyhow::bail!("invalid MAC address: {text:?}");
        }
        let mut bytes = [0u8; 6];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&digits[index * 2..index * 2 + 2], 16)?;
        }
        Ok(Mac(bytes))
    }
}

impl std::fmt::Display for Mac {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let [a, b, c, d, e, f] = self.0;
        write!(formatter, "{a:02X}-{b:02X}-{c:02X}-{d:02X}-{e:02X}-{f:02X}")
    }
}

impl std::str::FromStr for Ipv6Net {
    type Err = anyhow::Error;

    fn from_str(text: &str) -> anyhow::Result<Self> {
        match text.trim().split_once('/') {
            Some((addr, prefix)) => Ok(Ipv6Net {
                addr: addr.parse()?,
                prefix: Some(prefix.parse()?),
            }),
            None => Ok(Ipv6Net {
                addr: text.trim().parse()?,
                prefix: None,
            }),
        }
    }
}

impl std::fmt::Display for Ipv6Net {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.prefix {
            Some(prefix) => write!(formatter, "{}/{prefix}", self.addr),
            None => write!(formatter, "{}", self.addr),
        }
    }
}

impl std::str::FromStr for Channel {
    type Err = anyhow::Error;

    fn from_str(text: &str) -> anyhow::Result<Self> {
        if text.trim().eq_ignore_ascii_case("auto") {
            Ok(Channel::Auto)
        } else {
            Ok(Channel::Fixed(text.trim().parse()?))
        }
    }
}

impl std::fmt::Display for Channel {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Channel::Auto => formatter.write_str("auto"),
            Channel::Fixed(number) => write!(formatter, "{number}"),
        }
    }
}

macro_rules! text_serde {
    ($type:ty) => {
        impl serde::Serialize for $type {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        impl<'de> serde::Deserialize<'de> for $type {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = raw_text(<Raw as serde::Deserialize>::deserialize(deserializer)?);
                text.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

text_serde!(Switch);
text_serde!(YesNo);
text_serde!(Mac);
text_serde!(Ipv6Net);
text_serde!(Channel);

pub fn number<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let text = raw_text(<Raw as serde::Deserialize>::deserialize(deserializer)?);
    text.trim().parse().map_err(serde::de::Error::custom)
}

pub fn empty_as_none<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match <Option<Raw> as serde::Deserialize>::deserialize(deserializer)? {
        None => Ok(None),
        Some(raw) => {
            let text = raw_text(raw);
            let text = text.trim();
            if text.is_empty() {
                Ok(None)
            } else {
                text.parse().map(Some).map_err(serde::de::Error::custom)
            }
        }
    }
}

pub fn none_as_empty<T: serde::Serialize, S: serde::Serializer>(
    value: &Option<T>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(value) => serde::Serialize::serialize(value, serializer),
        None => serializer.serialize_str(""),
    }
}
