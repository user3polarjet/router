const MAX_PASSWORD_LEN: usize = 125;

pub struct Session {
    pub host: String,
    pub http: reqwest::Client,
    pub aes: crate::crypto::AesSession,
    pub auth_key: rsa::RsaPublicKey,
    pub hash: String,
    pub seq: u64,
    pub stok: String,
    pub sysauth: String,
}

struct Handshake {
    password_key: rsa::RsaPublicKey,
    auth_key: rsa::RsaPublicKey,
    seq: u64,
}

pub fn normalize_host(host: &str) -> String {
    let host = host.trim().trim_end_matches('/');
    if host.starts_with("http://") || host.starts_with("https://") {
        host.to_string()
    } else {
        format!("http://{host}")
    }
}

fn index_url(host: &str) -> String {
    format!("{host}/webpages/index.html")
}

fn pair(value: &serde_json::Value, what: &str) -> anyhow::Result<rsa::RsaPublicKey> {
    let modulus = value
        .get(0)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("{what}: missing modulus in {value}"))?;
    let exponent = value
        .get(1)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("{what}: missing exponent in {value}"))?;
    crate::crypto::rsa_public_key(modulus, exponent)
}

async fn read_form(http: &reqwest::Client, host: &str, form: &str) -> anyhow::Result<serde_json::Value> {
    let url = format!("{host}/cgi-bin/luci/;stok=/login?form={form}&operation=read");
    let text = http.post(url).send().await?.text().await?;
    let mut json: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| anyhow::anyhow!("login form {form}: {e}; response: {text}"))?;
    Ok(json["data"].take())
}

async fn handshake(http: &reqwest::Client, host: &str) -> anyhow::Result<Handshake> {
    let keys = read_form(http, host, "keys").await?;
    let auth = read_form(http, host, "auth").await?;
    let seq = match &auth["seq"] {
        serde_json::Value::String(text) => text.parse::<u64>()?,
        serde_json::Value::Number(number) => number
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("invalid seq: {number}"))?,
        other => anyhow::bail!("login form auth: missing seq in {other}"),
    };
    Ok(Handshake {
        password_key: pair(&keys["password"], "password key")?,
        auth_key: pair(&auth["key"], "auth key")?,
        seq,
    })
}

fn encrypted_form(
    aes: &crate::crypto::AesSession,
    auth_key: &rsa::RsaPublicKey,
    hash: &str,
    seq: u64,
    is_login: bool,
    plain: &str,
) -> anyhow::Result<String> {
    let data = crate::crypto::aes_encrypt(aes, plain)?;
    let sign = crate::crypto::signature(aes, auth_key, hash, seq + data.len() as u64, is_login)?;
    Ok(format!("sign={}&data={}", urlencoding::encode(&sign), urlencoding::encode(&data)))
}

fn sysauth_cookie(headers: &reqwest::header::HeaderMap) -> Option<String> {
    headers
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|value| {
            let rest = value.split("sysauth=").nth(1)?;
            Some(rest.split(';').next()?.to_string())
        })
}

async fn try_login(
    http: &reqwest::Client,
    host: &str,
    aes: &crate::crypto::AesSession,
    handshake: &Handshake,
    hash: &str,
    password: &str,
) -> anyhow::Result<(reqwest::StatusCode, reqwest::header::HeaderMap, String)> {
    let encrypted_password = crate::crypto::rsa_encrypt_hex(&handshake.password_key, password.as_bytes())?;
    let plain = format!("operation=login&password={encrypted_password}&confirm=true");
    let body = encrypted_form(aes, &handshake.auth_key, hash, handshake.seq, true, &plain)?;
    let response = http
        .post(format!("{host}/cgi-bin/luci/;stok=/login?form=login"))
        .header(reqwest::header::REFERER, index_url(host))
        .header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await?;
    let status = response.status();
    let headers = response.headers().clone();
    let text = response.text().await?;
    Ok((status, headers, text))
}

pub async fn login(host: &str, username: &str, password: &str, timeout_secs: u64) -> anyhow::Result<Session> {
    if password.len() > MAX_PASSWORD_LEN {
        anyhow::bail!("password is longer than {MAX_PASSWORD_LEN} bytes, the router cannot accept it");
    }
    let host = normalize_host(host);
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .build()?;
    let aes = crate::crypto::new_aes_session();
    let hash = crate::crypto::credentials_hash(username, password);

    let mut shake = handshake(&http, &host).await?;
    let mut attempt = try_login(&http, &host, &aes, &shake, &hash, password).await?;
    let valid_json = serde_json::from_str::<serde_json::Value>(&attempt.2).is_ok();
    if !valid_json || attempt.0 == reqwest::StatusCode::FORBIDDEN {
        shake = handshake(&http, &host).await?;
        attempt = try_login(&http, &host, &aes, &shake, &hash, password).await?;
    }

    let (status, headers, text) = attempt;
    let envelope: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| anyhow::anyhow!("login failed ({status}): {e}; response: {text}"))?;
    let encrypted = envelope["data"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("login failed ({status}): no encrypted data in {text}"))?;
    let decrypted: serde_json::Value = serde_json::from_str(&crate::crypto::aes_decrypt(&aes, encrypted)?)?;
    let stok = decrypted["data"]["stok"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("login rejected, check username and password: {decrypted}"))?
        .to_string();
    let sysauth = sysauth_cookie(&headers).ok_or_else(|| anyhow::anyhow!("login response has no sysauth cookie"))?;

    Ok(Session {
        host,
        http,
        aes,
        auth_key: shake.auth_key,
        hash,
        seq: shake.seq,
        stok,
        sysauth,
    })
}

fn build_url(host: &str, stok: &str, path: &str, params: &[(&str, &str)]) -> String {
    let mut path = path.to_string();
    for (key, value) in params {
        if !path.contains(&format!("{key}=")) {
            path.push_str(&format!("&{key}={}", urlencoding::encode(value)));
        }
    }
    format!("{host}/cgi-bin/luci/;stok={stok}/{path}")
}

async fn send(session: &Session, path: &str, params: &[(&str, &str)]) -> anyhow::Result<reqwest::Response> {
    let payload: serde_json::Map<String, serde_json::Value> = params
        .iter()
        .map(|(key, value)| (key.to_string(), serde_json::Value::String(value.to_string())))
        .collect();
    let plain = serde_json::Value::Object(payload).to_string();
    let body = encrypted_form(&session.aes, &session.auth_key, &session.hash, session.seq, false, &plain)?;
    Ok(session
        .http
        .post(build_url(&session.host, &session.stok, path, params))
        .header(reqwest::header::REFERER, index_url(&session.host))
        .header(reqwest::header::ORIGIN, &session.host)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(reqwest::header::COOKIE, format!("sysauth={}", session.sysauth))
        .body(body)
        .send()
        .await?)
}

pub async fn envelope_params(
    session: &Session,
    path: &str,
    params: &[(&str, &str)],
) -> anyhow::Result<serde_json::Value> {
    let text = send(session, path, params).await?.text().await?;
    let envelope: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| anyhow::anyhow!("{path}: response is not JSON: {e}; response: {text}"))?;
    let encrypted = envelope["data"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("{path}: router did not answer with encrypted data: {text}"))?;
    let decrypted: serde_json::Value = serde_json::from_str(&crate::crypto::aes_decrypt(&session.aes, encrypted)?)
        .map_err(|e| anyhow::anyhow!("{path}: decrypted response is not JSON: {e}"))?;
    let success = decrypted["success"].as_bool().unwrap_or(false);
    if !success || decrypted.get("data").is_none() {
        anyhow::bail!("{path}: router reported an error: {decrypted}");
    }
    Ok(decrypted)
}

pub async fn request_envelope(session: &Session, path: &str, operation: &str) -> anyhow::Result<serde_json::Value> {
    envelope_params(session, path, &[("operation", operation)]).await
}

pub async fn request_params(
    session: &Session,
    path: &str,
    params: &[(&str, &str)],
) -> anyhow::Result<serde_json::Value> {
    let mut envelope = envelope_params(session, path, params).await?;
    Ok(envelope["data"].take())
}

pub async fn request(session: &Session, path: &str, operation: &str) -> anyhow::Result<serde_json::Value> {
    request_params(session, path, &[("operation", operation)]).await
}

pub async fn fire_and_forget(session: &Session, path: &str, operation: &str) -> anyhow::Result<()> {
    send(session, path, &[("operation", operation)]).await?;
    Ok(())
}

pub async fn logout(session: &Session) -> anyhow::Result<()> {
    fire_and_forget(session, "admin/system?form=logout", "write").await
}

pub fn list_rows(data: &serde_json::Value, keys: &[&str], what: &str) -> anyhow::Result<Vec<serde_json::Value>> {
    match data {
        serde_json::Value::Array(items) => Ok(items.clone()),
        serde_json::Value::Object(map) if map.is_empty() => Ok(Vec::new()),
        serde_json::Value::Object(map) => keys
            .iter()
            .find_map(|key| map.get(*key).and_then(serde_json::Value::as_array).cloned())
            .ok_or_else(|| anyhow::anyhow!("{what}: object without a list under {keys:?}, keys: {:?}", map.keys())),
        serde_json::Value::Null => Ok(Vec::new()),
        other => anyhow::bail!("{what}: neither a list nor an object: {other}"),
    }
}

pub async fn typed<T: serde::de::DeserializeOwned>(
    session: &Session,
    path: &str,
    operation: &str,
) -> anyhow::Result<T> {
    let data = request(session, path, operation).await?;
    serde_json::from_value(data).map_err(|e| anyhow::anyhow!("{path}: {e}"))
}

pub async fn typed_list<T: serde::de::DeserializeOwned>(
    session: &Session,
    path: &str,
    operation: &str,
    keys: &[&str],
) -> anyhow::Result<Vec<T>> {
    let data = request(session, path, operation).await?;
    list_rows(&data, keys, path)?
        .into_iter()
        .map(|row| serde_json::from_value(row).map_err(|e| anyhow::anyhow!("{path}: {e}")))
        .collect()
}
