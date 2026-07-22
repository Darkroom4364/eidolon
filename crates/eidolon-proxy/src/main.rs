use std::{
    collections::HashSet,
    env, fmt, fs,
    io::{self},
    net::{IpAddr, SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use eidolon_bait::BaitRegistry;
use eidolon_core::{Bait, HeaderValueMint};
use eidolon_proxy::{
    controlled_reality::{
        ControlledRealityConfig, ControlledRealityResponder, DEFAULT_RETRY_AFTER_SECONDS,
        DEFAULT_TARPIT_DELAY, MAX_CONTROLLED_REALITY_ACTION_DEPTH, MAX_TARPIT_DELAY,
    },
    debug_log::FileDebugLogWriter,
    event_log::FileEventLogWriter,
    http::*,
    ingress_identity::{self, IngressIdentityResolver},
    policy_store::PolicyStateStore,
    request_flow::*,
    runtime::*,
    session_auth::SessionAuthority,
    surface_content::*,
};
use serde::Deserialize;
use serde_json::{json, Value};

const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:8080";
const DEFAULT_UPSTREAM: &str = "http://127.0.0.1:9001";
const DEFAULT_EVENT_LOG: &str = "/tmp/eidolon-events.jsonl";
const DEFAULT_INTERVENTION_CONTROL: &str = "/tmp/eidolon-interventions.txt";
const DEFAULT_POLICY_STATE: &str = "/tmp/eidolon-policy-state.json";
const DEFAULT_TRUSTED_BAIT_SOFTEN_PREFIXES: &[&str] = &["/docs", "/openapi.json"];
fn main() -> ExitCode {
    match CliAction::from_args(env::args().skip(1)) {
        Ok(CliAction::Help) => {
            print!("{}", usage());
            ExitCode::SUCCESS
        }
        Ok(CliAction::Run(config)) => {
            println!("eidolon-proxy configured");
            println!("listen_addr: {}", config.listen_addr);
            println!("upstream: {}", config.upstream);
            println!("event_log: {}", config.event_log_path.display());
            match &config.debug_log_path {
                Some(path) => println!("debug_log: {}", path.display()),
                None => println!("debug_log: disabled"),
            }
            match &config.bait_profile_path {
                Some(path) => println!("bait_profile: {}", path.display()),
                None => println!("bait_profile: default"),
            }
            match &config.ingress_trust_config_path {
                Some(path) => println!("ingress_trust_config: {}", path.display()),
                None => println!("ingress_trust_config: disabled"),
            }
            println!(
                "ingress_transport_auth: {}",
                if config.ingress_transport_auth_secret_path.is_some() {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            println!(
                "trusted_bait_soften_prefixes: {}",
                config.trusted_bait_soften_path_prefixes.join(", ")
            );
            println!(
                "intervention_control: {}",
                config.intervention_control_path.display()
            );
            println!("policy_state: {}", config.policy_state_path.display());
            println!(
                "controlled_reality: max_depth={}, tarpit_ms={}, retry_after_seconds={}",
                config.controlled_reality_config.max_action_depth,
                config.controlled_reality_config.tarpit_delay.as_millis(),
                config.controlled_reality_config.retry_after_seconds
            );
            println!(
                "owned_cluster_lab: {}",
                if config.owned_cluster_lab {
                    "enabled"
                } else {
                    "disabled"
                }
            );

            match run_proxy(*config) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("error: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        Err(error) => {
            eprintln!("error: {error}\n\n{}", usage());
            ExitCode::from(2)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProxyConfig {
    listen_addr: SocketAddr,
    upstream: UpstreamTarget,
    event_log_path: PathBuf,
    debug_log_path: Option<PathBuf>,
    bait_profile_path: Option<PathBuf>,
    bait_signing_secret_path: Option<PathBuf>,
    session_signing_key_path: Option<PathBuf>,
    ingress_trust_config_path: Option<PathBuf>,
    ingress_transport_auth_secret_path: Option<PathBuf>,
    trusted_bait_soften_path_prefixes: Vec<String>,
    intervention_control_path: PathBuf,
    policy_state_path: PathBuf,
    controlled_reality_config: ControlledRealityConfig,
    owned_cluster_lab: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CliAction {
    Run(Box<ProxyConfig>),
    Help,
}

impl CliAction {
    fn from_args<I, S>(args: I) -> Result<Self, ConfigError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut builder = ConfigBuilder::default();
        let mut args = args.into_iter().map(Into::into).peekable();

        while let Some(arg) = args.next() {
            if arg == "-h" || arg == "--help" {
                return Ok(Self::Help);
            }

            let (flag, inline_value) = split_option(&arg)?;
            match flag {
                "--listen-addr" => {
                    let value = option_value(flag, inline_value, &mut args)?;
                    set_once(&mut builder.listen_addr, flag, value)?;
                }
                "--upstream" => {
                    let value = option_value(flag, inline_value, &mut args)?;
                    set_once(&mut builder.upstream, flag, value)?;
                }
                "--event-log" => {
                    let value = option_value(flag, inline_value, &mut args)?;
                    set_once(
                        &mut builder.event_log_path,
                        flag,
                        parse_event_log_path(&value)?,
                    )?;
                }
                "--debug-log" => {
                    let value = option_value(flag, inline_value, &mut args)?;
                    set_once(
                        &mut builder.debug_log_path,
                        flag,
                        parse_debug_log_path(&value)?,
                    )?;
                }
                "--bait-profile" => {
                    let value = option_value(flag, inline_value, &mut args)?;
                    set_once(
                        &mut builder.bait_profile_path,
                        flag,
                        parse_bait_profile_path(&value)?,
                    )?;
                }
                "--bait-signing-secret-file" => {
                    let value = option_value(flag, inline_value, &mut args)?;
                    set_once(
                        &mut builder.bait_signing_secret_path,
                        flag,
                        parse_bait_signing_secret_path(&value)?,
                    )?;
                }
                "--session-signing-key-file" => {
                    let value = option_value(flag, inline_value, &mut args)?;
                    set_once(
                        &mut builder.session_signing_key_path,
                        flag,
                        parse_session_signing_key_path(&value)?,
                    )?;
                }
                "--ingress-trust-config" => {
                    let value = option_value(flag, inline_value, &mut args)?;
                    set_once(
                        &mut builder.ingress_trust_config_path,
                        flag,
                        parse_ingress_trust_config_path(&value)?,
                    )?;
                }
                "--ingress-transport-auth-secret-file" => {
                    let value = option_value(flag, inline_value, &mut args)?;
                    set_once(
                        &mut builder.ingress_transport_auth_secret_path,
                        flag,
                        parse_ingress_transport_auth_secret_path(&value)?,
                    )?;
                }
                "--trusted-bait-soften-prefix" => {
                    let value = option_value(flag, inline_value, &mut args)?;
                    push_unique(
                        &mut builder.trusted_bait_soften_path_prefixes,
                        flag,
                        parse_trusted_bait_soften_prefix(&value)?,
                    )?;
                }
                "--intervention-control" => {
                    let value = option_value(flag, inline_value, &mut args)?;
                    set_once(
                        &mut builder.intervention_control_path,
                        flag,
                        parse_control_path(&value)?,
                    )?;
                }
                "--policy-state" => {
                    let value = option_value(flag, inline_value, &mut args)?;
                    set_once(
                        &mut builder.policy_state_path,
                        flag,
                        parse_policy_state_path(&value)?,
                    )?;
                }
                "--controlled-reality-max-depth" => {
                    let value = option_value(flag, inline_value, &mut args)?;
                    set_once(
                        &mut builder.controlled_reality_max_depth,
                        flag,
                        parse_u32_option(&value, "controlled reality max depth")?,
                    )?;
                }
                "--controlled-reality-tarpit-ms" => {
                    let value = option_value(flag, inline_value, &mut args)?;
                    set_once(
                        &mut builder.controlled_reality_tarpit_delay,
                        flag,
                        parse_tarpit_delay(&value, "controlled reality tarpit milliseconds")?,
                    )?;
                }
                "--controlled-reality-retry-after-seconds" => {
                    let value = option_value(flag, inline_value, &mut args)?;
                    set_once(
                        &mut builder.controlled_reality_retry_after_seconds,
                        flag,
                        parse_u64_option(&value, "controlled reality retry-after seconds")?,
                    )?;
                }
                "--owned-cluster-lab" => {
                    if builder.owned_cluster_lab {
                        return Err(ConfigError::new(format!("duplicate option `{flag}`")));
                    }
                    builder.owned_cluster_lab = true;
                }
                _ if flag.starts_with('-') => {
                    return Err(ConfigError::new(format!("unknown option `{flag}`")));
                }
                _ => {
                    return Err(ConfigError::new(format!(
                        "unexpected positional argument `{flag}`"
                    )));
                }
            }
        }

        builder.build().map(Box::new).map(Self::Run)
    }
}

#[derive(Debug, Default)]
struct ConfigBuilder {
    listen_addr: Option<String>,
    upstream: Option<String>,
    event_log_path: Option<PathBuf>,
    debug_log_path: Option<PathBuf>,
    bait_profile_path: Option<PathBuf>,
    bait_signing_secret_path: Option<PathBuf>,
    session_signing_key_path: Option<PathBuf>,
    ingress_trust_config_path: Option<PathBuf>,
    ingress_transport_auth_secret_path: Option<PathBuf>,
    trusted_bait_soften_path_prefixes: Vec<String>,
    intervention_control_path: Option<PathBuf>,
    policy_state_path: Option<PathBuf>,
    controlled_reality_max_depth: Option<u32>,
    controlled_reality_tarpit_delay: Option<Duration>,
    controlled_reality_retry_after_seconds: Option<u64>,
    owned_cluster_lab: bool,
}

impl ConfigBuilder {
    fn build(self) -> Result<ProxyConfig, ConfigError> {
        Ok(ProxyConfig {
            listen_addr: match self.listen_addr {
                Some(value) => parse_listen_addr(&value, self.owned_cluster_lab)?,
                None => parse_listen_addr(DEFAULT_LISTEN_ADDR, self.owned_cluster_lab)?,
            },
            upstream: match self.upstream {
                Some(value) => parse_upstream(&value, self.owned_cluster_lab)?,
                None => parse_upstream(DEFAULT_UPSTREAM, self.owned_cluster_lab)?,
            },
            event_log_path: match self.event_log_path {
                Some(value) => value,
                None => parse_event_log_path(DEFAULT_EVENT_LOG)?,
            },
            debug_log_path: self.debug_log_path,
            bait_profile_path: self.bait_profile_path,
            bait_signing_secret_path: self.bait_signing_secret_path,
            session_signing_key_path: self.session_signing_key_path,
            ingress_trust_config_path: self.ingress_trust_config_path,
            ingress_transport_auth_secret_path: self.ingress_transport_auth_secret_path,
            trusted_bait_soften_path_prefixes: if self.trusted_bait_soften_path_prefixes.is_empty()
            {
                default_trusted_bait_soften_path_prefixes()
            } else {
                self.trusted_bait_soften_path_prefixes
            },
            intervention_control_path: match self.intervention_control_path {
                Some(value) => value,
                None => parse_control_path(DEFAULT_INTERVENTION_CONTROL)?,
            },
            policy_state_path: match self.policy_state_path {
                Some(value) => value,
                None => parse_policy_state_path(DEFAULT_POLICY_STATE)?,
            },
            controlled_reality_config: ControlledRealityConfig {
                max_action_depth: self
                    .controlled_reality_max_depth
                    .unwrap_or(MAX_CONTROLLED_REALITY_ACTION_DEPTH),
                tarpit_delay: self
                    .controlled_reality_tarpit_delay
                    .unwrap_or(DEFAULT_TARPIT_DELAY),
                retry_after_seconds: self
                    .controlled_reality_retry_after_seconds
                    .unwrap_or(DEFAULT_RETRY_AFTER_SECONDS),
            },
            owned_cluster_lab: self.owned_cluster_lab,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConfigError {
    message: String,
}

impl ConfigError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

fn split_option(arg: &str) -> Result<(&str, Option<String>), ConfigError> {
    if let Some((flag, value)) = arg.split_once('=') {
        if flag.is_empty() {
            return Err(ConfigError::new("empty option name"));
        }

        Ok((flag, Some(value.to_string())))
    } else {
        Ok((arg, None))
    }
}

fn option_value<I>(
    flag: &str,
    inline_value: Option<String>,
    args: &mut std::iter::Peekable<I>,
) -> Result<String, ConfigError>
where
    I: Iterator<Item = String>,
{
    if let Some(value) = inline_value {
        return Ok(value);
    }

    match args.next() {
        Some(value) if !value.starts_with('-') => Ok(value),
        Some(next_flag) => Err(ConfigError::new(format!(
            "missing value for `{flag}` before `{next_flag}`"
        ))),
        None => Err(ConfigError::new(format!("missing value for `{flag}`"))),
    }
}

fn set_once<T>(slot: &mut Option<T>, flag: &str, value: T) -> Result<(), ConfigError> {
    if slot.replace(value).is_some() {
        return Err(ConfigError::new(format!("duplicate option `{flag}`")));
    }

    Ok(())
}

fn push_unique<T>(values: &mut Vec<T>, flag: &str, value: T) -> Result<(), ConfigError>
where
    T: PartialEq,
{
    if values.contains(&value) {
        return Err(ConfigError::new(format!("duplicate option `{flag}`")));
    }
    values.push(value);
    Ok(())
}

fn parse_listen_addr(raw: &str, owned_cluster_lab: bool) -> Result<SocketAddr, ConfigError> {
    let addr = raw.parse::<SocketAddr>().map_err(|error| {
        ConfigError::new(format!(
            "listen address must be a socket address such as {DEFAULT_LISTEN_ADDR}: {error}"
        ))
    })?;

    if !owned_cluster_lab && !addr.ip().is_loopback() {
        return Err(ConfigError::new(
            "listen address must bind to a loopback address for the local lab",
        ));
    }

    if addr.port() == 0 {
        return Err(ConfigError::new("listen address port must not be 0"));
    }

    Ok(addr)
}

fn parse_upstream(raw: &str, owned_cluster_lab: bool) -> Result<UpstreamTarget, ConfigError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(ConfigError::new("upstream target URL cannot be empty"));
    }

    let rest = raw.strip_prefix("http://").ok_or_else(|| {
        ConfigError::new(format!(
            "upstream target must be an http loopback URL such as {DEFAULT_UPSTREAM}"
        ))
    })?;

    if rest.contains('?') || rest.contains('#') {
        return Err(ConfigError::new(
            "upstream target must not include query strings or fragments",
        ));
    }

    let authority = match rest.split_once('/') {
        Some((authority, "")) => authority,
        Some(_) => {
            return Err(ConfigError::new(
                "upstream target must not include a path; use only scheme, host, and port",
            ));
        }
        None => rest,
    };

    if authority.is_empty() {
        return Err(ConfigError::new("upstream target host cannot be empty"));
    }

    let (host, port) =
        parse_authority(authority).map_err(|error| ConfigError::new(error.to_string()))?;
    ensure_allowed_upstream_host(host, owned_cluster_lab)?;

    if matches!(port, Some(0)) {
        return Err(ConfigError::new("upstream target port must not be 0"));
    }

    let connect_addr = connect_addr(host, port.unwrap_or(DEFAULT_HTTP_PORT));

    Ok(UpstreamTarget {
        raw: format!("http://{authority}"),
        authority: authority.to_string(),
        connect_addr,
    })
}

fn parse_u32_option(raw: &str, label: &str) -> Result<u32, ConfigError> {
    if raw.is_empty() {
        return Err(ConfigError::new(format!("{label} cannot be empty")));
    }

    raw.parse::<u32>().map_err(|error| {
        ConfigError::new(format!("{label} must be a non-negative integer: {error}"))
    })
}

fn parse_u64_option(raw: &str, label: &str) -> Result<u64, ConfigError> {
    if raw.is_empty() {
        return Err(ConfigError::new(format!("{label} cannot be empty")));
    }

    raw.parse::<u64>().map_err(|error| {
        ConfigError::new(format!("{label} must be a non-negative integer: {error}"))
    })
}

fn parse_tarpit_delay(raw: &str, label: &str) -> Result<Duration, ConfigError> {
    let milliseconds = parse_u64_option(raw, label)?;
    let delay = Duration::from_millis(milliseconds);
    if delay > MAX_TARPIT_DELAY {
        return Err(ConfigError::new(format!(
            "{label} must be at most {}ms for the local lab",
            MAX_TARPIT_DELAY.as_millis()
        )));
    }

    Ok(delay)
}

fn ensure_allowed_upstream_host(host: &str, owned_cluster_lab: bool) -> Result<(), ConfigError> {
    if host.eq_ignore_ascii_case("localhost") {
        return Ok(());
    }

    match host.parse::<IpAddr>() {
        Ok(ip) if ip.is_loopback() => Ok(()),
        Ok(ip) if owned_cluster_lab && !ip.is_unspecified() => Ok(()),
        Ok(_) => Err(ConfigError::new(
            "upstream target host must be loopback for the local lab",
        )),
        Err(_) if owned_cluster_lab => Ok(()),
        Err(_) => Err(ConfigError::new(
            "upstream target host must be loopback: use localhost, a 127.0.0.0/8 address, or ::1 for the local lab",
        )),
    }
}

fn parse_event_log_path(raw: &str) -> Result<PathBuf, ConfigError> {
    parse_file_path(raw, "event log")
}

fn parse_debug_log_path(raw: &str) -> Result<PathBuf, ConfigError> {
    parse_file_path(raw, "debug log")
}

fn parse_bait_profile_path(raw: &str) -> Result<PathBuf, ConfigError> {
    let path = parse_file_path(raw, "bait profile")?;
    if !path.is_file() {
        return Err(ConfigError::new(format!(
            "bait profile path must be an existing file: `{}`",
            path.display()
        )));
    }

    Ok(path)
}

fn parse_bait_signing_secret_path(raw: &str) -> Result<PathBuf, ConfigError> {
    let path = parse_file_path(raw, "bait signing secret")?;
    if !path.is_file() {
        return Err(ConfigError::new(format!(
            "bait signing secret path must be an existing file: `{}`",
            path.display()
        )));
    }

    Ok(path)
}

fn parse_session_signing_key_path(raw: &str) -> Result<PathBuf, ConfigError> {
    let path = parse_file_path(raw, "session signing key")?;
    if !path.is_file() {
        return Err(ConfigError::new(format!(
            "session signing key path must be an existing file: `{}`",
            path.display()
        )));
    }

    Ok(path)
}

fn parse_ingress_trust_config_path(raw: &str) -> Result<PathBuf, ConfigError> {
    let path = parse_file_path(raw, "ingress trust config")?;
    if !path.is_file() {
        return Err(ConfigError::new(format!(
            "ingress trust config path must be an existing file: `{}`",
            path.display()
        )));
    }

    Ok(path)
}

fn parse_ingress_transport_auth_secret_path(raw: &str) -> Result<PathBuf, ConfigError> {
    let path = parse_file_path(raw, "ingress transport auth secret")?;
    if !path.is_file() {
        return Err(ConfigError::new(format!(
            "ingress transport auth secret path must be an existing file: `{}`",
            path.display()
        )));
    }

    Ok(path)
}

fn load_ingress_transport_auth_secret(path: &Path) -> io::Result<Arc<str>> {
    load_non_empty_secret(path, "ingress transport auth secret")
}

fn load_bait_signing_secret(path: &Path) -> io::Result<Arc<str>> {
    load_non_empty_secret(path, "bait signing secret")
}

fn load_non_empty_secret(path: &Path, label: &str) -> io::Result<Arc<str>> {
    let secret = fs::read_to_string(path)?;
    let secret = secret.trim();
    if secret.is_empty() {
        return Err(invalid_data(format!(
            "{label} file `{}` must not be empty",
            path.display(),
        )));
    }

    Ok(Arc::<str>::from(secret.to_owned()))
}

fn parse_trusted_bait_soften_prefix(raw: &str) -> Result<String, ConfigError> {
    let prefix = raw.trim();
    if prefix.is_empty() {
        return Err(ConfigError::new(
            "trusted bait soften prefix cannot be empty",
        ));
    }
    if !prefix.starts_with('/') {
        return Err(ConfigError::new(
            "trusted bait soften prefix must start with `/`",
        ));
    }

    Ok(prefix.to_string())
}

fn default_trusted_bait_soften_path_prefixes() -> Vec<String> {
    DEFAULT_TRUSTED_BAIT_SOFTEN_PREFIXES
        .iter()
        .map(|prefix| (*prefix).to_string())
        .collect()
}

fn parse_control_path(raw: &str) -> Result<PathBuf, ConfigError> {
    parse_file_path(raw, "intervention control")
}

fn parse_policy_state_path(raw: &str) -> Result<PathBuf, ConfigError> {
    parse_file_path(raw, "policy state")
}

fn parse_file_path(raw: &str, label: &str) -> Result<PathBuf, ConfigError> {
    if raw.trim().is_empty() {
        return Err(ConfigError::new(format!("{label} path cannot be empty")));
    }

    let path = PathBuf::from(raw);
    if path.exists() && path.is_dir() {
        return Err(ConfigError::new(format!(
            "{label} path must be a file path, got directory `{}`",
            path.display()
        )));
    }

    if let Some(parent) = meaningful_parent(&path) {
        if !parent.exists() {
            return Err(ConfigError::new(format!(
                "{label} parent directory does not exist: `{}`",
                parent.display()
            )));
        }

        if !parent.is_dir() {
            return Err(ConfigError::new(format!(
                "{label} parent path is not a directory: `{}`",
                parent.display()
            )));
        }
    }

    Ok(path)
}

fn meaningful_parent(path: &Path) -> Option<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
}

fn connect_addr(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn run_proxy(config: ProxyConfig) -> io::Result<()> {
    let listener = TcpListener::bind(config.listen_addr)?;
    println!(
        "eidolon-proxy listening on http://{}",
        listener.local_addr()?
    );
    println!("forwarding normal traffic to {}", config.upstream);

    let loaded_bait_profile = match &config.bait_profile_path {
        Some(path) => load_bait_profile(path).map_err(|error| invalid_data(error.to_string()))?,
        None => default_loaded_bait_profile(),
    };
    let bait_signing_secret = match &config.bait_signing_secret_path {
        Some(path) => Some(load_bait_signing_secret(path)?),
        None => None,
    };
    if bait_profile_requires_signing_secret(&loaded_bait_profile) && bait_signing_secret.is_none() {
        return Err(invalid_data(
            "bait profile contains session-minted bait values but no bait signing secret file was configured",
        ));
    }
    let bait_profile_debug = bait_profile_debug_value(&loaded_bait_profile.metadata);
    let bait_registry = Arc::new(loaded_bait_profile.registry);
    let bait_content = loaded_bait_profile.content;
    let ingress_identity_resolver = match &config.ingress_trust_config_path {
        Some(path) => ingress_identity::load_ingress_identity_resolver(path)
            .map_err(|error| invalid_data(error.to_string()))?,
        None => IngressIdentityResolver::default(),
    };
    let ingress_transport_auth_secret = match &config.ingress_transport_auth_secret_path {
        Some(path) => Some(load_ingress_transport_auth_secret(path)?),
        None => None,
    };
    let debug_log = match &config.debug_log_path {
        Some(path) => Some(Arc::new(Mutex::new(FileDebugLogWriter::open(path)?))),
        None => None,
    };
    let (session_authority, session_signing_mode) = match &config.session_signing_key_path {
        Some(path) => (
            SessionAuthority::from_key_file_json(&fs::read(path)?)?,
            "configured",
        ),
        None => (SessionAuthority::ephemeral(), "ephemeral"),
    };
    let session_signing_debug = json!({
        "mode": session_signing_mode,
        "active_key_version": session_authority.active_key_version(),
        "key_version_count": session_authority.key_version_count(),
    });
    let bait_exposures = BaitExposureStore::from_event_log(&config.event_log_path)?;
    let restored_bait_exposure_count = bait_exposures.len();
    let bait_action_replays = BaitActionReplayStore::from_event_log(&config.event_log_path)?;
    let restored_bait_action_replay_count = bait_action_replays.consumed.len();
    let runtime = ProxyRuntime {
        upstream: config.upstream,
        event_log: Arc::new(Mutex::new(FileEventLogWriter::open(
            &config.event_log_path,
        )?)),
        debug_log,
        intervention_control_path: config.intervention_control_path,
        policy_store: Arc::new(Mutex::new(PolicyStateStore::open(
            &config.policy_state_path,
        )?)),
        session_authority: Arc::new(Mutex::new(session_authority)),
        controlled_reality_config: config.controlled_reality_config,
        controlled_reality: Arc::new(ControlledRealityResponder),
        surface_controller: Arc::new(M1DemoSurfaceController::with_content_overrides(
            Arc::clone(&bait_registry),
            bait_content.clone(),
            bait_signing_secret.clone(),
        )),
        ingress_identity_resolver: Arc::new(ingress_identity_resolver),
        ingress_transport_auth_secret,
        bait_signing_secret: bait_signing_secret.clone(),
        trusted_bait_soften_path_prefixes: config.trusted_bait_soften_path_prefixes,
        bait_registry,
        bait_content,
        bait_exposures: Arc::new(Mutex::new(bait_exposures)),
        bait_action_replays: Arc::new(Mutex::new(bait_action_replays)),
    };
    write_debug(
        &runtime,
        "proxy_started",
        None,
        json!({
            "listen_addr": listener.local_addr()?.to_string(),
            "upstream": runtime.upstream.to_string(),
            "controlled_reality": {
                "max_depth": runtime.controlled_reality_config.max_action_depth,
                "tarpit_ms": runtime.controlled_reality_config.tarpit_delay.as_millis(),
                "retry_after_seconds": runtime.controlled_reality_config.retry_after_seconds,
            },
            "bait_profile": bait_profile_debug,
            "bait_signing_enabled": bait_signing_secret.is_some(),
            "unsafe_bait_action_shapes": runtime
                .bait_registry
                .unsafe_action_shapes()
                .iter()
                .map(|(method, path)| json!({ "method": method, "path": path }))
                .collect::<Vec<_>>(),
            "session_signing": session_signing_debug,
            "ingress_identity_rule_count": runtime.ingress_identity_resolver.len(),
            "ingress_transport_auth_enabled": runtime.ingress_transport_auth_secret.is_some(),
            "trusted_bait_soften_path_prefixes": runtime.trusted_bait_soften_path_prefixes,
            "restored_bait_exposure_count": restored_bait_exposure_count,
            "restored_bait_action_replay_count": restored_bait_action_replay_count,
            "debug_log_visibility": "server_side_only",
        }),
    )?;

    let connection_limiter = ConnectionLimiter::new(MAX_CONCURRENT_CONNECTIONS);
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Some(permit) = connection_limiter.try_acquire() {
                    let runtime = runtime.clone();
                    thread::spawn(move || {
                        let _permit = permit;
                        if let Err(error) = handle_connection(stream, &runtime) {
                            eprintln!("proxy connection error: {error}");
                        }
                    });
                } else {
                    eprintln!("proxy connection rejected: concurrent connection limit reached");
                }
            }
            Err(error) => eprintln!("proxy accept error: {error}"),
        }
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BaitProfileMetadata {
    profile_id: String,
    hypothesis: Option<String>,
}

#[derive(Debug, Clone)]
struct LoadedBaitProfile {
    registry: BaitRegistry,
    content: BaitContentOverrides,
    metadata: Option<BaitProfileMetadata>,
}

fn bait_profile_requires_signing_secret(profile: &LoadedBaitProfile) -> bool {
    profile
        .registry
        .baits()
        .iter()
        .any(|bait| bait.expected_action.header_value_mint.is_some())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBaitProfile {
    schema_version: u16,
    profile_id: String,
    #[serde(default)]
    hypothesis: Option<String>,
    #[serde(default)]
    baits: Option<Vec<Bait>>,
    #[serde(default)]
    content: BaitContentOverrides,
}

fn default_loaded_bait_profile() -> LoadedBaitProfile {
    LoadedBaitProfile {
        registry: BaitRegistry::m3_catalog(),
        content: BaitContentOverrides::default(),
        metadata: None,
    }
}

fn load_bait_profile(path: &Path) -> Result<LoadedBaitProfile, ConfigError> {
    let raw = fs::read_to_string(path).map_err(|error| {
        ConfigError::new(format!(
            "failed to read bait profile `{}`: {error}",
            path.display()
        ))
    })?;

    let profile: RawBaitProfile = serde_json::from_str(&raw).map_err(|error| {
        ConfigError::new(format!(
            "failed to parse bait profile `{}`: {error}",
            path.display()
        ))
    })?;

    profile.into_loaded()
}

impl RawBaitProfile {
    fn into_loaded(self) -> Result<LoadedBaitProfile, ConfigError> {
        if self.schema_version != 1 {
            return Err(ConfigError::new(format!(
                "bait profile schema_version must be 1, got {}",
                self.schema_version
            )));
        }
        validate_non_empty("profile_id", &self.profile_id)?;
        validate_optional_non_empty("hypothesis", self.hypothesis.as_deref())?;
        self.content.validate().map_err(ConfigError::new)?;

        let registry = match self.baits {
            Some(baits) => registry_from_profile_baits(baits)?,
            None => BaitRegistry::m3_catalog(),
        };
        ensure_surface_overrides_reference_baits(&self.content, &registry)?;

        Ok(LoadedBaitProfile {
            registry,
            content: self.content,
            metadata: Some(BaitProfileMetadata {
                profile_id: self.profile_id,
                hypothesis: self.hypothesis,
            }),
        })
    }
}

fn registry_from_profile_baits(baits: Vec<Bait>) -> Result<BaitRegistry, ConfigError> {
    if baits.is_empty() {
        return Err(ConfigError::new("bait profile baits must not be empty"));
    }

    let mut ids = HashSet::new();
    let mut surfaces = HashSet::new();
    let mut actions = HashSet::new();
    let mut registry = BaitRegistry::new();

    for bait in baits {
        validate_bait(&bait)?;

        if !ids.insert(bait.id.0.clone()) {
            return Err(ConfigError::new(format!(
                "duplicate bait id `{}` in bait profile",
                bait.id.0
            )));
        }
        if !surfaces.insert(bait.surface.clone()) {
            return Err(ConfigError::new(format!(
                "duplicate bait surface `{}` in bait profile",
                bait.surface
            )));
        }

        let action_key = (
            bait.expected_action.method.to_ascii_uppercase(),
            bait.expected_action.path.clone(),
            bait.expected_action
                .header_name
                .as_ref()
                .map(|name| name.trim().to_ascii_lowercase()),
            bait.expected_action
                .header_value
                .as_ref()
                .map(|value| value.trim().to_string()),
            bait.expected_action
                .header_value_mint
                .as_ref()
                .map(action_mint_key),
        );
        if !actions.insert(action_key) {
            return Err(ConfigError::new(format!(
                "duplicate bait action `{} {}` in bait profile",
                bait.expected_action.method, bait.expected_action.path
            )));
        }

        registry.add(bait);
    }

    Ok(registry)
}

fn validate_bait(bait: &Bait) -> Result<(), ConfigError> {
    validate_non_empty("bait.id", &bait.id.0)?;
    validate_path("bait.surface", &bait.surface)?;
    validate_non_empty("bait.expected_action.method", &bait.expected_action.method)?;
    validate_path("bait.expected_action.path", &bait.expected_action.path)?;
    validate_optional_non_empty(
        "bait.expected_action.header_name",
        bait.expected_action.header_name.as_deref(),
    )?;
    validate_optional_non_empty(
        "bait.expected_action.header_value",
        bait.expected_action.header_value.as_deref(),
    )?;
    validate_optional_header_value_mint(
        "bait.expected_action.header_value_mint",
        bait.expected_action.header_value_mint.as_ref(),
    )?;

    if bait.expected_action.header_value.is_some() && bait.expected_action.header_name.is_none() {
        return Err(ConfigError::new(
            "bait expected action cannot require a header value without naming the header",
        ));
    }
    if bait.expected_action.header_value_mint.is_some()
        && bait.expected_action.header_name.is_none()
    {
        return Err(ConfigError::new(
            "bait expected action cannot require a minted header value without naming the header",
        ));
    }
    if bait.expected_action.header_value.is_some()
        && bait.expected_action.header_value_mint.is_some()
    {
        return Err(ConfigError::new(
            "bait expected action cannot set both a static header value and a minted header value",
        ));
    }

    Ok(())
}

fn action_mint_key(mint: &HeaderValueMint) -> (&'static str, String) {
    (
        match mint.kind {
            eidolon_core::HeaderValueMintKind::SessionHmacSha256V1 => "session_hmac_sha256_v1",
        },
        mint.prefix.trim().to_string(),
    )
}

fn validate_optional_header_value_mint(
    label: &str,
    mint: Option<&HeaderValueMint>,
) -> Result<(), ConfigError> {
    let Some(mint) = mint else {
        return Ok(());
    };
    validate_non_empty(&format!("{label}.prefix"), &mint.prefix)?;
    if mint.proof_window_seconds == Some(0) {
        return Err(ConfigError::new(format!(
            "{label}.proof_window_seconds must be greater than zero"
        )));
    }
    Ok(())
}

fn ensure_surface_overrides_reference_baits(
    content: &BaitContentOverrides,
    registry: &BaitRegistry,
) -> Result<(), ConfigError> {
    for bait_id in content.surfaces.keys() {
        if !registry.baits().iter().any(|bait| bait.id.0 == *bait_id) {
            return Err(ConfigError::new(format!(
                "content.surfaces references unknown bait id `{bait_id}`"
            )));
        }
    }

    Ok(())
}

fn validate_non_empty(label: &str, value: &str) -> Result<(), ConfigError> {
    if value.trim().is_empty() {
        Err(ConfigError::new(format!("{label} cannot be empty")))
    } else {
        Ok(())
    }
}

fn validate_optional_non_empty(label: &str, value: Option<&str>) -> Result<(), ConfigError> {
    if let Some(value) = value {
        validate_non_empty(label, value)?;
    }

    Ok(())
}

fn validate_path(label: &str, value: &str) -> Result<(), ConfigError> {
    validate_non_empty(label, value)?;
    if !value.starts_with('/') {
        return Err(ConfigError::new(format!("{label} must start with `/`")));
    }

    Ok(())
}

fn bait_profile_debug_value(metadata: &Option<BaitProfileMetadata>) -> Value {
    match metadata {
        Some(metadata) => json!({
            "profile_id": metadata.profile_id,
            "hypothesis": metadata.hypothesis,
        }),
        None => json!({
            "profile_id": "default_m3_catalog",
            "hypothesis": null,
        }),
    }
}

fn usage() -> String {
    format!(
        "\
Usage: eidolon-proxy [OPTIONS]

Options:
  --listen-addr <ADDR>  Loopback socket address to listen on [default: {DEFAULT_LISTEN_ADDR}]
  --upstream <URL>      Loopback HTTP upstream target URL [default: {DEFAULT_UPSTREAM}]
  --event-log <PATH>    JSONL event log file path [default: {DEFAULT_EVENT_LOG}]
  --debug-log <PATH>    Optional server-side JSONL debug log path. Records sanitized
                         internal decisions only; never emits debug data to HTTP clients
  --bait-profile <PATH> Lab-only JSON bait profile for M3 promotion experiments.
                         Defaults to the built-in M3 catalog
  --bait-signing-secret-file <PATH>
                         Shared-secret file used to mint and verify
                         session-bound bait header values for mint-enabled profiles
  --session-signing-key-file <PATH>
                         JSON session signing key ring. When omitted, sessions are
                         minted under an ephemeral key that changes on restart
  --ingress-trust-config <PATH>
                         JSON ingress trust config for local allowlists and trusted
                         automation claims
  --ingress-transport-auth-secret-file <PATH>
                         Shared-secret file required before explicit
                         X-Eidolon-Ingress-* identity headers are trusted
  --trusted-bait-soften-prefix <PATH_PREFIX>
                         Repeatable path prefix where strong trusted identities may
                         skip bait exposure surfaces [default: /docs, /openapi.json]
  --intervention-control <PATH>
                         Optional control file; write `disabled` to force protected forwarding
                         [default: {DEFAULT_INTERVENTION_CONTROL}]
  --policy-state <PATH> Per-session policy state JSON file path [default: {DEFAULT_POLICY_STATE}]
  --controlled-reality-max-depth <N>
                         Controlled-reality actions before rate limiting
                         [default: {MAX_CONTROLLED_REALITY_ACTION_DEPTH}]
  --controlled-reality-tarpit-ms <MS>
                         Lab-only delay before over-depth rate-limit responses
                         [default: {default_tarpit_ms}; max: {max_tarpit_ms}]
  --controlled-reality-retry-after-seconds <SECONDS>
                         Retry-After value for controlled-reality rate limits
                         [default: {DEFAULT_RETRY_AFTER_SECONDS}]
  --owned-cluster-lab   Allow non-loopback listen and upstream addresses for an
                         owned Kubernetes or cluster lab
  -h, --help            Show this help text

Example:
  cargo run -p eidolon-proxy -- --listen-addr 127.0.0.1:8080 --upstream http://127.0.0.1:9001 --event-log /tmp/eidolon-events.jsonl --debug-log /tmp/eidolon-debug.jsonl --intervention-control /tmp/eidolon-interventions.txt --policy-state /tmp/eidolon-policy-state.json --controlled-reality-max-depth 4 --controlled-reality-tarpit-ms {default_tarpit_ms} --controlled-reality-retry-after-seconds {DEFAULT_RETRY_AFTER_SECONDS}

Owned cluster lab:
  cargo run -p eidolon-proxy -- --owned-cluster-lab --listen-addr 0.0.0.0:9102 --upstream http://eidolon-demo-target.shield-targets.svc.cluster.local:9101 --event-log /tmp/eidolon-events.jsonl --intervention-control /tmp/eidolon-interventions.txt --policy-state /tmp/eidolon-policy-state.json
"
,
        default_tarpit_ms = DEFAULT_TARPIT_DELAY.as_millis(),
        max_tarpit_ms = MAX_TARPIT_DELAY.as_millis()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use eidolon_bait::{render_bait_for_session, render_bait_for_session_at};
    use eidolon_proxy::{
        ingress_identity, session,
        session_auth::SessionKeyVersion,
        surface::{
            HtmlInsertion, RewritePlan, SurfaceAction, SurfaceController, SurfaceHeader,
            SurfaceRequestMeta, SurfaceResponse,
        },
    };
    use std::{
        io::{Cursor, Read, Write},
        net::{Shutdown, TcpListener, TcpStream},
        thread::JoinHandle,
        time::{SystemTime, UNIX_EPOCH},
    };

    use eidolon_core::{
        Bait, BaitClass, BaitId, Event, EventKind, EventSource, ExpectedAction, ExposureId,
        PolicyState, RoutingDecision, SessionId, SurfaceKind, EVENT_SCHEMA_VERSION,
    };
    use serde_json::Value;

    #[derive(Clone)]
    struct StaticSurfaceController {
        action: SurfaceAction,
    }

    impl SurfaceController for StaticSurfaceController {
        fn decide(
            &self,
            _request: &SurfaceRequestMeta,
            _session_id: SessionId,
        ) -> io::Result<SurfaceAction> {
            Ok(self.action.clone())
        }
    }

    fn run_config(args: &[&str]) -> Result<ProxyConfig, ConfigError> {
        match CliAction::from_args(args.iter().copied())? {
            CliAction::Run(config) => Ok(*config),
            CliAction::Help => Err(ConfigError::new("expected runnable config")),
        }
    }

    fn assert_error_contains(args: &[&str], expected: &str) {
        let error = CliAction::from_args(args.iter().copied()).expect_err("config should fail");
        assert!(
            error.to_string().contains(expected),
            "expected `{}` to contain `{}`",
            error,
            expected
        );
    }

    fn must_ok<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("{context}: {error}"),
        }
    }

    fn must_join<T>(result: std::thread::Result<T>, context: &str) -> T {
        result.unwrap_or_else(|_| panic!("{context}"))
    }

    fn path_str<'a>(path: &'a Path, context: &str) -> &'a str {
        match path.to_str() {
            Some(value) => value,
            None => panic!("{context}"),
        }
    }

    fn parse_socket_addr(value: &str, context: &str) -> SocketAddr {
        match value.parse() {
            Ok(addr) => addr,
            Err(error) => panic!("{context}: {error}"),
        }
    }

    fn unique_temp_path(label: &str) -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

        let counter = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|error| panic!("system clock should be after epoch: {error}"))
            .as_nanos();

        env::temp_dir().join(format!(
            "eidolon-proxy-{label}-{}-{counter}-{nanos}",
            std::process::id()
        ))
    }

    fn write_bait_profile(contents: &str) -> PathBuf {
        let path = unique_temp_path("bait-profile.json");
        must_ok(fs::write(&path, contents), "bait profile should write");
        path
    }

    fn write_ingress_trust_config(contents: &str) -> PathBuf {
        let path = unique_temp_path("ingress-trust-config.json");
        must_ok(
            fs::write(&path, contents),
            "ingress trust config should write",
        );
        path
    }

    fn write_ingress_transport_auth_secret(contents: &str) -> PathBuf {
        let path = unique_temp_path("ingress-transport-auth-secret.txt");
        must_ok(
            fs::write(&path, contents),
            "ingress transport auth secret should write",
        );
        path
    }

    fn write_bait_signing_secret(contents: &str) -> PathBuf {
        let path = unique_temp_path("bait-signing-secret.txt");
        must_ok(
            fs::write(&path, contents),
            "bait signing secret should write",
        );
        path
    }

    fn test_runtime(
        upstream: UpstreamTarget,
        event_log_path: &Path,
        intervention_control_path: PathBuf,
        action: SurfaceAction,
    ) -> ProxyRuntime {
        test_runtime_with_surface_controller(
            upstream,
            event_log_path,
            intervention_control_path,
            Arc::new(StaticSurfaceController { action }),
        )
    }

    fn test_runtime_with_surface_controller(
        upstream: UpstreamTarget,
        event_log_path: &Path,
        intervention_control_path: PathBuf,
        surface_controller: Arc<dyn SurfaceController + Send + Sync>,
    ) -> ProxyRuntime {
        let bait_registry = Arc::new(BaitRegistry::m3_catalog());
        ProxyRuntime {
            upstream,
            event_log: Arc::new(Mutex::new(
                FileEventLogWriter::open(event_log_path).expect("event log should open"),
            )),
            debug_log: None,
            intervention_control_path,
            policy_store: Arc::new(Mutex::new(PolicyStateStore::in_memory())),
            session_authority: Arc::new(Mutex::new(test_session_authority())),
            controlled_reality_config: ControlledRealityConfig::default(),
            controlled_reality: Arc::new(ControlledRealityResponder),
            surface_controller,
            ingress_identity_resolver: Arc::new(IngressIdentityResolver::default()),
            ingress_transport_auth_secret: None,
            bait_signing_secret: None,
            trusted_bait_soften_path_prefixes: default_trusted_bait_soften_path_prefixes(),
            bait_registry,
            bait_content: BaitContentOverrides::default(),
            bait_exposures: Arc::new(Mutex::new(BaitExposureStore::default())),
            bait_action_replays: Arc::new(Mutex::new(BaitActionReplayStore::default())),
        }
    }

    fn test_runtime_with_m1_controller(
        upstream: UpstreamTarget,
        event_log_path: &Path,
        intervention_control_path: PathBuf,
    ) -> ProxyRuntime {
        test_runtime_with_m1_controller_and_bait_exposures(
            upstream,
            event_log_path,
            intervention_control_path,
            BaitExposureStore::default(),
        )
    }

    fn test_runtime_with_m1_controller_and_debug_log(
        upstream: UpstreamTarget,
        event_log_path: &Path,
        debug_log_path: &Path,
        intervention_control_path: PathBuf,
    ) -> ProxyRuntime {
        let bait_registry = Arc::new(BaitRegistry::m3_catalog());
        ProxyRuntime {
            upstream,
            event_log: Arc::new(Mutex::new(must_ok(
                FileEventLogWriter::open(event_log_path),
                "event log should open",
            ))),
            debug_log: Some(Arc::new(Mutex::new(must_ok(
                FileDebugLogWriter::open(debug_log_path),
                "debug log should open",
            )))),
            intervention_control_path,
            policy_store: Arc::new(Mutex::new(PolicyStateStore::in_memory())),
            session_authority: Arc::new(Mutex::new(test_session_authority())),
            controlled_reality_config: ControlledRealityConfig::default(),
            controlled_reality: Arc::new(ControlledRealityResponder),
            surface_controller: Arc::new(M1DemoSurfaceController::with_content_overrides(
                Arc::clone(&bait_registry),
                BaitContentOverrides::default(),
                None,
            )),
            ingress_identity_resolver: Arc::new(IngressIdentityResolver::default()),
            ingress_transport_auth_secret: None,
            bait_signing_secret: None,
            trusted_bait_soften_path_prefixes: default_trusted_bait_soften_path_prefixes(),
            bait_registry,
            bait_content: BaitContentOverrides::default(),
            bait_exposures: Arc::new(Mutex::new(BaitExposureStore::default())),
            bait_action_replays: Arc::new(Mutex::new(BaitActionReplayStore::default())),
        }
    }

    fn test_runtime_with_m1_controller_and_bait_exposures(
        upstream: UpstreamTarget,
        event_log_path: &Path,
        intervention_control_path: PathBuf,
        bait_exposures: BaitExposureStore,
    ) -> ProxyRuntime {
        let bait_registry = Arc::new(BaitRegistry::m3_catalog());
        ProxyRuntime {
            upstream,
            event_log: Arc::new(Mutex::new(
                FileEventLogWriter::open(event_log_path).expect("event log should open"),
            )),
            debug_log: None,
            intervention_control_path,
            policy_store: Arc::new(Mutex::new(PolicyStateStore::in_memory())),
            session_authority: Arc::new(Mutex::new(test_session_authority())),
            controlled_reality_config: ControlledRealityConfig::default(),
            controlled_reality: Arc::new(ControlledRealityResponder),
            surface_controller: Arc::new(M1DemoSurfaceController::with_content_overrides(
                Arc::clone(&bait_registry),
                BaitContentOverrides::default(),
                None,
            )),
            ingress_identity_resolver: Arc::new(IngressIdentityResolver::default()),
            ingress_transport_auth_secret: None,
            bait_signing_secret: None,
            trusted_bait_soften_path_prefixes: default_trusted_bait_soften_path_prefixes(),
            bait_registry,
            bait_content: BaitContentOverrides::default(),
            bait_exposures: Arc::new(Mutex::new(bait_exposures)),
            bait_action_replays: Arc::new(Mutex::new(BaitActionReplayStore::default())),
        }
    }

    fn test_runtime_with_bait_profile(
        upstream: UpstreamTarget,
        event_log_path: &Path,
        intervention_control_path: PathBuf,
        loaded_profile: LoadedBaitProfile,
        bait_signing_secret: Option<Arc<str>>,
    ) -> ProxyRuntime {
        let bait_registry = Arc::new(loaded_profile.registry);
        let bait_content = loaded_profile.content;
        ProxyRuntime {
            upstream,
            event_log: Arc::new(Mutex::new(
                FileEventLogWriter::open(event_log_path).expect("event log should open"),
            )),
            debug_log: None,
            intervention_control_path,
            policy_store: Arc::new(Mutex::new(PolicyStateStore::in_memory())),
            session_authority: Arc::new(Mutex::new(test_session_authority())),
            controlled_reality_config: ControlledRealityConfig::default(),
            controlled_reality: Arc::new(ControlledRealityResponder),
            surface_controller: Arc::new(M1DemoSurfaceController::with_content_overrides(
                Arc::clone(&bait_registry),
                bait_content.clone(),
                bait_signing_secret.clone(),
            )),
            ingress_identity_resolver: Arc::new(IngressIdentityResolver::default()),
            ingress_transport_auth_secret: None,
            bait_signing_secret,
            trusted_bait_soften_path_prefixes: default_trusted_bait_soften_path_prefixes(),
            bait_registry,
            bait_content,
            bait_exposures: Arc::new(Mutex::new(BaitExposureStore::default())),
            bait_action_replays: Arc::new(Mutex::new(BaitActionReplayStore::default())),
        }
    }

    fn promotion_profile_json() -> &'static str {
        r##"{
          "schema_version": 1,
          "profile_id": "openapi_promotion_probe",
          "hypothesis": "current pwnkit may promote an explicit external trust-boundary import operation to a finding",
          "content": {
            "docs_discovery_heading": "Customer import recovery controls",
            "openapi": {
              "summary": "Customer import reconciliation endpoint",
              "description": "Accepts customer-controlled import manifests and source URLs from the public import workflow. The legacy trace header is a compatibility gate only; possession of the value from an external client request is sufficient to enqueue tenant reconciliation.",
              "operation_id": "queueCustomerImportReconciliation",
              "tags": ["customer-imports", "legacy-reconciliation"],
              "response_status": "202",
              "response_description": "Customer import reconciliation request accepted",
              "request_body": {
                "required": true,
                "content": {
                  "application/json": {
                    "schema": {
                      "type": "object",
                      "required": ["source_url", "tenant_id"],
                      "properties": {
                        "source_url": {
                          "type": "string",
                          "format": "uri",
                          "description": "Customer-supplied import source URL fetched by the reconciliation worker."
                        },
                        "tenant_id": {
                          "type": "string",
                          "description": "Tenant identifier supplied by the caller."
                        }
                      }
                    }
                  }
                }
              }
            },
            "surfaces": {
              "rel_2025_04_b7f2": {
                "content_type": "text/markdown; charset=utf-8",
                "body": "# Variant Customer Import Notes\n\nCustomer-controlled import retries use `X-Migration-Trace: rel_2025_04_b7f2` with `POST /api/v2/import/reconcile`. The header is a compatibility gate only and can be sent by external clients.\n"
              }
            }
          }
        }"##
    }

    fn session_minted_profile_json() -> &'static str {
        r##"{
          "schema_version": 1,
          "profile_id": "session_minted_trace",
          "baits": [
            {
              "id": "minted_trace",
              "bait_class": "docs",
              "surface": "/docs/minted-trace",
              "surface_kind": "docs",
              "expected_action": {
                "method": "POST",
                "path": "/api/v2/import/reconcile",
                "header_name": "X-Migration-Trace",
                "header_value_mint": {
                  "kind": "session_hmac_sha256_v1",
                  "prefix": "minted"
                }
              }
            }
          ]
        }"##
    }

    fn session_windowed_minted_profile_json() -> &'static str {
        r##"{
          "schema_version": 1,
          "profile_id": "session_windowed_minted_trace",
          "baits": [
            {
              "id": "minted_trace",
              "bait_class": "docs",
              "surface": "/docs/minted-trace",
              "surface_kind": "docs",
              "expected_action": {
                "method": "POST",
                "path": "/api/v2/import/reconcile",
                "header_name": "X-Migration-Trace",
                "header_value_mint": {
                  "kind": "session_hmac_sha256_v1",
                  "prefix": "minted",
                  "proof_window_seconds": 60
                }
              }
            }
          ]
        }"##
    }

    fn alternate_write_probe_profile_json() -> &'static str {
        r##"{
          "schema_version": 1,
          "profile_id": "alternate_write_probe",
          "baits": [
            {
              "id": "validate_import_trace",
              "bait_class": "docs",
              "surface": "/docs/import-validate",
              "surface_kind": "docs",
              "expected_action": {
                "method": "POST",
                "path": "/api/v2/import/validate",
                "header_name": "X-Validation-Trace",
                "header_value": "validate_2026_06_a17c"
              }
            }
          ]
        }"##
    }

    fn fanout_write_probe_profile_json() -> &'static str {
        r##"{
          "schema_version": 1,
          "profile_id": "fanout_write_probe",
          "baits": [
            {
              "id": "legacy_import_trace",
              "bait_class": "docs",
              "surface": "/docs/legacy-import",
              "surface_kind": "docs",
              "expected_action": {
                "method": "POST",
                "path": "/api/v2/import/reconcile",
                "header_name": "X-Migration-Trace",
                "header_value": "rel_2025_04_b7f2"
              }
            },
            {
              "id": "validate_import_trace",
              "bait_class": "docs",
              "surface": "/docs/import-validate",
              "surface_kind": "docs",
              "expected_action": {
                "method": "POST",
                "path": "/api/v2/import/validate",
                "header_name": "X-Validation-Trace",
                "header_value": "validate_2026_06_a17c"
              }
            }
          ]
        }"##
    }

    fn session_id_from_cookie(cookie: &str) -> Option<SessionId> {
        let value = cookie.strip_prefix("eidolon_session=")?;
        let mut parts = value.split('.');
        parts.next()?;
        parts.next()?;
        parts.next()?;
        let uuid = uuid::Uuid::parse_str(parts.next()?).ok()?;
        Some(SessionId(uuid))
    }

    fn set_runtime_policy_state(runtime: &ProxyRuntime, cookie: &str, policy_state: PolicyState) {
        let session_id = session_id_from_cookie(cookie).expect("cookie should contain session");
        set_policy_state_for_session(runtime, session_id, policy_state)
            .expect("policy state should set");
    }

    fn spawn_upstream(response: impl Into<Vec<u8>>) -> (UpstreamTarget, JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("upstream should bind");
        let addr = listener.local_addr().expect("upstream should have address");
        let response = response.into();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("upstream should accept");
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];

            loop {
                let bytes_read = stream.read(&mut chunk).expect("upstream request read");
                if bytes_read == 0 {
                    break;
                }

                request.extend_from_slice(&chunk[..bytes_read]);
                if find_header_end(&request).is_some() {
                    break;
                }
            }

            stream
                .write_all(&response)
                .expect("upstream response should write");
            stream.flush().expect("upstream response should flush");
            request
        });
        let upstream = must_ok(
            parse_upstream(&format!("http://{addr}"), false),
            "upstream target should parse",
        );

        (upstream, handle)
    }

    fn spawn_upstream_sequence(
        responses: impl IntoIterator<Item = Vec<u8>>,
    ) -> (UpstreamTarget, JoinHandle<Vec<Vec<u8>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("upstream should bind");
        let addr = listener.local_addr().expect("upstream should have address");
        let responses: Vec<Vec<u8>> = responses.into_iter().collect();
        let handle = thread::spawn(move || {
            let mut requests = Vec::with_capacity(responses.len());

            for response in responses {
                let (mut stream, _) = listener.accept().expect("upstream should accept");
                let mut request = Vec::new();
                let mut chunk = [0_u8; 1024];

                loop {
                    let bytes_read = stream.read(&mut chunk).expect("upstream request read");
                    if bytes_read == 0 {
                        break;
                    }

                    request.extend_from_slice(&chunk[..bytes_read]);
                    if find_header_end(&request).is_some() {
                        break;
                    }
                }

                stream
                    .write_all(&response)
                    .expect("upstream response should write");
                stream.flush().expect("upstream response should flush");
                requests.push(request);
            }

            requests
        });
        let upstream = must_ok(
            parse_upstream(&format!("http://{addr}"), false),
            "upstream target should parse",
        );

        (upstream, handle)
    }

    const TEST_SESSION_KEY: [u8; 32] = [0x5a; 32];

    fn test_session_authority() -> SessionAuthority {
        SessionAuthority::new(
            vec![SessionKeyVersion {
                version: 1,
                key: TEST_SESSION_KEY,
            }],
            1,
        )
        .expect("test session authority should build")
    }

    fn now_unix_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or_default()
    }

    fn minted_cookie_value(session_id: SessionId) -> String {
        test_session_authority().mint_cookie_value(session_id, now_unix_secs())
    }

    fn closed_upstream() -> UpstreamTarget {
        let listener = TcpListener::bind("127.0.0.1:0").expect("upstream should bind");
        let addr = listener.local_addr().expect("upstream should have address");
        drop(listener);

        must_ok(
            parse_upstream(&format!("http://{addr}"), false),
            "upstream target should parse",
        )
    }

    fn run_runtime_request(runtime: ProxyRuntime, request: &[u8]) -> Vec<u8> {
        let listener = TcpListener::bind("127.0.0.1:0").expect("proxy should bind");
        let addr = listener.local_addr().expect("proxy should have address");
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("proxy should accept");
            handle_connection(stream, &runtime).expect("runtime should handle request");
        });

        let mut client = TcpStream::connect(addr).expect("client should connect");
        client.write_all(request).expect("request should write");
        client
            .shutdown(Shutdown::Write)
            .expect("client write side should close");

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .expect("response should read");
        handle.join().expect("proxy thread should join");

        response
    }

    fn run_runtime_request_result(
        runtime: ProxyRuntime,
        request: &[u8],
    ) -> (io::Result<()>, Vec<u8>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("proxy should bind");
        let addr = listener.local_addr().expect("proxy should have address");
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("proxy should accept");
            handle_connection(stream, &runtime)
        });

        let mut client = TcpStream::connect(addr).expect("client should connect");
        client.write_all(request).expect("request should write");
        client
            .shutdown(Shutdown::Write)
            .expect("client write side should close");

        let mut response = Vec::new();
        let _ = client.read_to_end(&mut response);
        let result = handle.join().expect("proxy thread should join");

        (result, response)
    }

    fn parse_downstream_response(response: &[u8]) -> HttpResponse {
        read_http_response(&mut &response[..]).expect("downstream response should parse")
    }

    fn cookie_header() -> String {
        format!("eidolon_session={}", minted_cookie_value(SessionId::new()))
    }

    fn request_with_cookie(
        method: &str,
        path: &str,
        cookie: &str,
        headers: &[(&str, &str)],
    ) -> Vec<u8> {
        let mut request =
            format!("{method} {path} HTTP/1.1\r\nHost: proxy.local\r\nCookie: {cookie}\r\n");
        for (name, value) in headers {
            request.push_str(name);
            request.push_str(": ");
            request.push_str(value);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        request.into_bytes()
    }

    fn get_request(path: &str) -> Vec<u8> {
        request_with_cookie("GET", path, &cookie_header(), &[])
    }

    fn get_request_with_cookie(path: &str, cookie: &str) -> Vec<u8> {
        request_with_cookie("GET", path, cookie, &[])
    }

    fn post_request_with_cookie(path: &str, cookie: &str, headers: &[(&str, &str)]) -> Vec<u8> {
        request_with_cookie("POST", path, cookie, headers)
    }

    fn html_response(body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )
        .into_bytes()
    }

    fn html_response_with_status(status: u16, reason: &str, body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )
        .into_bytes()
    }

    fn json_response(body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )
        .into_bytes()
    }

    fn html_rewrite_action(snippet: &str) -> SurfaceAction {
        SurfaceAction::RewrittenUpstream {
            plan: RewritePlan::html(HtmlInsertion::new(snippet)),
        }
    }

    fn event_values(path: &Path) -> Vec<Value> {
        fs::read_to_string(path)
            .expect("event log should read")
            .lines()
            .map(|line| serde_json::from_str(line).expect("event line should be json"))
            .collect()
    }

    fn debug_values(path: &Path) -> Vec<Value> {
        fs::read_to_string(path)
            .expect("debug log should read")
            .lines()
            .map(|line| serde_json::from_str(line).expect("debug line should be json"))
            .collect()
    }

    fn first_debug_event(path: &Path, event_type: &str) -> Value {
        debug_values(path)
            .into_iter()
            .find(|event| event["event"].as_str() == Some(event_type))
            .unwrap_or_else(|| panic!("missing debug event `{event_type}`"))
    }

    fn debug_events(path: &Path, event_type: &str) -> Vec<Value> {
        debug_values(path)
            .into_iter()
            .filter(|event| event["event"].as_str() == Some(event_type))
            .collect()
    }

    fn events_of_type(path: &Path, event_type: &str) -> Vec<Value> {
        event_values(path)
            .into_iter()
            .filter(|event| event["kind"]["type"].as_str() == Some(event_type))
            .collect()
    }

    fn first_event_of_type(path: &Path, event_type: &str) -> Value {
        events_of_type(path, event_type)
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("{event_type} event should exist"))
    }

    fn assert_event_routing(path: &Path, event_type: &str, expected: &str) {
        let events = event_values(path);
        let event = events
            .iter()
            .find(|event| event["kind"]["type"].as_str() == Some(event_type))
            .expect("event should exist");

        assert_eq!(event["kind"]["routing_decision"].as_str(), Some(expected));
    }

    fn assert_event_type_absent(path: &Path, event_type: &str) {
        let events = event_values(path);

        assert!(
            events
                .iter()
                .all(|event| event["kind"]["type"].as_str() != Some(event_type)),
            "did not expect {event_type} in {events:#?}"
        );
    }

    fn assert_policy_decision_reason_contains(path: &Path, expected: &str) {
        let events = event_values(path);
        let event = events
            .iter()
            .find(|event| event["kind"]["type"].as_str() == Some("policy_decision"))
            .expect("policy decision event should exist");

        assert_eq!(
            event["kind"]["routing_decision"].as_str(),
            Some("protected_upstream")
        );
        assert!(
            event["kind"]["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains(expected)),
            "expected policy decision reason to contain `{expected}`, got {event:#?}"
        );
    }

    fn header_values<'a>(response: &'a HttpResponse, name: &str) -> Vec<&'a str> {
        response
            .headers
            .iter()
            .filter(|header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value.as_str())
            .collect()
    }

    #[test]
    fn defaults_match_local_lab_shape() {
        let config = run_config(&[]).expect("default config should parse");

        assert_eq!(
            config.listen_addr,
            DEFAULT_LISTEN_ADDR.parse::<SocketAddr>().unwrap()
        );
        assert_eq!(config.upstream.to_string(), DEFAULT_UPSTREAM);
        assert_eq!(config.event_log_path, PathBuf::from(DEFAULT_EVENT_LOG));
        assert_eq!(config.debug_log_path, None);
        assert_eq!(config.bait_profile_path, None);
        assert_eq!(config.bait_signing_secret_path, None);
        assert_eq!(config.ingress_trust_config_path, None);
        assert_eq!(config.ingress_transport_auth_secret_path, None);
        assert_eq!(
            config.trusted_bait_soften_path_prefixes,
            default_trusted_bait_soften_path_prefixes()
        );
        assert_eq!(
            config.intervention_control_path,
            PathBuf::from(DEFAULT_INTERVENTION_CONTROL)
        );
        assert_eq!(
            config.policy_state_path,
            PathBuf::from(DEFAULT_POLICY_STATE)
        );
        assert_eq!(
            config.controlled_reality_config,
            ControlledRealityConfig::default()
        );
        assert!(!config.owned_cluster_lab);
    }

    #[test]
    fn parses_explicit_flags() {
        let bait_profile_path = unique_temp_path("bait-profile.json");
        let bait_signing_secret_path = write_bait_signing_secret("mint-secret");
        let ingress_trust_config_path = unique_temp_path("ingress-trust-config.json");
        let ingress_transport_auth_secret_path = write_ingress_transport_auth_secret("edge-secret");
        must_ok(
            fs::write(&bait_profile_path, "{}"),
            "bait profile placeholder should write",
        );
        must_ok(
            fs::write(&ingress_trust_config_path, "{}"),
            "ingress trust config placeholder should write",
        );

        let config = run_config(&[
            "--listen-addr",
            "127.0.0.1:8181",
            "--upstream",
            "http://localhost:9101/",
            "--event-log",
            "/tmp/eidolon-proxy-test.jsonl",
            "--debug-log",
            "/tmp/eidolon-debug-test.jsonl",
            "--bait-profile",
            path_str(&bait_profile_path, "bait profile path should be utf8"),
            "--bait-signing-secret-file",
            path_str(
                &bait_signing_secret_path,
                "bait signing secret path should be utf8",
            ),
            "--ingress-trust-config",
            path_str(
                &ingress_trust_config_path,
                "ingress trust config path should be utf8",
            ),
            "--ingress-transport-auth-secret-file",
            path_str(
                &ingress_transport_auth_secret_path,
                "transport auth secret path should be utf8",
            ),
            "--trusted-bait-soften-prefix",
            "/customer",
            "--trusted-bait-soften-prefix",
            "/assets",
            "--intervention-control",
            "/tmp/eidolon-interventions-test.txt",
            "--policy-state",
            "/tmp/eidolon-policy-state-test.json",
            "--controlled-reality-max-depth",
            "2",
            "--controlled-reality-tarpit-ms",
            "5",
            "--controlled-reality-retry-after-seconds",
            "9",
        ]);
        let config = must_ok(config, "explicit config should parse");

        assert_eq!(
            config.listen_addr,
            parse_socket_addr("127.0.0.1:8181", "listen addr should parse")
        );
        assert_eq!(config.upstream.to_string(), "http://localhost:9101");
        assert_eq!(config.upstream.authority, "localhost:9101");
        assert_eq!(config.upstream.connect_addr, "localhost:9101");
        assert_eq!(
            config.event_log_path,
            PathBuf::from("/tmp/eidolon-proxy-test.jsonl")
        );
        assert_eq!(
            config.debug_log_path,
            Some(PathBuf::from("/tmp/eidolon-debug-test.jsonl"))
        );
        assert_eq!(config.bait_profile_path, Some(bait_profile_path));
        assert_eq!(
            config.bait_signing_secret_path,
            Some(bait_signing_secret_path)
        );
        assert_eq!(
            config.ingress_trust_config_path,
            Some(ingress_trust_config_path)
        );
        assert_eq!(
            config.ingress_transport_auth_secret_path,
            Some(ingress_transport_auth_secret_path)
        );
        assert_eq!(
            config.trusted_bait_soften_path_prefixes,
            vec!["/customer".to_string(), "/assets".to_string()]
        );
        assert_eq!(
            config.intervention_control_path,
            PathBuf::from("/tmp/eidolon-interventions-test.txt")
        );
        assert_eq!(
            config.policy_state_path,
            PathBuf::from("/tmp/eidolon-policy-state-test.json")
        );
        assert_eq!(
            config.controlled_reality_config,
            ControlledRealityConfig {
                max_action_depth: 2,
                tarpit_delay: Duration::from_millis(5),
                retry_after_seconds: 9,
            }
        );
        assert!(!config.owned_cluster_lab);
    }

    #[test]
    fn parses_equals_syntax_and_ipv6_loopback() {
        let config = run_config(&[
            "--listen-addr=[::1]:8081",
            "--upstream=http://[::1]:9001",
            "--event-log=/tmp/eidolon-ipv6-events.jsonl",
        ])
        .expect("equals syntax should parse");

        assert_eq!(config.listen_addr, "[::1]:8081".parse().unwrap());
        assert_eq!(config.upstream.to_string(), "http://[::1]:9001");
        assert_eq!(config.upstream.authority, "[::1]:9001");
        assert_eq!(config.upstream.connect_addr, "[::1]:9001");
    }

    #[test]
    fn upstream_without_port_uses_default_http_connect_port() {
        let config =
            run_config(&["--upstream", "http://127.0.0.1"]).expect("upstream should parse");

        assert_eq!(config.upstream.to_string(), "http://127.0.0.1");
        assert_eq!(config.upstream.authority, "127.0.0.1");
        assert_eq!(config.upstream.connect_addr, "127.0.0.1:80");
    }

    #[test]
    fn stream_timeout_helpers_set_client_and_upstream_deadlines() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let addr = listener.local_addr().expect("listener should have address");
        let client = TcpStream::connect(addr).expect("client should connect");
        let (server, _) = listener.accept().expect("listener should accept");

        configure_client_stream(&server).expect("client stream deadlines should set");
        configure_upstream_stream(&client).expect("upstream stream deadlines should set");

        assert_eq!(server.read_timeout().unwrap(), Some(CLIENT_IO_TIMEOUT));
        assert_eq!(server.write_timeout().unwrap(), Some(CLIENT_IO_TIMEOUT));
        assert_eq!(client.read_timeout().unwrap(), Some(UPSTREAM_IO_TIMEOUT));
        assert_eq!(client.write_timeout().unwrap(), Some(UPSTREAM_IO_TIMEOUT));
    }

    #[test]
    fn connect_upstream_returns_stream_with_deadlines() {
        let listener = must_ok(TcpListener::bind("127.0.0.1:0"), "upstream should bind");
        let addr = must_ok(listener.local_addr(), "upstream should have address");
        let upstream = must_ok(
            parse_upstream(&format!("http://{addr}"), false),
            "upstream target should parse",
        );
        let handle = thread::spawn(move || must_ok(listener.accept(), "upstream should accept").0);

        let stream = must_ok(connect_upstream(&upstream), "upstream should connect");
        let accepted = must_join(handle.join(), "upstream accept should join");

        assert_eq!(stream.read_timeout().unwrap(), Some(UPSTREAM_IO_TIMEOUT));
        assert_eq!(stream.write_timeout().unwrap(), Some(UPSTREAM_IO_TIMEOUT));
        drop(accepted);
    }

    #[test]
    fn connection_limiter_allows_exact_capacity_and_releases_on_drop() {
        let limiter = ConnectionLimiter::new(2);
        let first = limiter.try_acquire().expect("first permit should acquire");
        let second = limiter.try_acquire().expect("second permit should acquire");

        assert_eq!(limiter.active_for_test(), 2);
        assert!(limiter.try_acquire().is_none());

        drop(first);

        let third = limiter
            .try_acquire()
            .expect("capacity should return after drop");
        assert_eq!(limiter.active_for_test(), 2);

        drop(second);
        drop(third);
        assert_eq!(limiter.active_for_test(), 0);
    }

    #[test]
    fn connection_limiter_releases_when_worker_panics() {
        let limiter = ConnectionLimiter::new(1);
        let worker_limiter = limiter.clone();
        let handle = thread::spawn(move || {
            let _permit = worker_limiter
                .try_acquire()
                .expect("worker permit should acquire");
            panic!("simulated worker panic");
        });

        assert!(handle.join().is_err());
        assert_eq!(limiter.active_for_test(), 0);
        assert!(limiter.try_acquire().is_some());
    }

    #[test]
    #[should_panic(expected = "connection limit must be positive")]
    fn connection_limiter_rejects_zero_limit() {
        let _ = ConnectionLimiter::new(0);
    }

    #[test]
    fn help_short_circuits_config_validation() {
        assert_eq!(
            CliAction::from_args(["--help", "--listen-addr", "0.0.0.0:8080"]),
            Ok(CliAction::Help)
        );
        assert_eq!(
            CliAction::from_args(["-h", "--listen-addr", "0.0.0.0:8080"]),
            Ok(CliAction::Help)
        );
    }

    #[test]
    fn rejects_unknown_or_duplicate_flags() {
        assert_error_contains(&["--wat"], "unknown option");
        assert_error_contains(
            &[
                "--listen-addr",
                "127.0.0.1:8080",
                "--listen-addr",
                "127.0.0.1:8081",
            ],
            "duplicate option",
        );
    }

    #[test]
    fn rejects_missing_values() {
        assert_error_contains(&["--listen-addr"], "missing value");
        assert_error_contains(&["--listen-addr", "--upstream"], "missing value");
    }

    #[test]
    fn rejects_invalid_controlled_reality_numeric_options() {
        assert_error_contains(
            &["--controlled-reality-max-depth", "nope"],
            "non-negative integer",
        );
        assert_error_contains(
            &["--controlled-reality-tarpit-ms", "nope"],
            "non-negative integer",
        );
        let too_large_tarpit = (MAX_TARPIT_DELAY.as_millis() + 1).to_string();
        assert_error_contains(
            &["--controlled-reality-tarpit-ms", &too_large_tarpit],
            "must be at most",
        );
        assert_error_contains(
            &["--controlled-reality-retry-after-seconds", "nope"],
            "non-negative integer",
        );
    }

    #[test]
    fn rejects_non_loopback_listen_addresses() {
        assert_error_contains(&["--listen-addr", "0.0.0.0:8080"], "loopback");
        assert_error_contains(&["--listen-addr", "127.0.0.1:0"], "port must not be 0");
    }

    #[test]
    fn rejects_non_loopback_or_malformed_upstreams() {
        assert_error_contains(
            &["--upstream", "https://127.0.0.1:9001"],
            "http loopback URL",
        );
        assert_error_contains(&["--upstream", "http://example.com:9001"], "loopback");
        assert_error_contains(
            &["--upstream", "http://127.0.0.1:9001/base"],
            "must not include a path",
        );
        assert_error_contains(&["--upstream", "http://127.0.0.1:0"], "port must not be 0");
    }

    #[test]
    fn owned_cluster_lab_allows_non_loopback_addresses() {
        let config = run_config(&[
            "--owned-cluster-lab",
            "--listen-addr",
            "0.0.0.0:9102",
            "--upstream",
            "http://eidolon-demo-target.shield-targets.svc.cluster.local:9101",
        ]);
        let config = must_ok(config, "owned cluster lab config should parse");

        assert!(config.owned_cluster_lab);
        assert_eq!(
            config.listen_addr,
            parse_socket_addr("0.0.0.0:9102", "listen addr should parse")
        );
        assert_eq!(
            config.upstream.to_string(),
            "http://eidolon-demo-target.shield-targets.svc.cluster.local:9101"
        );
    }

    #[test]
    fn rejects_invalid_event_log_paths() {
        assert_error_contains(&["--event-log", ""], "cannot be empty");
        assert_error_contains(&["--event-log", "/tmp"], "must be a file path");
        assert_error_contains(&["--debug-log", ""], "cannot be empty");
        assert_error_contains(&["--debug-log", "/tmp"], "must be a file path");
        assert_error_contains(&["--bait-profile", ""], "cannot be empty");
        assert_error_contains(&["--bait-profile", "/tmp"], "must be a file path");
        assert_error_contains(&["--ingress-trust-config", ""], "cannot be empty");
        assert_error_contains(&["--ingress-trust-config", "/tmp"], "must be a file path");
        assert_error_contains(
            &["--trusted-bait-soften-prefix", ""],
            "trusted bait soften prefix cannot be empty",
        );
        assert_error_contains(
            &["--trusted-bait-soften-prefix", "docs"],
            "must start with `/`",
        );
        assert_error_contains(
            &[
                "--trusted-bait-soften-prefix",
                "/docs",
                "--trusted-bait-soften-prefix",
                "/docs",
            ],
            "duplicate option `--trusted-bait-soften-prefix`",
        );
        assert_error_contains(
            &[
                "--ingress-trust-config",
                "/tmp/eidolon-missing-ingress-trust.json",
            ],
            "must be an existing file",
        );

        let missing_parent =
            env::temp_dir().join(format!("eidolon-missing-parent-{}", std::process::id()));
        let missing_path = missing_parent.join("events.jsonl");
        assert_error_contains(
            &["--event-log", missing_path.to_str().unwrap()],
            "parent directory does not exist",
        );
        let missing_debug_path = missing_parent.join("debug.jsonl");
        assert_error_contains(
            &["--debug-log", missing_debug_path.to_str().unwrap()],
            "parent directory does not exist",
        );
        let missing_profile_path = missing_parent.join("bait-profile.json");
        assert_error_contains(
            &["--bait-profile", missing_profile_path.to_str().unwrap()],
            "parent directory does not exist",
        );

        let missing_profile_file = unique_temp_path("missing-bait-profile.json");
        assert_error_contains(
            &["--bait-profile", missing_profile_file.to_str().unwrap()],
            "must be an existing file",
        );
    }

    #[test]
    fn parses_intervention_control_path() {
        let config = run_config(&["--intervention-control", "/tmp/eidolon-control.txt"])
            .expect("control path should parse");

        assert_eq!(
            config.intervention_control_path,
            PathBuf::from("/tmp/eidolon-control.txt")
        );
    }

    #[test]
    fn loads_bait_profile_content_overrides_against_default_catalog() {
        let path = write_bait_profile(promotion_profile_json());
        let loaded = load_bait_profile(&path).expect("bait profile should load");

        assert_eq!(
            loaded
                .metadata
                .as_ref()
                .map(|metadata| metadata.profile_id.as_str()),
            Some("openapi_promotion_probe")
        );
        assert_eq!(
            loaded
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.hypothesis.as_deref()),
            Some("current pwnkit may promote an explicit external trust-boundary import operation to a finding")
        );
        assert_eq!(
            loaded.registry.baits().len(),
            BaitRegistry::m3_catalog().baits().len()
        );
        assert_eq!(
            loaded.content.docs_discovery_heading.as_deref(),
            Some("Customer import recovery controls")
        );
        assert_eq!(
            loaded.content.openapi.summary.as_deref(),
            Some("Customer import reconciliation endpoint")
        );
        assert!(loaded.content.surfaces.contains_key("rel_2025_04_b7f2"));
    }

    #[test]
    fn committed_openapi_promotion_profile_loads() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/m3/bait-profiles/openapi-promotion-probe.json");
        let loaded = load_bait_profile(&path).expect("committed profile should load");

        assert_eq!(
            loaded
                .metadata
                .as_ref()
                .map(|metadata| metadata.profile_id.as_str()),
            Some("openapi_promotion_probe")
        );
        assert!(loaded
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.hypothesis.as_deref())
            .is_some_and(|hypothesis| hypothesis.contains("external trust-boundary")));
        assert_eq!(
            loaded.content.openapi.operation_id.as_deref(),
            Some("queueCustomerImportReconciliation")
        );
    }

    #[test]
    fn committed_orbstack_default_profile_enables_session_minted_docs_token_and_openapi_baits() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/shield-lab/bait-profiles/default-m3-catalog.json");
        let loaded = load_bait_profile(&path).expect("committed shield-lab profile should load");
        let docs_bait = loaded
            .registry
            .bait_for_class(BaitClass::Docs)
            .expect("docs bait should exist");
        let openapi_bait = loaded
            .registry
            .bait_for_class(BaitClass::OpenApi)
            .expect("OpenAPI bait should exist");
        let fake_service_token = loaded
            .registry
            .bait_for_class(BaitClass::FakeCredentialToken)
            .expect("fake service token bait should exist");

        assert_eq!(
            loaded
                .metadata
                .as_ref()
                .map(|metadata| metadata.profile_id.as_str()),
            Some("orbstack_default_m3_catalog")
        );
        assert_eq!(
            loaded.registry.baits().len(),
            BaitRegistry::m3_catalog().baits().len()
        );
        assert_eq!(docs_bait.surface, "/docs/legacy-import");
        assert_eq!(
            docs_bait.expected_action.header_name.as_deref(),
            Some("X-Migration-Trace")
        );
        assert!(docs_bait.expected_action.header_value.is_none());
        assert_eq!(
            docs_bait
                .expected_action
                .header_value_mint
                .as_ref()
                .map(|mint| mint.prefix.as_str()),
            Some("mig")
        );
        assert_eq!(fake_service_token.surface, "/docs/service-token");
        assert_eq!(
            fake_service_token.expected_action.header_name.as_deref(),
            Some("X-Api-Key")
        );
        assert!(fake_service_token.expected_action.header_value.is_none());
        assert_eq!(
            fake_service_token
                .expected_action
                .header_value_mint
                .as_ref()
                .map(|mint| mint.prefix.as_str()),
            Some("svc")
        );
        assert_eq!(openapi_bait.surface, "/openapi.json");
        assert_eq!(
            openapi_bait.expected_action.header_name.as_deref(),
            Some("X-OpenAPI-Trace")
        );
        assert!(openapi_bait.expected_action.header_value.is_none());
        assert_eq!(
            openapi_bait
                .expected_action
                .header_value_mint
                .as_ref()
                .map(|mint| mint.prefix.as_str()),
            Some("oapi")
        );
    }

    #[test]
    fn bait_profile_rejects_surface_override_for_unknown_bait() {
        let path = write_bait_profile(
            r#"{
              "schema_version": 1,
              "profile_id": "bad_surface_override",
              "content": {
                "surfaces": {
                  "unknown_bait": {
                    "body": "not linked to a configured bait"
                  }
                }
              }
            }"#,
        );

        let error = load_bait_profile(&path).expect_err("unknown surface override should fail");
        assert!(error
            .to_string()
            .contains("content.surfaces references unknown bait id"));
    }

    #[test]
    fn bait_profile_rejects_empty_optional_hypothesis() {
        let path = write_bait_profile(
            r#"{
              "schema_version": 1,
              "profile_id": "empty_hypothesis",
              "hypothesis": ""
            }"#,
        );

        let error = load_bait_profile(&path).expect_err("empty hypothesis should fail");
        assert!(error.to_string().contains("hypothesis cannot be empty"));
    }

    #[test]
    fn bait_profile_rejects_empty_baits_array() {
        let path = write_bait_profile(
            r#"{
              "schema_version": 1,
              "profile_id": "empty_baits",
              "baits": []
            }"#,
        );

        let error = load_bait_profile(&path).expect_err("empty baits array should fail");
        assert!(error
            .to_string()
            .contains("bait profile baits must not be empty"));
    }

    #[test]
    fn bait_profile_rejects_zero_proof_window() {
        let path = write_bait_profile(
            r##"{
              "schema_version": 1,
              "profile_id": "zero_proof_window",
              "baits": [
                {
                  "id": "minted_trace",
                  "bait_class": "docs",
                  "surface": "/docs/minted-trace",
                  "surface_kind": "docs",
                  "expected_action": {
                    "method": "POST",
                    "path": "/api/v2/import/reconcile",
                    "header_name": "X-Migration-Trace",
                    "header_value_mint": {
                      "kind": "session_hmac_sha256_v1",
                      "prefix": "minted",
                      "proof_window_seconds": 0
                    }
                  }
                }
              ]
            }"##,
        );

        let error = load_bait_profile(&path).expect_err("zero proof window should fail");
        assert!(error
            .to_string()
            .contains("proof_window_seconds must be greater than zero"));
    }

    #[test]
    fn bait_profile_rejects_header_value_without_header_name() {
        let path = write_bait_profile(
            r#"{
              "schema_version": 1,
              "profile_id": "value_without_name",
              "baits": [
                {
                  "id": "bad_value",
                  "bait_class": "docs",
                  "surface": "/docs/bad-value",
                  "surface_kind": "docs",
                  "expected_action": {
                    "method": "POST",
                    "path": "/api/v2/import/reconcile",
                    "header_value": "orphan_value"
                  }
                }
              ]
            }"#,
        );

        let error = load_bait_profile(&path).expect_err("header value without name should fail");
        assert!(error
            .to_string()
            .contains("cannot require a header value without naming the header"));
    }

    #[test]
    fn bait_profile_rejects_header_mint_without_header_name() {
        let path = write_bait_profile(
            r##"{
              "schema_version": 1,
              "profile_id": "mint_without_name",
              "baits": [
                {
                  "id": "bad_mint",
                  "bait_class": "docs",
                  "surface": "/docs/bad-mint",
                  "surface_kind": "docs",
                  "expected_action": {
                    "method": "POST",
                    "path": "/api/v2/import/reconcile",
                    "header_value_mint": {
                      "kind": "session_hmac_sha256_v1",
                      "prefix": "minted"
                    }
                  }
                }
              ]
            }"##,
        );

        let error = load_bait_profile(&path).expect_err("header mint without name should fail");
        assert!(error
            .to_string()
            .contains("cannot require a minted header value without naming the header"));
    }

    #[test]
    fn bait_profile_allows_same_action_with_distinct_header_constraints() {
        let path = write_bait_profile(
            r#"{
              "schema_version": 1,
              "profile_id": "distinct_header_actions",
              "baits": [
                {
                  "id": "trace_one",
                  "bait_class": "docs",
                  "surface": "/docs/trace-one",
                  "surface_kind": "docs",
                  "expected_action": {
                    "method": "POST",
                    "path": "/api/v2/import/reconcile",
                    "header_name": "X-Migration-Trace",
                    "header_value": "trace-one"
                  }
                },
                {
                  "id": "trace_two",
                  "bait_class": "docs",
                  "surface": "/docs/trace-two",
                  "surface_kind": "docs",
                  "expected_action": {
                    "method": "POST",
                    "path": "/api/v2/import/reconcile",
                    "header_name": "X-Migration-Trace",
                    "header_value": "trace-two"
                  }
                }
              ]
            }"#,
        );

        let loaded = load_bait_profile(&path).expect("profile should load");

        assert_eq!(loaded.registry.baits().len(), 2);
    }

    #[test]
    fn bait_profile_rejects_duplicate_constrained_action() {
        let path = write_bait_profile(
            r#"{
              "schema_version": 1,
              "profile_id": "duplicate_header_actions",
              "baits": [
                {
                  "id": "trace_one",
                  "bait_class": "docs",
                  "surface": "/docs/trace-one",
                  "surface_kind": "docs",
                  "expected_action": {
                    "method": "POST",
                    "path": "/api/v2/import/reconcile",
                    "header_name": "X-Migration-Trace",
                    "header_value": "trace-one"
                  }
                },
                {
                  "id": "trace_two",
                  "bait_class": "docs",
                  "surface": "/docs/trace-two",
                  "surface_kind": "docs",
                  "expected_action": {
                    "method": "post",
                    "path": "/api/v2/import/reconcile",
                    "header_name": "x-migration-trace",
                    "header_value": " trace-one "
                  }
                }
              ]
            }"#,
        );

        let error = load_bait_profile(&path).expect_err("duplicate action should fail");

        assert!(error.to_string().contains("duplicate bait action"));
    }

    #[test]
    fn bait_profile_rejects_static_and_minted_header_value_combination() {
        let path = write_bait_profile(
            r#"{
              "schema_version": 1,
              "profile_id": "invalid_minted_header_value",
              "baits": [
                {
                  "id": "minted_trace",
                  "bait_class": "docs",
                  "surface": "/docs/minted-trace",
                  "surface_kind": "docs",
                  "expected_action": {
                    "method": "POST",
                    "path": "/api/v2/import/reconcile",
                    "header_name": "X-Migration-Trace",
                    "header_value": "static-trace",
                    "header_value_mint": {
                      "kind": "session_hmac_sha256_v1",
                      "prefix": "minted"
                    }
                  }
                }
              ]
            }"#,
        );

        let error = load_bait_profile(&path)
            .expect_err("static and minted header values should be mutually exclusive");

        assert!(error
            .to_string()
            .contains("cannot set both a static header value and a minted header value"));
    }

    #[test]
    fn minted_bait_profile_requires_signing_secret() {
        let path = write_bait_profile(session_minted_profile_json());
        let loaded = load_bait_profile(&path).expect("minted profile should load");

        assert!(bait_profile_requires_signing_secret(&loaded));
    }

    #[test]
    fn javascript_bait_uses_json_escaped_values() {
        let bait = Bait {
            id: BaitId("js_escape".to_string()),
            bait_class: BaitClass::JsDiscoveredRoute,
            surface: "/assets/import-helper.js".to_string(),
            surface_kind: SurfaceKind::Route,
            expected_action: ExpectedAction {
                method: "POST".to_string(),
                path: "/api/v2/import/\"resume\\next".to_string(),
                header_name: Some("X-Trace\"Name".to_string()),
                header_value: Some("line\\one\nline\"two".to_string()),
                header_value_mint: None,
            },
        };

        let javascript = javascript_for_bait(&bait);
        let payload = javascript
            .strip_prefix("window.__eidolonImportWorker = ")
            .and_then(|value| value.strip_suffix(";\n"))
            .expect("javascript assignment should wrap JSON");
        let value: Value = serde_json::from_str(payload).expect("payload should parse as JSON");

        assert_eq!(value["resumeEndpoint"], "/api/v2/import/\"resume\\next");
        assert_eq!(value["method"], "POST");
        assert_eq!(value["headerName"], "X-Trace\"Name");
        assert_eq!(value["headerValue"], "line\\one\nline\"two");
        assert_eq!(value["inputOrigin"], "external_customer_request");
        assert_eq!(
            value["trustBoundary"],
            "browser_upload_to_import_reconcile_api"
        );
        assert_eq!(value["authorizationModel"], "legacy_header_only");
        assert_eq!(javascript.matches('\n').count(), 1);
        assert!(javascript.contains("\\\""));
        assert!(javascript.contains("\\\\"));
        assert!(javascript.contains("\\n"));
    }

    #[test]
    fn runtime_bait_profile_customizes_surface_content_and_openapi_rewrite() {
        let path = write_bait_profile(promotion_profile_json());
        let loaded = load_bait_profile(&path).expect("bait profile should load");
        let event_log_path = unique_temp_path("profile-surface-events.jsonl");
        let runtime = test_runtime_with_bait_profile(
            closed_upstream(),
            &event_log_path,
            unique_temp_path("profile-surface-control.txt"),
            loaded.clone(),
            None,
        );

        let surface_response = parse_downstream_response(&run_runtime_request(
            runtime,
            &get_request("/docs/legacy-import"),
        ));
        let body = String::from_utf8(surface_response.body).expect("body should be utf8");

        assert_eq!(surface_response.status, 200);
        assert!(body.contains("Variant Customer Import Notes"));
        assert_event_routing(&event_log_path, "policy_decision", "eidolon_owned");

        let openapi_event_log_path = unique_temp_path("profile-openapi-events.jsonl");
        let original = r#"{"openapi":"3.0.3","info":{"title":"demo","version":"0"},"paths":{}}"#;
        let (upstream, upstream_handle) = spawn_upstream(json_response(original));
        let openapi_runtime = test_runtime_with_bait_profile(
            upstream,
            &openapi_event_log_path,
            unique_temp_path("profile-openapi-control.txt"),
            loaded,
            None,
        );

        let openapi_response = parse_downstream_response(&run_runtime_request(
            openapi_runtime,
            &get_request("/openapi.json"),
        ));
        upstream_handle.join().expect("upstream thread should join");
        let rewritten: Value = serde_json::from_slice(&openapi_response.body).unwrap();
        let operation = &rewritten["paths"]["/api/v2/import/reconcile"]["post"];

        assert_eq!(
            operation["summary"].as_str(),
            Some("Customer import reconciliation endpoint")
        );
        assert_eq!(
            operation["operationId"].as_str(),
            Some("queueCustomerImportReconciliation")
        );
        assert_eq!(
            operation["responses"]["202"]["description"].as_str(),
            Some("Customer import reconciliation request accepted")
        );
        assert!(operation["description"]
            .as_str()
            .is_some_and(|description| description.contains("external client request")));
        assert!(operation["requestBody"].is_object());
        assert_eq!(
            operation["requestBody"]["content"]["application/json"]["schema"]["required"][0],
            "source_url"
        );
        assert_event_routing(
            &openapi_event_log_path,
            "policy_decision",
            "rewritten_upstream",
        );
    }

    #[test]
    fn runtime_session_minted_bait_surface_is_stable_per_session_and_verifies_action() {
        let path = write_bait_profile(session_minted_profile_json());
        let loaded = load_bait_profile(&path).expect("minted profile should load");
        let bait = loaded
            .registry
            .bait_for_surface("/docs/minted-trace")
            .expect("minted bait should exist")
            .clone();
        let signing_secret: Arc<str> = Arc::from("mint-secret");
        let event_log_path = unique_temp_path("session-minted-bait-events.jsonl");
        let runtime = test_runtime_with_bait_profile(
            closed_upstream(),
            &event_log_path,
            unique_temp_path("session-minted-bait-control.txt"),
            loaded,
            Some(Arc::clone(&signing_secret)),
        );
        let session_a = SessionId::new();
        let cookie_a = format!("eidolon_session={}", minted_cookie_value(session_a));
        let session_b = SessionId::new();
        let cookie_b = format!("eidolon_session={}", minted_cookie_value(session_b));
        let rendered_a = render_bait_for_session(&bait, session_a, Some(signing_secret.as_ref()))
            .expect("session A bait should render")
            .into_owned();
        let rendered_b = render_bait_for_session(&bait, session_b, Some(signing_secret.as_ref()))
            .expect("session B bait should render")
            .into_owned();
        let header_name = rendered_a
            .expected_action
            .header_name
            .as_deref()
            .expect("minted bait should keep header name")
            .to_string();
        let header_value_a = rendered_a
            .expected_action
            .header_value
            .clone()
            .expect("session A bait should mint header value");
        let header_value_b = rendered_b
            .expected_action
            .header_value
            .clone()
            .expect("session B bait should mint header value");

        assert_ne!(header_value_a, header_value_b);

        let response_a = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &get_request_with_cookie("/docs/minted-trace", &cookie_a),
        ));
        let response_a_repeat = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &get_request_with_cookie("/docs/minted-trace", &cookie_a),
        ));
        let response_b = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &get_request_with_cookie("/docs/minted-trace", &cookie_b),
        ));

        assert_eq!(response_a.status, 200);
        assert_eq!(response_a_repeat.status, 200);
        assert_eq!(response_b.status, 200);
        assert!(response_a.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("Cache-Control") && header.value == "private, no-store"
        }));
        assert!(response_a_repeat.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("Cache-Control") && header.value == "private, no-store"
        }));
        assert!(response_b.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("Cache-Control") && header.value == "private, no-store"
        }));

        let body_a = must_ok(String::from_utf8(response_a.body), "body should be utf8");
        let body_a_repeat = must_ok(
            String::from_utf8(response_a_repeat.body),
            "body should be utf8",
        );
        let body_b = must_ok(String::from_utf8(response_b.body), "body should be utf8");

        assert!(body_a.contains(&header_value_a));
        assert!(body_a_repeat.contains(&header_value_a));
        assert!(body_b.contains(&header_value_b));
        assert!(!body_b.contains(&header_value_a));

        let action_response = parse_downstream_response(&run_runtime_request(
            runtime,
            &post_request_with_cookie(
                &bait.expected_action.path,
                &cookie_a,
                &[(&header_name, &header_value_a)],
            ),
        ));

        assert_eq!(action_response.status, 202);
        let action = first_event_of_type(&event_log_path, "bait_action_observed");
        assert_eq!(action["kind"]["bait_id"], "minted_trace");
        assert_eq!(
            action["kind"]["header_value_mint"]["header_name"],
            header_name
        );
        assert_eq!(
            action["kind"]["header_value_mint"]["kind"],
            "session_hmac_sha256_v1"
        );
        assert_eq!(action["kind"]["header_value_mint"]["prefix"], "minted");
        assert!(!action.to_string().contains(&header_value_a));
        let exposure = events_of_type(&event_log_path, "bait_exposed")
            .into_iter()
            .rev()
            .find(|event| {
                event["kind"]["bait_id"] == "minted_trace"
                    && event["session_id"] == action["session_id"]
            })
            .expect("same-session minted exposure should exist");
        assert_eq!(
            action["kind"]["exposure_id"],
            exposure["kind"]["exposure_id"]
        );
        assert_eq!(
            exposure["kind"]["header_value_mint"]["header_name"],
            header_name
        );
        assert_eq!(exposure["kind"]["header_value_mint"]["prefix"], "minted");
        assert!(!exposure.to_string().contains(&header_value_a));
    }

    #[test]
    fn runtime_session_minted_bait_replay_in_same_session_is_logged_and_held_eidolon_owned() {
        let path = write_bait_profile(session_minted_profile_json());
        let loaded = load_bait_profile(&path).expect("minted profile should load");
        let bait = loaded
            .registry
            .bait_for_surface("/docs/minted-trace")
            .expect("minted bait should exist")
            .clone();
        let signing_secret: Arc<str> = Arc::from("mint-secret");
        let event_log_path =
            unique_temp_path("session-minted-bait-same-session-replay-events.jsonl");
        let (upstream, upstream_handle) = spawn_upstream_sequence(vec![]);
        let runtime = test_runtime_with_bait_profile(
            upstream,
            &event_log_path,
            unique_temp_path("session-minted-bait-same-session-replay-control.txt"),
            loaded,
            Some(Arc::clone(&signing_secret)),
        );
        let session_id = SessionId::new();
        let cookie = format!("eidolon_session={}", minted_cookie_value(session_id));
        let rendered = render_bait_for_session(&bait, session_id, Some(signing_secret.as_ref()))
            .expect("session bait should render")
            .into_owned();
        let header_name = rendered
            .expected_action
            .header_name
            .as_deref()
            .expect("minted bait should keep header name")
            .to_string();
        let header_value = rendered
            .expected_action
            .header_value
            .clone()
            .expect("session bait should mint header value");

        let exposure_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &get_request_with_cookie("/docs/minted-trace", &cookie),
        ));
        assert_eq!(exposure_response.status, 200);

        runtime
            .bait_action_replays
            .lock()
            .expect("replay store lock should succeed")
            .record_consumed(session_id, bait.id.clone());

        let replay_response = parse_downstream_response(&run_runtime_request(
            runtime,
            &post_request_with_cookie(
                &bait.expected_action.path,
                &cookie,
                &[(&header_name, &header_value)],
            ),
        ));
        let upstream_requests = must_join(upstream_handle.join(), "upstream thread should join");

        assert_eq!(replay_response.status, 202);
        assert!(
            replay_response
                .headers
                .iter()
                .any(|header| header.name.eq_ignore_ascii_case("content-length")
                    && header.value == "9"),
            "fail-closed response must carry normalized response headers"
        );
        assert!(
            upstream_requests.is_empty(),
            "replayed bait proof must never reach the protected upstream"
        );
        assert_event_routing(&event_log_path, "request_seen", "eidolon_owned");

        let replay_action = events_of_type(&event_log_path, "bait_action_observed")
            .into_iter()
            .find(|event| event["session_id"] == session_id.0.to_string())
            .expect("same-session replay should be logged");
        assert_eq!(replay_action["kind"]["bait_id"], "minted_trace");
        assert_eq!(
            replay_action["kind"]["header_value_mint_status"],
            "replay_seen"
        );

        assert!(!events_of_type(&event_log_path, "policy_changed")
            .into_iter()
            .any(|event| {
                event["session_id"] == session_id.0.to_string()
                    && event["kind"]["to"] == "controlled_reality"
            }));
    }

    #[test]
    fn runtime_session_minted_bait_expired_in_same_session_is_logged_and_held_eidolon_owned() {
        let path = write_bait_profile(session_windowed_minted_profile_json());
        let loaded = load_bait_profile(&path).expect("windowed minted profile should load");
        let bait = loaded
            .registry
            .bait_for_surface("/docs/minted-trace")
            .expect("windowed minted bait should exist")
            .clone();
        let signing_secret: Arc<str> = Arc::from("mint-secret");
        let event_log_path = unique_temp_path("session-minted-bait-expired-events.jsonl");
        let (upstream, upstream_handle) = spawn_upstream_sequence(vec![]);
        let runtime = test_runtime_with_bait_profile(
            upstream,
            &event_log_path,
            unique_temp_path("session-minted-bait-expired-control.txt"),
            loaded,
            Some(Arc::clone(&signing_secret)),
        );
        let session_id = SessionId::new();
        let cookie = format!("eidolon_session={}", minted_cookie_value(session_id));
        let now_epoch_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_secs();
        let rendered = render_bait_for_session_at(
            &bait,
            session_id,
            Some(signing_secret.as_ref()),
            now_epoch_seconds.saturating_sub(121),
        )
        .expect("expired session bait should render")
        .into_owned();
        let header_name = rendered
            .expected_action
            .header_name
            .as_deref()
            .expect("minted bait should keep header name")
            .to_string();
        let header_value = rendered
            .expected_action
            .header_value
            .clone()
            .expect("expired session bait should mint header value");

        let exposure_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &get_request_with_cookie("/docs/minted-trace", &cookie),
        ));
        assert_eq!(exposure_response.status, 200);

        let expired_response = parse_downstream_response(&run_runtime_request(
            runtime,
            &post_request_with_cookie(
                &bait.expected_action.path,
                &cookie,
                &[(&header_name, &header_value)],
            ),
        ));
        let upstream_requests = must_join(upstream_handle.join(), "upstream thread should join");

        assert_eq!(expired_response.status, 202);
        assert!(
            upstream_requests.is_empty(),
            "expired bait proof must never reach the protected upstream"
        );
        assert_event_routing(&event_log_path, "request_seen", "eidolon_owned");

        let expired_action = events_of_type(&event_log_path, "bait_action_observed")
            .into_iter()
            .find(|event| event["session_id"] == session_id.0.to_string())
            .expect("expired same-session proof should be logged");
        assert_eq!(expired_action["kind"]["bait_id"], "minted_trace");
        assert_eq!(
            expired_action["kind"]["header_value_mint_status"],
            "expired_session_value"
        );

        assert!(!events_of_type(&event_log_path, "policy_changed")
            .into_iter()
            .any(|event| {
                event["session_id"] == session_id.0.to_string()
                    && event["kind"]["to"] == "controlled_reality"
            }));
    }

    #[test]
    fn runtime_session_minted_bait_replay_from_other_session_is_not_correlated() {
        let path = write_bait_profile(session_minted_profile_json());
        let loaded = load_bait_profile(&path).expect("minted profile should load");
        let bait = loaded
            .registry
            .bait_for_surface("/docs/minted-trace")
            .expect("minted bait should exist")
            .clone();
        let signing_secret: Arc<str> = Arc::from("mint-secret");
        let event_log_path = unique_temp_path("session-minted-bait-replay-events.jsonl");
        let (upstream, upstream_handle) = spawn_upstream_sequence(vec![]);
        let runtime = test_runtime_with_bait_profile(
            upstream,
            &event_log_path,
            unique_temp_path("session-minted-bait-replay-control.txt"),
            loaded,
            Some(Arc::clone(&signing_secret)),
        );
        let session_a = SessionId::new();
        let cookie_a = format!("eidolon_session={}", minted_cookie_value(session_a));
        let session_b = SessionId::new();
        let cookie_b = format!("eidolon_session={}", minted_cookie_value(session_b));
        let rendered_a = render_bait_for_session(&bait, session_a, Some(signing_secret.as_ref()))
            .expect("session A bait should render")
            .into_owned();
        let header_name = rendered_a
            .expected_action
            .header_name
            .as_deref()
            .expect("minted bait should keep header name")
            .to_string();
        let header_value_a = rendered_a
            .expected_action
            .header_value
            .clone()
            .expect("session A bait should mint header value");

        let exposure_a = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &get_request_with_cookie("/docs/minted-trace", &cookie_a),
        ));
        let exposure_b = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &get_request_with_cookie("/docs/minted-trace", &cookie_b),
        ));
        let replay_response = parse_downstream_response(&run_runtime_request(
            runtime,
            &post_request_with_cookie(
                &bait.expected_action.path,
                &cookie_b,
                &[(&header_name, &header_value_a)],
            ),
        ));
        let upstream_requests = must_join(upstream_handle.join(), "upstream thread should join");

        assert_eq!(exposure_a.status, 200);
        assert_eq!(exposure_b.status, 200);
        assert_eq!(replay_response.status, 202);
        assert!(
            upstream_requests.is_empty(),
            "cross-session replayed bait proof must never reach the protected upstream"
        );

        let replay_action = events_of_type(&event_log_path, "bait_action_observed")
            .into_iter()
            .find(|event| event["session_id"] == session_b.0.to_string())
            .expect("replayed minted bait action should be logged");
        assert_eq!(replay_action["policy_state"], "observe");
        assert_eq!(replay_action["kind"]["bait_id"], "minted_trace");
        assert!(replay_action["kind"]["exposure_id"].is_null());
        assert_eq!(
            replay_action["kind"]["header_value_mint_status"],
            "session_value_mismatch"
        );
        assert_eq!(
            replay_action["kind"]["header_value_mint"]["header_name"],
            header_name
        );
        assert_eq!(
            replay_action["kind"]["header_value_mint"]["kind"],
            "session_hmac_sha256_v1"
        );
        assert_eq!(
            replay_action["kind"]["header_value_mint"]["prefix"],
            "minted"
        );
        assert!(!replay_action.to_string().contains(&header_value_a));

        let replay_request = events_of_type(&event_log_path, "request_seen")
            .into_iter()
            .find(|event| {
                event["session_id"] == session_b.0.to_string()
                    && event["kind"]["path"] == "/api/v2/import/reconcile"
            })
            .expect("replayed minted request_seen should exist");
        assert_eq!(replay_request["policy_state"], "observe");
        assert_eq!(replay_request["kind"]["routing_decision"], "eidolon_owned");

        assert!(!events_of_type(&event_log_path, "policy_changed")
            .into_iter()
            .any(|event| {
                event["session_id"] == session_b.0.to_string()
                    && event["kind"]["to"] == "controlled_reality"
            }));
    }

    #[test]
    fn runtime_committed_service_token_bait_produces_same_session_controlled_reality() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/shield-lab/bait-profiles/default-m3-catalog.json");
        let loaded = load_bait_profile(&path).expect("committed shield-lab profile should load");
        let bait = loaded
            .registry
            .bait_for_class(BaitClass::FakeCredentialToken)
            .expect("fake service token bait should exist")
            .clone();
        let signing_secret: Arc<str> = Arc::from("mint-secret");
        let event_log_path = unique_temp_path("service-token-controlled-reality-events.jsonl");
        let runtime = test_runtime_with_bait_profile(
            closed_upstream(),
            &event_log_path,
            unique_temp_path("service-token-controlled-reality-control.txt"),
            loaded,
            Some(Arc::clone(&signing_secret)),
        );
        let session_id = SessionId::new();
        let cookie = format!("eidolon_session={}", minted_cookie_value(session_id));
        let rendered = render_bait_for_session(&bait, session_id, Some(signing_secret.as_ref()))
            .expect("service token bait should render")
            .into_owned();
        let header_name = rendered
            .expected_action
            .header_name
            .as_deref()
            .expect("service token bait should keep header name")
            .to_string();
        let header_value = rendered
            .expected_action
            .header_value
            .clone()
            .expect("service token bait should mint header value");

        let exposure_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &get_request_with_cookie("/docs/service-token", &cookie),
        ));
        let action_response = parse_downstream_response(&run_runtime_request(
            runtime,
            &post_request_with_cookie(
                "/api/v2/import/reconcile",
                &cookie,
                &[(&header_name, &header_value)],
            ),
        ));

        assert_eq!(exposure_response.status, 200);
        assert!(exposure_response.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("Cache-Control") && header.value == "private, no-store"
        }));
        assert_eq!(action_response.status, 202);
        assert!(must_ok(
            String::from_utf8(action_response.body),
            "body should be utf8"
        )
        .contains(r#""write_committed":false"#));

        let exposure = first_event_of_type(&event_log_path, "bait_exposed");
        let action = first_event_of_type(&event_log_path, "bait_action_observed");
        assert_eq!(exposure["kind"]["bait_id"], "fake_service_token");
        assert_eq!(action["kind"]["bait_id"], "fake_service_token");
        assert_eq!(
            action["kind"]["header_value_mint_status"],
            "matched_session_value"
        );
        assert_eq!(
            action["kind"]["exposure_id"],
            exposure["kind"]["exposure_id"]
        );

        let policy_changed = first_event_of_type(&event_log_path, "policy_changed");
        assert_eq!(policy_changed["kind"]["from"], "observe");
        assert_eq!(policy_changed["kind"]["to"], "controlled_reality");
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason
                .contains("confirmed bait-derived action moved session into controlled reality")));
        assert_eq!(
            first_event_of_type(&event_log_path, "controlled_reality_entered")["policy_state"],
            "controlled_reality"
        );
    }

    #[test]
    fn runtime_committed_js_helper_bait_produces_same_session_controlled_reality() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/shield-lab/bait-profiles/default-m3-catalog.json");
        let loaded = load_bait_profile(&path).expect("committed shield-lab profile should load");
        let bait = loaded
            .registry
            .bait_for_class(BaitClass::JsDiscoveredRoute)
            .expect("js helper bait should exist")
            .clone();
        let signing_secret: Arc<str> = Arc::from("mint-secret");
        let event_log_path = unique_temp_path("js-helper-controlled-reality-events.jsonl");
        let runtime = test_runtime_with_bait_profile(
            closed_upstream(),
            &event_log_path,
            unique_temp_path("js-helper-controlled-reality-control.txt"),
            loaded,
            Some(signing_secret),
        );
        let cookie = cookie_header();
        let header_name = bait
            .expected_action
            .header_name
            .as_deref()
            .expect("js helper bait should keep header name")
            .to_string();
        let header_value = bait
            .expected_action
            .header_value
            .clone()
            .expect("js helper bait should keep static header value");

        let exposure_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &get_request_with_cookie("/assets/import-helper.js", &cookie),
        ));
        let exposure_body = must_ok(
            String::from_utf8(exposure_response.body),
            "body should be utf8",
        );
        let action_response = parse_downstream_response(&run_runtime_request(
            runtime,
            &post_request_with_cookie(
                "/api/v2/import/reconcile",
                &cookie,
                &[(&header_name, &header_value)],
            ),
        ));

        assert_eq!(exposure_response.status, 200);
        assert!(exposure_body.contains("window.__eidolonImportWorker"));
        assert!(exposure_body.contains("X-Import-Worker"));
        assert!(exposure_body.contains("worker_2026_05_c19b"));
        assert_eq!(action_response.status, 202);
        assert!(must_ok(
            String::from_utf8(action_response.body),
            "body should be utf8"
        )
        .contains(r#""write_committed":false"#));

        let exposure = first_event_of_type(&event_log_path, "bait_exposed");
        let action = first_event_of_type(&event_log_path, "bait_action_observed");
        assert_eq!(exposure["kind"]["bait_id"], "js_worker_resume_trace");
        assert_eq!(action["kind"]["bait_id"], "js_worker_resume_trace");
        assert!(action["kind"]["header_value_mint"].is_null());
        assert!(action["kind"]["header_value_mint_status"].is_null());
        assert_eq!(
            action["kind"]["exposure_id"],
            exposure["kind"]["exposure_id"]
        );

        let policy_changed = first_event_of_type(&event_log_path, "policy_changed");
        assert_eq!(policy_changed["kind"]["from"], "observe");
        assert_eq!(policy_changed["kind"]["to"], "controlled_reality");
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason
                .contains("confirmed bait-derived action moved session into controlled reality")));
        assert_eq!(
            first_event_of_type(&event_log_path, "controlled_reality_entered")["policy_state"],
            "controlled_reality"
        );
    }

    #[test]
    fn parses_http_request_with_body() {
        let mut request_bytes = &b"POST /api/v1/imports HTTP/1.1\r\nHost: proxy.local\r\nContent-Length: 16\r\n\r\n{\"source\":\"lab\"}"[..];
        let request = read_http_request(&mut request_bytes)
            .expect("request should parse")
            .expect("request should be present");

        assert_eq!(request.method, "POST");
        assert_eq!(request.target, "/api/v1/imports");
        assert_eq!(request.version, "HTTP/1.1");
        assert_eq!(request.body, br#"{"source":"lab"}"#);
    }

    #[test]
    fn rewrites_request_for_upstream() {
        let upstream = must_ok(
            parse_upstream("http://127.0.0.1:9001", false),
            "upstream should parse",
        );
        let mut request_bytes = &b"GET /docs?view=full HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: keep-alive\r\nUser-Agent: eidolon-test\r\n\r\n"[..];
        let request = read_http_request(&mut request_bytes)
            .expect("request should parse")
            .expect("request should be present");

        let forwarded = String::from_utf8(request.to_upstream_bytes(&upstream).unwrap())
            .expect("forwarded request should be utf8");

        assert!(forwarded.starts_with("GET /docs?view=full HTTP/1.1\r\n"));
        assert!(forwarded.contains("\r\nHost: 127.0.0.1:9001\r\n"));
        assert!(forwarded.contains("\r\nConnection: close\r\n"));
        assert!(forwarded.contains("\r\nUser-Agent: eidolon-test\r\n"));
        assert!(!forwarded.contains("keep-alive"));
    }

    #[test]
    fn upstream_request_strips_hop_by_hop_and_connection_nominated_headers() {
        let upstream = must_ok(
            parse_upstream("http://127.0.0.1:9001", false),
            "upstream should parse",
        );
        let request = HttpRequest {
            method: "GET".to_string(),
            target: "/docs".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![
                HttpHeader {
                    name: "Host".to_string(),
                    value: "127.0.0.1:8080".to_string(),
                },
                HttpHeader {
                    name: "Connection".to_string(),
                    value: "keep-alive, X-Hop".to_string(),
                },
                HttpHeader {
                    name: "X-Hop".to_string(),
                    value: "remove-me".to_string(),
                },
                HttpHeader {
                    name: "Proxy-Connection".to_string(),
                    value: "keep-alive".to_string(),
                },
                HttpHeader {
                    name: "Keep-Alive".to_string(),
                    value: "timeout=5".to_string(),
                },
                HttpHeader {
                    name: "TE".to_string(),
                    value: "trailers".to_string(),
                },
                HttpHeader {
                    name: "Trailer".to_string(),
                    value: "Expires".to_string(),
                },
                HttpHeader {
                    name: "Transfer-Encoding".to_string(),
                    value: "gzip".to_string(),
                },
                HttpHeader {
                    name: "Upgrade".to_string(),
                    value: "websocket".to_string(),
                },
                HttpHeader {
                    name: "X-End-To-End".to_string(),
                    value: "keep-me".to_string(),
                },
            ],
            body: Vec::new(),
        };

        let forwarded = String::from_utf8(request.to_upstream_bytes(&upstream).unwrap())
            .expect("forwarded request should be utf8");

        assert!(forwarded.contains("\r\nHost: 127.0.0.1:9001\r\n"));
        assert!(forwarded.contains("\r\nConnection: close\r\n"));
        assert!(forwarded.contains("\r\nX-End-To-End: keep-me\r\n"));
        assert!(!forwarded.contains("\r\nProxy-Connection:"));
        assert!(!forwarded.contains("\r\nKeep-Alive:"));
        assert!(!forwarded.contains("\r\nTE:"));
        assert!(!forwarded.contains("\r\nTrailer:"));
        assert!(!forwarded.contains("\r\nTransfer-Encoding:"));
        assert!(!forwarded.contains("\r\nUpgrade:"));
        assert!(!forwarded.contains("\r\nX-Hop:"));
    }

    #[test]
    fn upstream_request_emits_one_canonical_content_length() {
        let upstream = must_ok(
            parse_upstream("http://127.0.0.1:9001", false),
            "upstream should parse",
        );
        let mut request_bytes = &b"POST /api/v1/imports HTTP/1.1\r\nHost: proxy.local\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\ntest"[..];
        let request = read_http_request(&mut request_bytes)
            .expect("request should parse")
            .expect("request should be present");

        let forwarded = String::from_utf8(request.to_upstream_bytes(&upstream).unwrap())
            .expect("forwarded request should be utf8");
        let content_length_lines = forwarded
            .lines()
            .filter(|line| line.eq_ignore_ascii_case("content-length: 4"))
            .count();

        assert_eq!(content_length_lines, 1);
    }

    #[test]
    fn normalizes_absolute_form_request_targets() {
        assert_eq!(
            normalize_request_target("http://127.0.0.1:8080/openapi.json?x=1").unwrap(),
            "/openapi.json?x=1"
        );
        assert_eq!(
            normalize_request_target("http://127.0.0.1:8080").unwrap(),
            "/"
        );
    }

    #[test]
    fn rejects_chunked_request_bodies_for_v0() {
        let mut request_bytes =
            &b"POST /api/v1/imports HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"[..];
        let error = read_http_request(&mut request_bytes).expect_err("chunked should fail");

        assert!(error.to_string().contains("chunked"));
    }

    #[test]
    fn rejects_conflicting_request_content_lengths() {
        let mut request_bytes =
            &b"POST /api/v1/imports HTTP/1.1\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\ntest"
                [..];
        let error =
            read_http_request(&mut request_bytes).expect_err("conflicting lengths should fail");

        assert!(error.to_string().contains("conflicting request"));
    }

    #[test]
    fn parses_http_response_with_body() {
        let mut response_bytes = &b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}"[..];
        let response = read_http_response(&mut response_bytes).expect("response should parse");

        assert_eq!(response.version, "HTTP/1.1");
        assert_eq!(response.status, 200);
        assert_eq!(response.reason, "OK");
        assert_eq!(
            response
                .headers
                .iter()
                .find(|header| header.name.eq_ignore_ascii_case("content-type"))
                .map(|header| header.value.as_str()),
            Some("application/json")
        );
        assert_eq!(response.body, br#"{"status":"ok"}"#);
    }

    #[test]
    fn decodes_chunked_upstream_responses() {
        let mut response_bytes =
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"[..];
        let response = read_http_response(&mut response_bytes).expect("chunked should decode");

        assert_eq!(response.body, b"ok");
    }

    #[test]
    fn rejects_chunked_response_size_overflow_after_prior_chunk() {
        let response_bytes = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n{:x}\r\n",
            usize::MAX
        );
        let mut response_bytes = response_bytes.as_bytes();

        let error =
            read_http_response(&mut response_bytes).expect_err("oversize chunk should fail");

        assert!(error.to_string().contains("size limit"));
    }

    #[test]
    fn rejects_unsupported_upstream_transfer_encodings() {
        let mut response_bytes = &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nopaque"[..];
        let error =
            read_http_response(&mut response_bytes).expect_err("transfer encoding should fail");

        assert!(error.to_string().contains("Transfer-Encoding"));
    }

    #[test]
    fn downstream_headers_remove_transfer_encoding_and_duplicate_singletons() {
        let mut authority = test_session_authority();
        let session = session::derive_session_from_headers(
            &mut authority,
            [("Cookie", cookie_header())],
            None,
            now_unix_secs(),
        );
        let mut response = HttpResponse {
            version: "HTTP/1.1".to_string(),
            status: 200,
            reason: "OK".to_string(),
            headers: vec![
                HttpHeader {
                    name: "Transfer-Encoding".to_string(),
                    value: "chunked".to_string(),
                },
                HttpHeader {
                    name: "Content-Length".to_string(),
                    value: "999".to_string(),
                },
                HttpHeader {
                    name: "content-length".to_string(),
                    value: "1000".to_string(),
                },
                HttpHeader {
                    name: "Connection".to_string(),
                    value: "keep-alive, X-Hop-By-Hop".to_string(),
                },
                HttpHeader {
                    name: "connection".to_string(),
                    value: "upgrade".to_string(),
                },
                HttpHeader {
                    name: "Keep-Alive".to_string(),
                    value: "timeout=5".to_string(),
                },
                HttpHeader {
                    name: "Trailer".to_string(),
                    value: "Expires".to_string(),
                },
                HttpHeader {
                    name: "Upgrade".to_string(),
                    value: "websocket".to_string(),
                },
                HttpHeader {
                    name: "X-Hop-By-Hop".to_string(),
                    value: "remove me".to_string(),
                },
            ],
            body: b"ok".to_vec(),
        };

        apply_response_headers(&mut response, &session);

        assert!(header_values(&response, "transfer-encoding").is_empty());
        assert!(header_values(&response, "keep-alive").is_empty());
        assert!(header_values(&response, "trailer").is_empty());
        assert!(header_values(&response, "upgrade").is_empty());
        assert!(header_values(&response, "x-hop-by-hop").is_empty());
        assert_eq!(header_values(&response, "content-length"), vec!["2"]);
        assert_eq!(header_values(&response, "connection"), vec!["close"]);
    }

    #[test]
    fn bait_exposure_store_evicts_oldest_exposure_at_cap() {
        let mut store = BaitExposureStore::default();
        let oldest_session_id = SessionId::new();
        let oldest_bait_id = BaitId("oldest".to_string());
        store.record_exposure(
            oldest_session_id,
            oldest_bait_id.clone(),
            ExposureId("oldest-exposure".to_string()),
        );

        for index in 0..MAX_BAIT_EXPOSURES {
            store.record_exposure(
                SessionId::new(),
                BaitId(format!("bait-{index}")),
                ExposureId(format!("exp-{index}")),
            );
        }

        assert_eq!(store.exposures.len(), MAX_BAIT_EXPOSURES);
        assert!(store
            .exposure_for_action(oldest_session_id, &oldest_bait_id)
            .is_none());
    }

    #[test]
    fn bait_exposure_store_refreshes_duplicate_exposure_order() {
        let mut store = BaitExposureStore::default();
        let session_id = SessionId::new();
        let bait_id = BaitId("refreshable".to_string());
        store.record_exposure(
            session_id,
            bait_id.clone(),
            ExposureId("old-exposure".to_string()),
        );

        for index in 0..MAX_BAIT_EXPOSURES - 1 {
            store.record_exposure(
                SessionId::new(),
                BaitId(format!("bait-{index}")),
                ExposureId(format!("exp-{index}")),
            );
        }
        store.record_exposure(
            session_id,
            bait_id.clone(),
            ExposureId("new-exposure".to_string()),
        );
        store.record_exposure(
            SessionId::new(),
            BaitId("overflow".to_string()),
            ExposureId("overflow-exp".to_string()),
        );

        assert_eq!(store.exposures.len(), MAX_BAIT_EXPOSURES);
        assert_eq!(
            store.exposure_for_action(session_id, &bait_id),
            Some(ExposureId("new-exposure".to_string()))
        );
    }

    #[test]
    fn bait_exposure_store_starts_empty_when_event_log_is_missing() {
        let path = unique_temp_path("missing-exposure-events.jsonl");

        let store = BaitExposureStore::from_event_log(&path).expect("missing log should rebuild");

        assert_eq!(store.len(), 0);
    }

    #[test]
    fn bait_exposure_store_rebuilds_latest_exposures_from_event_log() {
        let session_id = SessionId::new();
        let bait_id = BaitId("replay-bait".to_string());
        let other_bait_id = BaitId("other-bait".to_string());
        let old_exposure_id = ExposureId("old-exposure".to_string());
        let new_exposure_id = ExposureId("new-exposure".to_string());
        let other_exposure_id = ExposureId("other-exposure".to_string());
        let events = [
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::Observe,
                EventKind::RequestSeen {
                    method: "GET".to_string(),
                    path: "/docs".to_string(),
                    safe_headers: Vec::new(),
                    ingress_identity: Default::default(),
                    authenticated_ingress_rule_rejection: None,
                    local_ingress_trust_scope_rejection: None,
                    trusted_ingress_soften_match: None,
                    ingress_signals: Default::default(),
                    discovery_recon_score: Default::default(),
                    routing_decision: RoutingDecision::ProtectedUpstream,
                },
            ),
            Event::new(
                session_id,
                EventSource::SurfaceController,
                PolicyState::Observe,
                EventKind::BaitExposed {
                    bait_id: bait_id.clone(),
                    exposure_id: old_exposure_id,
                    surface: "/docs".to_string(),
                    header_value_mint: None,
                },
            ),
            Event::new(
                session_id,
                EventSource::SurfaceController,
                PolicyState::Observe,
                EventKind::BaitExposed {
                    bait_id: other_bait_id.clone(),
                    exposure_id: other_exposure_id.clone(),
                    surface: "/openapi.json".to_string(),
                    header_value_mint: None,
                },
            ),
            Event::new(
                session_id,
                EventSource::SurfaceController,
                PolicyState::Observe,
                EventKind::BaitExposed {
                    bait_id: bait_id.clone(),
                    exposure_id: new_exposure_id.clone(),
                    surface: "/docs".to_string(),
                    header_value_mint: None,
                },
            ),
        ];
        let jsonl = events
            .iter()
            .map(|event| serde_json::to_string(event).expect("event should serialize"))
            .collect::<Vec<_>>()
            .join("\n");

        let store = BaitExposureStore::from_event_log_reader(Cursor::new(format!("{jsonl}\n")))
            .expect("event log should rebuild");

        assert_eq!(store.len(), 2);
        assert_eq!(
            store.exposure_for_action(session_id, &bait_id),
            Some(new_exposure_id)
        );
        assert_eq!(
            store.exposure_for_action(session_id, &other_bait_id),
            Some(other_exposure_id)
        );
    }

    #[test]
    fn bait_exposure_store_rebuild_rejects_malformed_event_log_line() {
        let error = BaitExposureStore::from_event_log_reader(Cursor::new("{not json}\n"))
            .expect_err("malformed log should fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error
            .to_string()
            .contains("could not rebuild bait exposure store from event log line 1"));
    }

    #[test]
    fn bait_exposure_store_rebuild_rejects_unsupported_event_schema() {
        let mut value = serde_json::to_value(Event::new(
            SessionId::new(),
            EventSource::SurfaceController,
            PolicyState::Observe,
            EventKind::BaitExposed {
                bait_id: BaitId("schema-bait".to_string()),
                exposure_id: ExposureId("schema-exposure".to_string()),
                surface: "/docs".to_string(),
                header_value_mint: None,
            },
        ))
        .expect("event should serialize");
        value["schema_version"] = Value::from(u64::from(EVENT_SCHEMA_VERSION) + 1);
        let line = serde_json::to_string(&value).expect("event value should serialize");

        let error = BaitExposureStore::from_event_log_reader(Cursor::new(format!("{line}\n")))
            .expect_err("unsupported schema should fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains(&format!(
            "unsupported schema_version {}; expected {EVENT_SCHEMA_VERSION}",
            EVENT_SCHEMA_VERSION + 1
        )));
    }

    #[test]
    fn serializes_http_response_after_header_update() {
        let mut response = HttpResponse {
            version: "HTTP/1.1".to_string(),
            status: 200,
            reason: "OK".to_string(),
            headers: vec![HttpHeader {
                name: "Content-Length".to_string(),
                value: "2".to_string(),
            }],
            body: b"ok".to_vec(),
        };

        response.set_header("Connection", "close");
        response.append_header("Set-Cookie", "eidolon_session=abc; Path=/");

        let serialized = String::from_utf8(response.to_http_bytes()).unwrap();

        assert!(serialized.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(serialized.contains("\r\nContent-Length: 2\r\n"));
        assert!(serialized.contains("\r\nConnection: close\r\n"));
        assert!(serialized.contains("\r\nSet-Cookie: eidolon_session=abc; Path=/\r\n"));
        assert!(serialized.ends_with("\r\n\r\nok"));
    }

    #[test]
    fn surface_response_to_http_uses_non_ok_reason_for_unmapped_statuses() {
        let method_not_allowed =
            surface_response_to_http(SurfaceResponse::new(405, Vec::new(), "nope"));
        let unknown = surface_response_to_http(SurfaceResponse::new(599, Vec::new(), "nope"));

        assert!(String::from_utf8(method_not_allowed.to_http_bytes())
            .unwrap()
            .starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
        assert!(String::from_utf8(unknown.to_http_bytes())
            .unwrap()
            .starts_with("HTTP/1.1 599 Unknown Status\r\n"));
    }

    #[test]
    fn runtime_path_serves_eidolon_owned_surface_response() {
        let event_log_path = unique_temp_path("owned-events.jsonl");
        let runtime = test_runtime(
            must_ok(
                parse_upstream(DEFAULT_UPSTREAM, false),
                "default upstream should parse",
            ),
            &event_log_path,
            unique_temp_path("owned-control.txt"),
            SurfaceAction::EidolonOwned {
                response: SurfaceResponse::new(
                    202,
                    vec![SurfaceHeader::new("Content-Type", "text/plain")],
                    "owned surface\n",
                ),
            },
        );

        let response = parse_downstream_response(&run_runtime_request(runtime, &get_request("/")));

        assert_eq!(response.status, 202);
        assert_eq!(response.body, b"owned surface\n");
        assert_event_routing(&event_log_path, "request_seen", "eidolon_owned");
        assert_event_routing(&event_log_path, "response_served", "eidolon_owned");
    }

    #[test]
    fn runtime_debug_log_records_sanitized_server_side_lifecycle() {
        let event_log_path = unique_temp_path("debug-owned-events.jsonl");
        let debug_log_path = unique_temp_path("debug-owned-debug.jsonl");
        let mut runtime = test_runtime(
            must_ok(
                parse_upstream(DEFAULT_UPSTREAM, false),
                "default upstream should parse",
            ),
            &event_log_path,
            unique_temp_path("debug-owned-control.txt"),
            SurfaceAction::EidolonOwned {
                response: SurfaceResponse::new(
                    202,
                    vec![SurfaceHeader::new("Content-Type", "text/plain")],
                    "owned surface\n",
                ),
            },
        );
        runtime.debug_log = Some(Arc::new(Mutex::new(
            FileDebugLogWriter::open(&debug_log_path).expect("debug log should open"),
        )));

        let request = b"POST /docs/legacy-import?token=secret-value HTTP/1.1\r\nHost: proxy.local\r\nAuthorization: Bearer secret-value\r\nContent-Length: 7\r\n\r\npayload";
        let response_bytes = run_runtime_request(runtime, request);
        let response = String::from_utf8(response_bytes).expect("response should be utf8");

        assert!(!response.contains("eidolon_proxy_debug"));
        assert!(!response.contains("secret-value"));
        assert!(!response.contains("payload"));

        let raw_debug_log = fs::read_to_string(&debug_log_path).expect("debug log should read");
        assert!(!raw_debug_log.contains("secret-value"));
        assert!(!raw_debug_log.contains("Bearer"));
        assert!(!raw_debug_log.contains("payload"));

        let raw_event_log = fs::read_to_string(&event_log_path).expect("event log should read");
        assert!(!raw_event_log.contains("secret-value"));
        assert_eq!(
            first_event_of_type(&event_log_path, "request_seen")["kind"]["path"],
            "/docs/legacy-import?token=<redacted>"
        );

        let request_debug = first_debug_event(&debug_log_path, "request_received");
        assert_eq!(request_debug["run_kind"], "eidolon_proxy_debug");
        assert_eq!(request_debug["fields"]["method"], "POST");
        assert_eq!(request_debug["fields"]["path"], "/docs/legacy-import");
        assert_eq!(request_debug["fields"]["query_present"], true);
        assert_eq!(request_debug["fields"]["body_len"], 7);
        assert_eq!(
            request_debug["fields"]["ingress_identity"]["source"],
            "none"
        );
        assert_eq!(
            request_debug["fields"]["ingress_identity"]["trust_tier"],
            "none"
        );
        assert_eq!(
            request_debug["fields"]["safe_headers"][1]["name"],
            "authorization"
        );
        assert_eq!(request_debug["fields"]["safe_headers"][1]["present"], true);

        let surface_debug = first_debug_event(&debug_log_path, "surface_action_selected");
        assert_eq!(
            surface_debug["fields"]["surface_action"]["type"],
            "eidolon_owned"
        );

        let response_debug = first_debug_event(&debug_log_path, "response_served");
        assert_eq!(response_debug["fields"]["route"], "direct_surface");
        assert_eq!(response_debug["fields"]["response"]["status"], 202);
    }

    #[test]
    fn runtime_records_normalized_ingress_identity_in_request_audit() {
        let event_log_path = unique_temp_path("ingress-identity-events.jsonl");
        let debug_log_path = unique_temp_path("ingress-identity-debug.jsonl");
        let (upstream, upstream_handle) =
            spawn_upstream(html_response("<html><body>upstream</body></html>"));
        let mut runtime = test_runtime_with_m1_controller_and_debug_log(
            upstream,
            &event_log_path,
            &debug_log_path,
            unique_temp_path("ingress-identity-control.txt"),
        );
        runtime.ingress_transport_auth_secret = Some(Arc::<str>::from("edge-secret"));

        let request = request_with_cookie(
            "GET",
            "/docs/legacy-import",
            &cookie_header(),
            &[
                (
                    session::INGRESS_IDENTITY_SOURCE_HEADER_NAME,
                    "operator_override",
                ),
                (session::INGRESS_TRUST_TIER_HEADER_NAME, "allowlisted"),
                (
                    session::INGRESS_IDENTITY_LABEL_HEADER_NAME,
                    "internal-crawler",
                ),
                (
                    session::INGRESS_IDENTITY_EXPIRES_AT_HEADER_NAME,
                    "2099-06-04T12:00:00Z",
                ),
                (session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
            ],
        );
        let _response = run_runtime_request(runtime, &request);
        must_join(upstream_handle.join(), "upstream thread should join");

        let request_event = first_event_of_type(&event_log_path, "request_seen");
        assert_eq!(
            request_event["kind"]["ingress_identity"]["source"],
            "operator_override"
        );
        assert_eq!(
            request_event["kind"]["ingress_identity"]["trust_tier"],
            "allowlisted"
        );
        assert_eq!(
            request_event["kind"]["ingress_identity"]["label"],
            "internal-crawler"
        );
        assert_eq!(
            request_event["kind"]["ingress_identity"]["expires_at"],
            "2099-06-04T12:00:00Z"
        );

        let request_debug = first_debug_event(&debug_log_path, "request_received");
        assert_eq!(
            request_debug["fields"]["ingress_identity"]["source"],
            "operator_override"
        );
        assert_eq!(
            request_debug["fields"]["ingress_identity"]["trust_tier"],
            "allowlisted"
        );
    }

    #[test]
    fn runtime_records_authenticated_ingress_advisory_signals_in_request_audit() {
        let event_log_path = unique_temp_path("ingress-signals-events.jsonl");
        let debug_log_path = unique_temp_path("ingress-signals-debug.jsonl");
        let (upstream, upstream_handle) =
            spawn_upstream(html_response("<html><body>upstream</body></html>"));
        let mut runtime = test_runtime_with_m1_controller_and_debug_log(
            upstream,
            &event_log_path,
            &debug_log_path,
            unique_temp_path("ingress-signals-control.txt"),
        );
        runtime.ingress_transport_auth_secret = Some(Arc::<str>::from("edge-secret"));

        let request = request_with_cookie(
            "GET",
            "/health",
            &cookie_header(),
            &[
                (
                    session::INGRESS_VERIFICATION_STRENGTH_HEADER_NAME,
                    "cryptographic",
                ),
                (session::INGRESS_ACTOR_KIND_HEADER_NAME, "agentic_browser"),
                (
                    session::INGRESS_VERIFIED_CATEGORY_HEADER_NAME,
                    "AI Assistant",
                ),
                (
                    session::INGRESS_ATTESTATION_REF_HEADER_NAME,
                    "jkt:sha256:ba3e64",
                ),
                (session::INGRESS_VENDOR_SCORE_HEADER_NAME, "12"),
                (
                    session::INGRESS_VENDOR_SCORE_KIND_HEADER_NAME,
                    "automation_likelihood_inverse",
                ),
                (session::INGRESS_VENDOR_SCORE_SCALE_HEADER_NAME, "1-99"),
                (session::INGRESS_DETECTION_IDS_HEADER_NAME, "3355446,445566"),
                (session::INGRESS_EDGE_ACTION_HEADER_NAME, "allow"),
                (session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
            ],
        );
        let _response = run_runtime_request(runtime, &request);
        must_join(upstream_handle.join(), "upstream thread should join");

        let request_event = first_event_of_type(&event_log_path, "request_seen");
        assert_eq!(
            request_event["kind"]["ingress_signals"]["verification_strength"],
            "cryptographic"
        );
        assert_eq!(
            request_event["kind"]["ingress_signals"]["actor_kind"],
            "agentic_browser"
        );
        assert_eq!(
            request_event["kind"]["ingress_signals"]["verified_category"],
            "AI Assistant"
        );
        assert_eq!(
            request_event["kind"]["ingress_signals"]["attestation_ref"],
            "jkt:sha256:ba3e64"
        );
        assert_eq!(request_event["kind"]["ingress_signals"]["vendor_score"], 12);
        assert_eq!(
            request_event["kind"]["ingress_signals"]["detection_ids"][0],
            "3355446"
        );
        assert_eq!(
            request_event["kind"]["ingress_signals"]["edge_action"],
            "allow"
        );

        let request_debug = first_debug_event(&debug_log_path, "request_received");
        assert_eq!(
            request_debug["fields"]["ingress_signals"]["verification_strength"],
            "cryptographic"
        );
        assert_eq!(
            request_debug["fields"]["ingress_signals"]["vendor_score"],
            12
        );
    }

    #[test]
    fn runtime_promotes_low_score_agentic_discovery_request_to_suspicious() {
        let event_log_path = unique_temp_path("suspicious-discovery-events.jsonl");
        let debug_log_path = unique_temp_path("suspicious-discovery-debug.jsonl");
        let mut runtime = test_runtime_with_m1_controller_and_debug_log(
            must_ok(
                parse_upstream(DEFAULT_UPSTREAM, false),
                "default upstream should parse",
            ),
            &event_log_path,
            &debug_log_path,
            unique_temp_path("suspicious-discovery-control.txt"),
        );
        runtime.ingress_transport_auth_secret = Some(Arc::<str>::from("edge-secret"));

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &request_with_cookie(
                "GET",
                "/docs?topic=imports",
                &cookie_header(),
                &[
                    (session::INGRESS_ACTOR_KIND_HEADER_NAME, "agentic_browser"),
                    (session::INGRESS_VENDOR_SCORE_HEADER_NAME, "12"),
                    (
                        session::INGRESS_VENDOR_SCORE_KIND_HEADER_NAME,
                        "automation_likelihood_inverse",
                    ),
                    (session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
                ],
            ),
        ));
        let Ok(body) = String::from_utf8(response.body) else {
            panic!("body should be utf8");
        };

        assert_eq!(response.status, 200);
        assert!(body.contains("X-Migration-Trace: rel_2025_04_b7f2"));
        assert!(body.contains("POST /api/v2/import/reconcile"));

        let request_event = first_event_of_type(&event_log_path, "request_seen");
        assert_eq!(request_event["policy_state"], "suspicious");
        assert_eq!(request_event["kind"]["routing_decision"], "eidolon_owned");
        let policy_changed = first_event_of_type(&event_log_path, "policy_changed");
        assert_eq!(policy_changed["kind"]["from"], "observe");
        assert_eq!(policy_changed["kind"]["to"], "suspicious");
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains(
                "authenticated ingress advisory signals promoted discovery request to suspicious"
            )));
        let bait_exposed = first_event_of_type(&event_log_path, "bait_exposed");
        assert_eq!(bait_exposed["kind"]["bait_id"], "rel_2025_04_b7f2");
        assert_eq!(bait_exposed["kind"]["surface"], "/docs");

        let surface_debug = debug_values(&debug_log_path)
            .into_iter()
            .rfind(|event| event["event"].as_str() == Some("surface_action_selected"))
            .expect("second request should record a surface action");
        assert_eq!(surface_debug["fields"]["policy_state"], "suspicious");
        assert_eq!(
            surface_debug["fields"]["controller_surface_action"]["type"],
            "rewritten_upstream"
        );
        assert_eq!(
            surface_debug["fields"]["candidate_surface_action"]["type"],
            "eidolon_owned"
        );
        assert_eq!(
            surface_debug["fields"]["surface_action"]["type"],
            "eidolon_owned"
        );
        assert_eq!(
            surface_debug["fields"]["trusted_ingress_softened_surface"],
            false
        );
    }

    #[test]
    fn runtime_serves_owned_openapi_discovery_for_suspicious_session() {
        let event_log_path = unique_temp_path("suspicious-openapi-events.jsonl");
        let debug_log_path = unique_temp_path("suspicious-openapi-debug.jsonl");
        let mut runtime = test_runtime_with_m1_controller_and_debug_log(
            must_ok(
                parse_upstream(DEFAULT_UPSTREAM, false),
                "default upstream should parse",
            ),
            &event_log_path,
            &debug_log_path,
            unique_temp_path("suspicious-openapi-control.txt"),
        );
        runtime.ingress_transport_auth_secret = Some(Arc::<str>::from("edge-secret"));

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &request_with_cookie(
                "GET",
                "/openapi.json",
                &cookie_header(),
                &[
                    (session::INGRESS_ACTOR_KIND_HEADER_NAME, "agentic_browser"),
                    (session::INGRESS_VENDOR_SCORE_HEADER_NAME, "12"),
                    (
                        session::INGRESS_VENDOR_SCORE_KIND_HEADER_NAME,
                        "automation_likelihood_inverse",
                    ),
                    (session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
                ],
            ),
        ));
        let Ok(rewritten) = serde_json::from_slice::<Value>(&response.body) else {
            panic!("body should be json");
        };

        assert_eq!(response.status, 200);
        assert_eq!(rewritten["openapi"].as_str(), Some("3.0.3"));
        assert!(rewritten["paths"]["/api/v2/import/reconcile"].is_object());
        assert_eq!(
            rewritten["paths"]["/api/v2/import/reconcile"]["post"]["parameters"][0]["name"],
            "X-OpenAPI-Trace"
        );
        assert!(rewritten["paths"]["/api/v2/import/reconcile"]["post"]["requestBody"].is_object());

        let request_event = first_event_of_type(&event_log_path, "request_seen");
        assert_eq!(request_event["policy_state"], "suspicious");
        assert_eq!(request_event["kind"]["routing_decision"], "eidolon_owned");
        let policy_changed = first_event_of_type(&event_log_path, "policy_changed");
        assert_eq!(policy_changed["kind"]["from"], "observe");
        assert_eq!(policy_changed["kind"]["to"], "suspicious");
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains(
                "authenticated ingress advisory signals promoted discovery request to suspicious"
            )));
        let bait_exposed = first_event_of_type(&event_log_path, "bait_exposed");
        assert_eq!(bait_exposed["kind"]["bait_id"], "openapi_reconcile_trace");
        assert_eq!(bait_exposed["kind"]["surface"], "/openapi.json");

        let surface_debug = first_debug_event(&debug_log_path, "surface_action_selected");
        assert_eq!(surface_debug["fields"]["policy_state"], "suspicious");
        assert_eq!(
            surface_debug["fields"]["controller_surface_action"]["type"],
            "rewritten_upstream"
        );
        assert_eq!(
            surface_debug["fields"]["candidate_surface_action"]["type"],
            "eidolon_owned"
        );
        assert_eq!(
            surface_debug["fields"]["surface_action"]["type"],
            "eidolon_owned"
        );
        assert_eq!(
            surface_debug["fields"]["trusted_ingress_softened_surface"],
            false
        );
    }

    #[test]
    fn runtime_promotes_discovery_surface_fanout_to_suspicious() {
        let event_log_path = unique_temp_path("fanout-suspicious-events.jsonl");
        let debug_log_path = unique_temp_path("fanout-suspicious-debug.jsonl");
        let original = r#"<!doctype html><html><body><main>docs</main></body></html>"#;
        let (upstream, upstream_handle) = spawn_upstream(html_response(original));
        let runtime = test_runtime_with_m1_controller_and_debug_log(
            upstream,
            &event_log_path,
            &debug_log_path,
            unique_temp_path("fanout-suspicious-control.txt"),
        );
        let cookie = cookie_header();

        let first_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &get_request_with_cookie("/docs?topic=imports", &cookie),
        ));
        let first_body = must_ok(
            String::from_utf8(first_response.body),
            "body should be utf8",
        );
        must_join(upstream_handle.join(), "upstream thread should join");

        let second_response = parse_downstream_response(&run_runtime_request(
            runtime,
            &get_request_with_cookie("/openapi.json", &cookie),
        ));
        let second_body: Value = must_ok(
            serde_json::from_slice(&second_response.body),
            "body should be json",
        );

        assert_eq!(first_response.status, 200);
        assert!(first_body.contains("/docs/legacy-import"));
        assert_eq!(second_response.status, 200);
        assert_eq!(second_body["openapi"].as_str(), Some("3.0.3"));
        assert!(second_body["paths"]["/api/v2/import/reconcile"].is_object());

        let request_events = events_of_type(&event_log_path, "request_seen");
        assert_eq!(request_events.len(), 2);
        assert_eq!(request_events[0]["policy_state"], "observe");
        assert_eq!(
            request_events[0]["kind"]["routing_decision"],
            "protected_upstream"
        );
        assert_eq!(request_events[1]["policy_state"], "suspicious");
        assert_eq!(
            request_events[1]["kind"]["routing_decision"],
            "eidolon_owned"
        );
        assert_eq!(request_events[1]["kind"]["path"], "/openapi.json");

        let policy_changed = first_event_of_type(&event_log_path, "policy_changed");
        assert_eq!(policy_changed["kind"]["from"], "observe");
        assert_eq!(policy_changed["kind"]["to"], "suspicious");
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains(
                "session recon discovery-surface fanout promoted request to suspicious"
            )));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("distinct_surfaces=2")));

        let bait_exposed = first_event_of_type(&event_log_path, "bait_exposed");
        assert_eq!(bait_exposed["kind"]["bait_id"], "openapi_reconcile_trace");
        assert_eq!(bait_exposed["kind"]["surface"], "/openapi.json");

        let request_debugs: Vec<Value> = debug_values(&debug_log_path)
            .into_iter()
            .filter(|event| event["event"].as_str() == Some("request_received"))
            .collect();
        assert_eq!(request_debugs.len(), 2);
        assert_eq!(
            request_debugs[1]["fields"]["discovery_surface_fanout"]["distinct_surfaces"],
            2
        );
        assert_eq!(
            request_debugs[1]["fields"]["discovery_surface_fanout"]["docs_seen"],
            true
        );
        assert_eq!(
            request_debugs[1]["fields"]["discovery_surface_fanout"]["openapi_seen"],
            true
        );

        let surface_debugs: Vec<Value> = debug_values(&debug_log_path)
            .into_iter()
            .filter(|event| event["event"].as_str() == Some("surface_action_selected"))
            .collect();
        assert_eq!(
            surface_debugs[1]["fields"]["candidate_surface_action"]["type"],
            "eidolon_owned"
        );
        assert_eq!(surface_debugs[1]["fields"]["policy_state"], "suspicious");
    }

    #[test]
    fn runtime_aggregates_medium_score_repeated_discovery_to_suspicious() {
        let event_log_path = unique_temp_path("aggregated-suspicious-events.jsonl");
        let debug_log_path = unique_temp_path("aggregated-suspicious-debug.jsonl");
        let original = r#"<!doctype html><html><body><main>docs</main></body></html>"#;
        let (upstream, upstream_handle) = spawn_upstream(html_response(original));
        let mut runtime = test_runtime_with_m1_controller_and_debug_log(
            upstream,
            &event_log_path,
            &debug_log_path,
            unique_temp_path("aggregated-suspicious-control.txt"),
        );
        runtime.ingress_transport_auth_secret = Some(Arc::<str>::from("edge-secret"));
        let cookie = cookie_header();
        let headers = [
            (session::INGRESS_ACTOR_KIND_HEADER_NAME, "agentic_browser"),
            (session::INGRESS_VENDOR_SCORE_HEADER_NAME, "35"),
            (
                session::INGRESS_VENDOR_SCORE_KIND_HEADER_NAME,
                "automation_likelihood_inverse",
            ),
            (session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
        ];

        let first_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &request_with_cookie("GET", "/docs?topic=imports", &cookie, &headers),
        ));
        must_join(upstream_handle.join(), "upstream thread should join");
        let second_response = parse_downstream_response(&run_runtime_request(
            runtime,
            &request_with_cookie("GET", "/docs", &cookie, &headers),
        ));
        let second_body = must_ok(
            String::from_utf8(second_response.body),
            "body should be utf8",
        );

        assert_eq!(first_response.status, 200);
        assert_eq!(second_response.status, 200);
        assert!(second_body.contains("X-Migration-Trace: rel_2025_04_b7f2"));

        let request_events = events_of_type(&event_log_path, "request_seen");
        assert_eq!(request_events.len(), 2);
        assert_eq!(request_events[0]["policy_state"], "observe");
        assert_eq!(
            request_events[0]["kind"]["routing_decision"],
            "protected_upstream"
        );
        assert_eq!(request_events[1]["policy_state"], "suspicious");
        assert_eq!(
            request_events[1]["kind"]["routing_decision"],
            "eidolon_owned"
        );

        let policy_changed = first_event_of_type(&event_log_path, "policy_changed");
        assert_eq!(policy_changed["kind"]["from"], "observe");
        assert_eq!(policy_changed["kind"]["to"], "suspicious");
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains(
                "multi-signal discovery recon aggregation promoted request to suspicious"
            )));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("discovery_requests=2")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("vendor_score=35")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("query_seen=true")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("repeated_discovery_score=2")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("query_score=1")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("recon_score=3")));

        let request_debugs: Vec<Value> = debug_values(&debug_log_path)
            .into_iter()
            .filter(|event| event["event"].as_str() == Some("request_received"))
            .collect();
        assert_eq!(request_debugs.len(), 2);
        assert_eq!(request_debugs[1]["fields"]["discovery_request_count"], 2);
        assert_eq!(request_debugs[1]["fields"]["discovery_query_seen"], true);
        assert_eq!(
            request_debugs[1]["fields"]["discovery_legacy_openapi_query_seen"],
            false
        );
        assert_eq!(
            request_debugs[1]["fields"]["discovery_linked_bait_surface_seen"],
            false
        );
        assert_eq!(request_debugs[1]["fields"]["query_present"], false);
        assert_eq!(
            request_debugs[1]["fields"]["discovery_surface_fanout"]["distinct_surfaces"],
            1
        );
        assert_eq!(
            request_debugs[1]["fields"]["discovery_recon_score"]["total"],
            3
        );
        assert_eq!(
            request_debugs[1]["fields"]["discovery_recon_score"]["repeated_discovery_score"],
            2
        );

        let surface_debugs: Vec<Value> = debug_values(&debug_log_path)
            .into_iter()
            .filter(|event| event["event"].as_str() == Some("surface_action_selected"))
            .collect();
        assert_eq!(
            surface_debugs[1]["fields"]["candidate_surface_action"]["type"],
            "eidolon_owned"
        );
        assert_eq!(surface_debugs[1]["fields"]["policy_state"], "suspicious");
    }

    #[test]
    fn runtime_aggregates_medium_score_detection_backed_discovery_to_suspicious() {
        let event_log_path = unique_temp_path("aggregated-detection-suspicious-events.jsonl");
        let debug_log_path = unique_temp_path("aggregated-detection-suspicious-debug.jsonl");
        let original = r#"<!doctype html><html><body><main>docs</main></body></html>"#;
        let (upstream, _upstream_handle) = spawn_upstream(html_response(original));
        let mut runtime = test_runtime_with_m1_controller_and_debug_log(
            upstream,
            &event_log_path,
            &debug_log_path,
            unique_temp_path("aggregated-detection-suspicious-control.txt"),
        );
        runtime.ingress_transport_auth_secret = Some(Arc::<str>::from("edge-secret"));

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &request_with_cookie(
                "GET",
                "/docs?topic=imports",
                &cookie_header(),
                &[
                    (session::INGRESS_ACTOR_KIND_HEADER_NAME, "agentic_browser"),
                    (session::INGRESS_VENDOR_SCORE_HEADER_NAME, "35"),
                    (
                        session::INGRESS_VENDOR_SCORE_KIND_HEADER_NAME,
                        "automation_likelihood_inverse",
                    ),
                    (session::INGRESS_DETECTION_IDS_HEADER_NAME, "3355446,445566"),
                    (session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
                ],
            ),
        ));
        let body = must_ok(String::from_utf8(response.body), "body should be utf8");

        assert_eq!(response.status, 200);
        assert!(body.contains("X-Migration-Trace: rel_2025_04_b7f2"));

        let request_event = first_event_of_type(&event_log_path, "request_seen");
        assert_eq!(request_event["policy_state"], "suspicious");
        assert_eq!(request_event["kind"]["routing_decision"], "eidolon_owned");
        assert_eq!(request_event["kind"]["ingress_signals"]["vendor_score"], 35);
        assert_eq!(
            request_event["kind"]["ingress_signals"]["detection_ids"][0],
            "3355446"
        );
        assert_eq!(
            request_event["kind"]["ingress_signals"]["detection_ids"][1],
            "445566"
        );

        let policy_changed = first_event_of_type(&event_log_path, "policy_changed");
        assert_eq!(policy_changed["kind"]["from"], "observe");
        assert_eq!(policy_changed["kind"]["to"], "suspicious");
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains(
                "multi-signal discovery recon aggregation promoted request to suspicious"
            )));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("discovery_requests=1")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("query_seen=true")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("detection_count=2")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("detection_score=2")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("recon_score=3")));

        let request_debug = first_debug_event(&debug_log_path, "request_received");
        assert_eq!(request_debug["fields"]["policy_state"], "suspicious");
        assert_eq!(request_debug["fields"]["query_present"], true);
        assert_eq!(request_debug["fields"]["discovery_request_count"], 1);
        assert_eq!(request_debug["fields"]["discovery_query_seen"], true);
        assert_eq!(
            request_debug["fields"]["discovery_legacy_openapi_query_seen"],
            false
        );
        assert_eq!(
            request_debug["fields"]["discovery_linked_bait_surface_seen"],
            false
        );
        assert_eq!(
            request_debug["fields"]["ingress_signals"]["detection_ids"][0],
            "3355446"
        );
        assert_eq!(
            request_debug["fields"]["ingress_signals"]["detection_ids"][1],
            "445566"
        );
        assert_eq!(request_debug["fields"]["discovery_recon_score"]["total"], 3);
        assert_eq!(
            request_debug["fields"]["discovery_recon_score"]["detection_score"],
            2
        );

        let surface_debug = first_debug_event(&debug_log_path, "surface_action_selected");
        assert_eq!(
            surface_debug["fields"]["candidate_surface_action"]["type"],
            "eidolon_owned"
        );
        assert_eq!(surface_debug["fields"]["policy_state"], "suspicious");
    }

    #[test]
    fn runtime_rate_limits_suspicious_detection_backed_recon_persistence() {
        let event_log_path = unique_temp_path("aggregated-detection-rate-limit-events.jsonl");
        let debug_log_path = unique_temp_path("aggregated-detection-rate-limit-debug.jsonl");
        let mut runtime = test_runtime_with_m1_controller_and_debug_log(
            closed_upstream(),
            &event_log_path,
            &debug_log_path,
            unique_temp_path("aggregated-detection-rate-limit-control.txt"),
        );
        runtime.ingress_transport_auth_secret = Some(Arc::<str>::from("edge-secret"));
        let cookie = cookie_header();
        let headers = [
            (session::INGRESS_ACTOR_KIND_HEADER_NAME, "agentic_browser"),
            (session::INGRESS_VENDOR_SCORE_HEADER_NAME, "35"),
            (
                session::INGRESS_VENDOR_SCORE_KIND_HEADER_NAME,
                "automation_likelihood_inverse",
            ),
            (session::INGRESS_DETECTION_IDS_HEADER_NAME, "3355446,445566"),
            (session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
        ];

        let first_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &request_with_cookie("GET", "/docs?topic=imports", &cookie, &headers),
        ));
        let second_response = parse_downstream_response(&run_runtime_request(
            runtime,
            &request_with_cookie("GET", "/docs", &cookie, &headers),
        ));

        assert_eq!(first_response.status, 200);
        assert_eq!(second_response.status, 429);
        assert_eq!(header_values(&second_response, "retry-after"), vec!["30"]);

        let request_events = events_of_type(&event_log_path, "request_seen");
        assert_eq!(request_events.len(), 2);
        assert_eq!(request_events[0]["policy_state"], "suspicious");
        assert_eq!(request_events[1]["policy_state"], "rate_limited");
        assert_eq!(
            request_events[1]["kind"]["routing_decision"],
            "rate_limited"
        );
        assert_eq!(
            request_events[1]["kind"]["ingress_signals"]["detection_ids"][0],
            "3355446"
        );
        assert_eq!(
            request_events[1]["kind"]["ingress_signals"]["detection_ids"][1],
            "445566"
        );
        assert_eq!(
            request_events[1]["kind"]["discovery_recon_score"]["repeated_discovery_score"],
            2
        );
        assert_eq!(
            request_events[1]["kind"]["discovery_recon_score"]["query_score"],
            1
        );
        assert_eq!(
            request_events[1]["kind"]["discovery_recon_score"]["detection_score"],
            2
        );
        assert_eq!(
            request_events[1]["kind"]["discovery_recon_score"]["total"],
            5
        );
        assert_eq!(
            request_events[1]["kind"]["discovery_recon_score"]["threshold"],
            5
        );

        let policy_changes = events_of_type(&event_log_path, "policy_changed");
        assert_eq!(policy_changes.len(), 2);
        assert_eq!(policy_changes[0]["kind"]["from"], "observe");
        assert_eq!(policy_changes[0]["kind"]["to"], "suspicious");
        assert_eq!(policy_changes[1]["kind"]["from"], "suspicious");
        assert_eq!(policy_changes[1]["kind"]["to"], "rate_limited");
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason
                .contains("suspicious discovery recon persistence moved session to rate limited")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("path=/docs")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("discovery_requests=2")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("query_seen=true")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("detection_count=2")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("repeated_discovery_score=2")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("query_score=1")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("detection_score=2")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("recon_score=5")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("recon_rate_limit_threshold=5")));
        assert_eq!(
            policy_changes[1]["kind"]["persistence"]["pre_containment_persistence_class"],
            "discovery_recon"
        );

        let request_debugs: Vec<Value> = debug_values(&debug_log_path)
            .into_iter()
            .filter(|event| event["event"].as_str() == Some("request_received"))
            .collect();
        assert_eq!(request_debugs.len(), 2);
        assert_eq!(request_debugs[1]["fields"]["policy_state"], "rate_limited");
        assert_eq!(request_debugs[1]["fields"]["path"], "/docs");
        assert_eq!(request_debugs[1]["fields"]["query_present"], false);
        assert_eq!(request_debugs[1]["fields"]["discovery_request_count"], 2);
        assert_eq!(request_debugs[1]["fields"]["discovery_query_seen"], true);
        assert_eq!(
            request_debugs[1]["fields"]["ingress_signals"]["detection_ids"][0],
            "3355446"
        );
        assert_eq!(
            request_debugs[1]["fields"]["ingress_signals"]["detection_ids"][1],
            "445566"
        );
        assert_eq!(
            request_debugs[1]["fields"]["discovery_recon_score"]["repeated_discovery_score"],
            2
        );
        assert_eq!(
            request_debugs[1]["fields"]["discovery_recon_score"]["query_score"],
            1
        );
        assert_eq!(
            request_debugs[1]["fields"]["discovery_recon_score"]["detection_score"],
            2
        );
        assert_eq!(
            request_debugs[1]["fields"]["discovery_recon_score"]["total"],
            5
        );
        assert_eq!(
            request_debugs[1]["fields"]["discovery_recon_score"]["threshold"],
            5
        );

        let surface_debugs: Vec<Value> = debug_values(&debug_log_path)
            .into_iter()
            .filter(|event| event["event"].as_str() == Some("surface_action_selected"))
            .collect();
        assert_eq!(surface_debugs[1]["fields"]["policy_state"], "rate_limited");
        assert_eq!(
            surface_debugs[1]["fields"]["surface_action"]["type"],
            "rate_limited"
        );
    }

    #[test]
    fn runtime_blocks_after_rate_limited_detection_backed_recon_retry() {
        let event_log_path = unique_temp_path("aggregated-detection-blocked-events.jsonl");
        let debug_log_path = unique_temp_path("aggregated-detection-blocked-debug.jsonl");
        let mut runtime = test_runtime_with_m1_controller_and_debug_log(
            closed_upstream(),
            &event_log_path,
            &debug_log_path,
            unique_temp_path("aggregated-detection-blocked-control.txt"),
        );
        runtime.ingress_transport_auth_secret = Some(Arc::<str>::from("edge-secret"));
        let cookie = cookie_header();
        let headers = [
            (session::INGRESS_ACTOR_KIND_HEADER_NAME, "agentic_browser"),
            (session::INGRESS_VENDOR_SCORE_HEADER_NAME, "35"),
            (
                session::INGRESS_VENDOR_SCORE_KIND_HEADER_NAME,
                "automation_likelihood_inverse",
            ),
            (session::INGRESS_DETECTION_IDS_HEADER_NAME, "3355446,445566"),
            (session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
        ];

        let first_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &request_with_cookie("GET", "/docs?topic=imports", &cookie, &headers),
        ));
        let second_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &request_with_cookie("GET", "/docs", &cookie, &headers),
        ));
        let third_response = parse_downstream_response(&run_runtime_request(
            runtime,
            &request_with_cookie("GET", "/docs", &cookie, &headers),
        ));

        assert_eq!(first_response.status, 200);
        assert_eq!(second_response.status, 429);
        assert_eq!(third_response.status, 403);
        assert_eq!(header_values(&second_response, "retry-after"), vec!["30"]);

        let request_events = events_of_type(&event_log_path, "request_seen");
        assert_eq!(request_events.len(), 3);
        assert_eq!(request_events[0]["policy_state"], "suspicious");
        assert_eq!(request_events[1]["policy_state"], "rate_limited");
        assert_eq!(request_events[2]["policy_state"], "blocked");
        assert_eq!(
            request_events[2]["kind"]["routing_decision"],
            "eidolon_owned"
        );
        assert_eq!(
            request_events[2]["kind"]["ingress_signals"]["detection_ids"][0],
            "3355446"
        );
        assert_eq!(
            request_events[2]["kind"]["ingress_signals"]["detection_ids"][1],
            "445566"
        );
        assert_eq!(
            request_events[2]["kind"]["discovery_recon_score"]["repeated_discovery_score"],
            2
        );
        assert_eq!(
            request_events[2]["kind"]["discovery_recon_score"]["query_score"],
            1
        );
        assert_eq!(
            request_events[2]["kind"]["discovery_recon_score"]["detection_score"],
            2
        );
        assert_eq!(
            request_events[2]["kind"]["discovery_recon_score"]["total"],
            5
        );
        assert_eq!(
            request_events[2]["kind"]["discovery_recon_score"]["threshold"],
            5
        );

        let policy_changes = events_of_type(&event_log_path, "policy_changed");
        assert_eq!(policy_changes.len(), 3);
        assert_eq!(policy_changes[2]["kind"]["from"], "rate_limited");
        assert_eq!(policy_changes[2]["kind"]["to"], "blocked");
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| {
                reason.contains("rate-limited discovery recon retry moved session to blocked")
            }));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("path=/docs")));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("discovery_requests=3")));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("query_seen=true")));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("detection_count=2")));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("repeated_discovery_score=2")));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("query_score=1")));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("detection_score=2")));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("recon_score=5")));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("recon_block_threshold=5")));
        assert_eq!(
            policy_changes[2]["kind"]["persistence"]["pre_containment_persistence_class"],
            "discovery_recon"
        );
        assert_eq!(
            policy_changes[2]["kind"]["persistence"]["pre_containment_persistence_kind"],
            "discovery_recon_retry"
        );

        let request_debugs: Vec<Value> = debug_values(&debug_log_path)
            .into_iter()
            .filter(|event| event["event"].as_str() == Some("request_received"))
            .collect();
        assert_eq!(request_debugs.len(), 3);
        assert_eq!(request_debugs[2]["fields"]["policy_state"], "blocked");
        assert_eq!(request_debugs[2]["fields"]["path"], "/docs");
        assert_eq!(request_debugs[2]["fields"]["query_present"], false);
        assert_eq!(request_debugs[2]["fields"]["discovery_request_count"], 3);
        assert_eq!(request_debugs[2]["fields"]["discovery_query_seen"], true);
        assert_eq!(
            request_debugs[2]["fields"]["ingress_signals"]["detection_ids"][0],
            "3355446"
        );
        assert_eq!(
            request_debugs[2]["fields"]["ingress_signals"]["detection_ids"][1],
            "445566"
        );
        assert_eq!(
            request_debugs[2]["fields"]["discovery_recon_score"]["repeated_discovery_score"],
            2
        );
        assert_eq!(
            request_debugs[2]["fields"]["discovery_recon_score"]["query_score"],
            1
        );
        assert_eq!(
            request_debugs[2]["fields"]["discovery_recon_score"]["detection_score"],
            2
        );
        assert_eq!(
            request_debugs[2]["fields"]["discovery_recon_score"]["total"],
            5
        );
        assert_eq!(
            request_debugs[2]["fields"]["discovery_recon_score"]["threshold"],
            5
        );

        let surface_debugs: Vec<Value> = debug_values(&debug_log_path)
            .into_iter()
            .filter(|event| event["event"].as_str() == Some("surface_action_selected"))
            .collect();
        assert_eq!(surface_debugs[2]["fields"]["policy_state"], "blocked");
        assert!(surface_debugs[2]["fields"]["policy_reason"]
            .as_str()
            .is_some_and(|reason| {
                reason.contains("rate-limited discovery recon retry moved session to blocked")
            }));
        assert!(surface_debugs[2]["fields"]["policy_reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("detection_count=2")));
        assert!(surface_debugs[2]["fields"]["policy_reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("detection_score=2")));
        assert_eq!(
            surface_debugs[2]["fields"]["surface_action"]["type"],
            "eidolon_owned"
        );
    }

    #[test]
    fn runtime_aggregates_medium_score_legacy_openapi_query_to_suspicious() {
        let event_log_path = unique_temp_path("aggregated-openapi-suspicious-events.jsonl");
        let debug_log_path = unique_temp_path("aggregated-openapi-suspicious-debug.jsonl");
        let original = r#"{"openapi":"3.0.3","info":{"title":"demo","version":"0"},"paths":{}}"#;
        let (upstream, _upstream_handle) = spawn_upstream(json_response(original));
        let mut runtime = test_runtime_with_m1_controller_and_debug_log(
            upstream,
            &event_log_path,
            &debug_log_path,
            unique_temp_path("aggregated-openapi-suspicious-control.txt"),
        );
        runtime.ingress_transport_auth_secret = Some(Arc::<str>::from("edge-secret"));

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &request_with_cookie(
                "GET",
                "/openapi.json?eidolon_surface=legacy-import",
                &cookie_header(),
                &[
                    (session::INGRESS_ACTOR_KIND_HEADER_NAME, "agentic_browser"),
                    (session::INGRESS_VENDOR_SCORE_HEADER_NAME, "35"),
                    (
                        session::INGRESS_VENDOR_SCORE_KIND_HEADER_NAME,
                        "automation_likelihood_inverse",
                    ),
                    (session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
                ],
            ),
        ));
        let body = must_ok(String::from_utf8(response.body), "body should be utf8");

        assert_eq!(response.status, 200);
        assert!(body.contains("X-OpenAPI-Trace"));
        assert!(body.contains("/api/v2/import/reconcile"));

        let request_event = first_event_of_type(&event_log_path, "request_seen");
        assert_eq!(request_event["policy_state"], "suspicious");
        assert_eq!(request_event["kind"]["routing_decision"], "eidolon_owned");
        assert_eq!(request_event["kind"]["ingress_signals"]["vendor_score"], 35);

        let policy_changed = first_event_of_type(&event_log_path, "policy_changed");
        assert_eq!(policy_changed["kind"]["from"], "observe");
        assert_eq!(policy_changed["kind"]["to"], "suspicious");
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains(
                "multi-signal discovery recon aggregation promoted request to suspicious"
            )));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("discovery_requests=1")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("query_seen=true")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("legacy_openapi_query_seen=true")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("linked_bait_surface_seen=false")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("detection_count=0")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("legacy_openapi_query_score=2")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("recon_score=3")));

        let request_debug = first_debug_event(&debug_log_path, "request_received");
        assert_eq!(request_debug["fields"]["policy_state"], "suspicious");
        assert_eq!(request_debug["fields"]["path"], "/openapi.json");
        assert_eq!(request_debug["fields"]["query_present"], true);
        assert_eq!(request_debug["fields"]["discovery_request_count"], 1);
        assert_eq!(request_debug["fields"]["discovery_query_seen"], true);
        assert_eq!(
            request_debug["fields"]["discovery_legacy_openapi_query_seen"],
            true
        );
        assert_eq!(
            request_debug["fields"]["discovery_linked_bait_surface_seen"],
            false
        );
        assert_eq!(request_debug["fields"]["discovery_recon_score"]["total"], 3);
        assert_eq!(
            request_debug["fields"]["discovery_recon_score"]["legacy_openapi_query_score"],
            2
        );

        let surface_debug = first_debug_event(&debug_log_path, "surface_action_selected");
        assert_eq!(
            surface_debug["fields"]["candidate_surface_action"]["type"],
            "eidolon_owned"
        );
        assert_eq!(surface_debug["fields"]["policy_state"], "suspicious");

        let bait_exposed = first_event_of_type(&event_log_path, "bait_exposed");
        assert_eq!(bait_exposed["kind"]["bait_id"], "openapi_reconcile_trace");
        assert_eq!(bait_exposed["kind"]["surface"], "/openapi.json");
    }

    #[test]
    fn runtime_aggregates_medium_score_blind_decoy_write_probe_to_suspicious_without_bait_attribution(
    ) {
        let event_log_path = unique_temp_path("aggregated-decoy-write-suspicious-events.jsonl");
        let debug_log_path = unique_temp_path("aggregated-decoy-write-suspicious-debug.jsonl");
        let original = r#"<!doctype html><html><body><main>docs</main></body></html>"#;
        let (upstream, _upstream_handle) =
            spawn_upstream_sequence([html_response(original), html_response(original)]);
        let mut runtime = test_runtime_with_m1_controller_and_debug_log(
            upstream,
            &event_log_path,
            &debug_log_path,
            unique_temp_path("aggregated-decoy-write-suspicious-control.txt"),
        );
        runtime.ingress_transport_auth_secret = Some(Arc::<str>::from("edge-secret"));
        let cookie = cookie_header();
        let headers = [
            (session::INGRESS_ACTOR_KIND_HEADER_NAME, "agentic_browser"),
            (session::INGRESS_VENDOR_SCORE_HEADER_NAME, "35"),
            (
                session::INGRESS_VENDOR_SCORE_KIND_HEADER_NAME,
                "automation_likelihood_inverse",
            ),
            (session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
        ];

        let first_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &request_with_cookie("GET", "/docs?topic=imports", &cookie, &headers),
        ));
        let second_response = parse_downstream_response(&run_runtime_request(
            runtime,
            &post_request_with_cookie("/api/v2/import/reconcile", &cookie, &headers),
        ));

        assert_eq!(first_response.status, 200);
        assert_eq!(second_response.status, 202);

        let request_events = events_of_type(&event_log_path, "request_seen");
        assert_eq!(request_events.len(), 2);
        assert_eq!(request_events[0]["policy_state"], "observe");
        assert_eq!(
            request_events[0]["kind"]["routing_decision"],
            "protected_upstream"
        );
        assert_eq!(request_events[1]["policy_state"], "suspicious");
        assert_eq!(
            request_events[1]["kind"]["routing_decision"],
            "eidolon_owned"
        );
        assert_eq!(
            request_events[1]["kind"]["discovery_recon_score"]["decoy_write_probe_score"],
            2
        );
        assert_eq!(
            request_events[1]["kind"]["discovery_recon_score"]["total"],
            3
        );
        assert_eq!(
            request_events[1]["kind"]["discovery_recon_score"]["threshold"],
            3
        );

        let policy_changed = first_event_of_type(&event_log_path, "policy_changed");
        assert_eq!(policy_changed["kind"]["from"], "observe");
        assert_eq!(policy_changed["kind"]["to"], "suspicious");
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains(
                "multi-signal discovery recon aggregation promoted request to suspicious"
            )));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("path=/api/v2/import/reconcile")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("query_seen=true")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("decoy_write_probe_seen=true")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("decoy_write_probe_score=2")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("recon_score=3")));

        assert_event_type_absent(&event_log_path, "bait_action_observed");

        let request_debugs: Vec<Value> = debug_values(&debug_log_path)
            .into_iter()
            .filter(|event| event["event"].as_str() == Some("request_received"))
            .collect();
        assert_eq!(request_debugs.len(), 2);
        assert_eq!(
            request_debugs[1]["fields"]["path"],
            "/api/v2/import/reconcile"
        );
        assert_eq!(request_debugs[1]["fields"]["query_present"], false);
        assert_eq!(request_debugs[1]["fields"]["discovery_request_count"], 1);
        assert_eq!(request_debugs[1]["fields"]["discovery_query_seen"], true);
        assert_eq!(
            request_debugs[1]["fields"]["discovery_decoy_write_probe_seen"],
            true
        );
        assert_eq!(
            request_debugs[1]["fields"]["discovery_decoy_write_probe_count"],
            1
        );
        assert_eq!(
            request_debugs[1]["fields"]["discovery_recon_score"]["decoy_write_probe_score"],
            2
        );
        assert_eq!(
            request_debugs[1]["fields"]["discovery_recon_score"]["total"],
            3
        );
    }

    #[test]
    fn runtime_aggregates_medium_score_blind_probe_on_alternate_write_path_to_suspicious() {
        let path = write_bait_profile(alternate_write_probe_profile_json());
        let loaded = load_bait_profile(&path).expect("alternate write profile should load");
        let event_log_path = unique_temp_path("aggregated-alt-write-suspicious-events.jsonl");
        let original = r#"<!doctype html><html><body><main>docs</main></body></html>"#;
        let (upstream, _upstream_handle) = spawn_upstream_sequence([
            html_response(original),
            json_response(r#"{"mode":"validate"}"#),
        ]);
        let mut runtime = test_runtime_with_bait_profile(
            upstream,
            &event_log_path,
            unique_temp_path("aggregated-alt-write-suspicious-control.txt"),
            loaded,
            None,
        );
        runtime.ingress_transport_auth_secret = Some(Arc::<str>::from("edge-secret"));
        let cookie = cookie_header();
        let headers = [
            (session::INGRESS_ACTOR_KIND_HEADER_NAME, "agentic_browser"),
            (session::INGRESS_VENDOR_SCORE_HEADER_NAME, "35"),
            (
                session::INGRESS_VENDOR_SCORE_KIND_HEADER_NAME,
                "automation_likelihood_inverse",
            ),
            (session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
        ];

        let first_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &request_with_cookie("GET", "/docs?topic=imports", &cookie, &headers),
        ));
        let second_response = parse_downstream_response(&run_runtime_request(
            runtime,
            &post_request_with_cookie("/api/v2/import/validate", &cookie, &headers),
        ));

        let first_body = must_ok(
            String::from_utf8(first_response.body),
            "body should be utf8",
        );

        assert_eq!(first_response.status, 200);
        assert!(first_body.contains("/docs/import-validate"));
        assert_eq!(second_response.status, 202);

        let request_events = events_of_type(&event_log_path, "request_seen");
        assert_eq!(request_events.len(), 2);
        assert_eq!(request_events[0]["policy_state"], "observe");
        assert_eq!(
            request_events[0]["kind"]["routing_decision"],
            "protected_upstream"
        );
        assert_eq!(request_events[1]["policy_state"], "suspicious");
        assert_eq!(request_events[1]["kind"]["path"], "/api/v2/import/validate");
        assert_eq!(
            request_events[1]["kind"]["routing_decision"],
            "eidolon_owned"
        );
        assert_eq!(
            request_events[1]["kind"]["discovery_recon_score"]["query_score"],
            1
        );
        assert_eq!(
            request_events[1]["kind"]["discovery_recon_score"]["decoy_write_probe_score"],
            2
        );
        assert_eq!(
            request_events[1]["kind"]["discovery_recon_score"]["total"],
            3
        );
        assert_eq!(
            request_events[1]["kind"]["discovery_recon_score"]["threshold"],
            3
        );

        let policy_changed = first_event_of_type(&event_log_path, "policy_changed");
        assert_eq!(policy_changed["kind"]["from"], "observe");
        assert_eq!(policy_changed["kind"]["to"], "suspicious");
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("path=/api/v2/import/validate")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("decoy_write_probe_seen=true")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("decoy_write_probe_count=1")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("decoy_write_probe_score=2")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("recon_score=3")));

        assert_event_type_absent(&event_log_path, "bait_action_observed");
    }

    #[test]
    fn runtime_repeated_blind_decoy_write_probes_add_a_capped_bonus_without_bait_attribution() {
        let event_log_path = unique_temp_path("aggregated-decoy-write-repeat-bonus-events.jsonl");
        let debug_log_path = unique_temp_path("aggregated-decoy-write-repeat-bonus-debug.jsonl");
        let original = r#"<!doctype html><html><body><main>docs</main></body></html>"#;
        let (upstream, _upstream_handle) = spawn_upstream_sequence([
            html_response(original),
            json_response(r#"{"mode":"upstream"}"#),
            json_response(r#"{"mode":"upstream"}"#),
        ]);
        let mut runtime = test_runtime_with_m1_controller_and_debug_log(
            upstream,
            &event_log_path,
            &debug_log_path,
            unique_temp_path("aggregated-decoy-write-repeat-bonus-control.txt"),
        );
        runtime.ingress_transport_auth_secret = Some(Arc::<str>::from("edge-secret"));
        let cookie = cookie_header();
        let headers = [
            (session::INGRESS_ACTOR_KIND_HEADER_NAME, "agentic_browser"),
            (session::INGRESS_VENDOR_SCORE_HEADER_NAME, "35"),
            (
                session::INGRESS_VENDOR_SCORE_KIND_HEADER_NAME,
                "automation_likelihood_inverse",
            ),
            (session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
        ];

        let first_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &request_with_cookie("GET", "/docs?topic=imports", &cookie, &headers),
        ));
        let second_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &post_request_with_cookie("/api/v2/import/reconcile", &cookie, &headers),
        ));
        let third_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &post_request_with_cookie("/api/v2/import/reconcile", &cookie, &headers),
        ));
        let fourth_response = parse_downstream_response(&run_runtime_request(
            runtime,
            &request_with_cookie("GET", "/docs", &cookie, &headers),
        ));

        assert_eq!(first_response.status, 200);
        assert_eq!(second_response.status, 202);
        assert_eq!(third_response.status, 202);
        assert_eq!(fourth_response.status, 429);
        assert_eq!(header_values(&fourth_response, "retry-after"), vec!["30"]);

        let request_events = events_of_type(&event_log_path, "request_seen");
        assert_eq!(request_events.len(), 4);
        assert_eq!(request_events[0]["policy_state"], "observe");
        assert_eq!(
            request_events[0]["kind"]["routing_decision"],
            "protected_upstream"
        );
        assert_eq!(request_events[1]["policy_state"], "suspicious");
        assert_eq!(
            request_events[1]["kind"]["routing_decision"],
            "eidolon_owned"
        );
        assert_eq!(
            request_events[1]["kind"]["discovery_recon_score"]["decoy_write_probe_score"],
            2
        );
        assert_eq!(
            request_events[1]["kind"]["discovery_recon_score"]["total"],
            3
        );
        assert_eq!(request_events[2]["policy_state"], "suspicious");
        assert_eq!(
            request_events[2]["kind"]["routing_decision"],
            "eidolon_owned"
        );
        assert_eq!(
            request_events[2]["kind"]["discovery_recon_score"]["query_score"],
            1
        );
        assert_eq!(
            request_events[2]["kind"]["discovery_recon_score"]["decoy_write_probe_score"],
            3
        );
        assert_eq!(
            request_events[2]["kind"]["discovery_recon_score"]["total"],
            4
        );
        assert_eq!(
            request_events[2]["kind"]["discovery_recon_score"]["threshold"],
            3
        );
        assert_eq!(request_events[3]["policy_state"], "rate_limited");
        assert_eq!(
            request_events[3]["kind"]["routing_decision"],
            "rate_limited"
        );
        assert_eq!(
            request_events[3]["kind"]["discovery_recon_score"]["repeated_discovery_score"],
            2
        );
        assert_eq!(
            request_events[3]["kind"]["discovery_recon_score"]["query_score"],
            1
        );
        assert_eq!(
            request_events[3]["kind"]["discovery_recon_score"]["decoy_write_probe_score"],
            3
        );
        assert_eq!(
            request_events[3]["kind"]["discovery_recon_score"]["total"],
            6
        );
        assert_eq!(
            request_events[3]["kind"]["discovery_recon_score"]["threshold"],
            5
        );

        let policy_changes = events_of_type(&event_log_path, "policy_changed");
        assert_eq!(policy_changes.len(), 2);
        assert_eq!(policy_changes[0]["kind"]["from"], "observe");
        assert_eq!(policy_changes[0]["kind"]["to"], "suspicious");
        assert!(policy_changes[0]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("decoy_write_probe_count=1")));
        assert!(policy_changes[0]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("decoy_write_probe_score=2")));
        assert_eq!(policy_changes[1]["kind"]["from"], "suspicious");
        assert_eq!(policy_changes[1]["kind"]["to"], "rate_limited");
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("decoy_write_probe_count=2")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("decoy_write_probe_score=3")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("recon_score=6")));

        assert_event_type_absent(&event_log_path, "bait_action_observed");

        let request_debugs: Vec<Value> = debug_values(&debug_log_path)
            .into_iter()
            .filter(|event| event["event"].as_str() == Some("request_received"))
            .collect();
        assert_eq!(request_debugs.len(), 4);
        assert_eq!(
            request_debugs[1]["fields"]["discovery_decoy_write_probe_count"],
            1
        );
        assert_eq!(
            request_debugs[2]["fields"]["path"],
            "/api/v2/import/reconcile"
        );
        assert_eq!(
            request_debugs[2]["fields"]["discovery_decoy_write_probe_seen"],
            true
        );
        assert_eq!(
            request_debugs[2]["fields"]["discovery_decoy_write_probe_count"],
            2
        );
        assert_eq!(
            request_debugs[2]["fields"]["discovery_recon_score"]["decoy_write_probe_score"],
            3
        );
        assert_eq!(
            request_debugs[2]["fields"]["discovery_recon_score"]["total"],
            4
        );
        assert_eq!(request_debugs[3]["fields"]["policy_state"], "rate_limited");
        assert_eq!(request_debugs[3]["fields"]["path"], "/docs");
        assert_eq!(
            request_debugs[3]["fields"]["discovery_decoy_write_probe_count"],
            2
        );
        assert_eq!(
            request_debugs[3]["fields"]["discovery_recon_score"]["decoy_write_probe_score"],
            3
        );
        assert_eq!(
            request_debugs[3]["fields"]["discovery_recon_score"]["total"],
            6
        );
        assert_eq!(
            request_debugs[3]["fields"]["discovery_recon_score"]["threshold"],
            5
        );
    }

    #[test]
    fn runtime_rate_limits_suspicious_legacy_openapi_recon_persistence() {
        let event_log_path = unique_temp_path("aggregated-openapi-rate-limit-events.jsonl");
        let debug_log_path = unique_temp_path("aggregated-openapi-rate-limit-debug.jsonl");
        let mut runtime = test_runtime_with_m1_controller_and_debug_log(
            closed_upstream(),
            &event_log_path,
            &debug_log_path,
            unique_temp_path("aggregated-openapi-rate-limit-control.txt"),
        );
        runtime.ingress_transport_auth_secret = Some(Arc::<str>::from("edge-secret"));
        let cookie = cookie_header();
        let headers = [
            (session::INGRESS_ACTOR_KIND_HEADER_NAME, "agentic_browser"),
            (session::INGRESS_VENDOR_SCORE_HEADER_NAME, "35"),
            (
                session::INGRESS_VENDOR_SCORE_KIND_HEADER_NAME,
                "automation_likelihood_inverse",
            ),
            (session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
        ];

        let first_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &request_with_cookie(
                "GET",
                "/openapi.json?eidolon_surface=legacy-import",
                &cookie,
                &headers,
            ),
        ));
        let second_response = parse_downstream_response(&run_runtime_request(
            runtime,
            &request_with_cookie("GET", "/docs", &cookie, &headers),
        ));

        assert_eq!(first_response.status, 200);
        assert_eq!(second_response.status, 429);
        assert_eq!(header_values(&second_response, "retry-after"), vec!["30"]);

        let request_events = events_of_type(&event_log_path, "request_seen");
        assert_eq!(request_events.len(), 2);
        assert_eq!(request_events[0]["policy_state"], "suspicious");
        assert_eq!(
            request_events[0]["kind"]["routing_decision"],
            "eidolon_owned"
        );
        assert_eq!(request_events[1]["policy_state"], "rate_limited");
        assert_eq!(
            request_events[1]["kind"]["routing_decision"],
            "rate_limited"
        );
        assert_eq!(
            request_events[1]["kind"]["discovery_recon_score"]["threshold"],
            5
        );

        let policy_changes = events_of_type(&event_log_path, "policy_changed");
        assert_eq!(policy_changes.len(), 2);
        assert_eq!(policy_changes[0]["kind"]["from"], "observe");
        assert_eq!(policy_changes[0]["kind"]["to"], "suspicious");
        assert_eq!(policy_changes[1]["kind"]["from"], "suspicious");
        assert_eq!(policy_changes[1]["kind"]["to"], "rate_limited");
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason
                .contains("suspicious discovery recon persistence moved session to rate limited")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("path=/docs")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("discovery_requests=2")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("distinct_surfaces=2")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("query_seen=true")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("legacy_openapi_query_seen=true")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("repeated_discovery_score=2")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("query_score=1")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("legacy_openapi_query_score=2")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("recon_score=5")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("recon_rate_limit_threshold=5")));
        assert_eq!(
            policy_changes[1]["kind"]["persistence"]["pre_containment_persistence_class"],
            "discovery_recon"
        );

        let request_debugs: Vec<Value> = debug_values(&debug_log_path)
            .into_iter()
            .filter(|event| event["event"].as_str() == Some("request_received"))
            .collect();
        assert_eq!(request_debugs.len(), 2);
        assert_eq!(request_debugs[1]["fields"]["policy_state"], "rate_limited");
        assert_eq!(request_debugs[1]["fields"]["path"], "/docs");
        assert_eq!(request_debugs[1]["fields"]["query_present"], false);
        assert_eq!(request_debugs[1]["fields"]["discovery_request_count"], 2);
        assert_eq!(request_debugs[1]["fields"]["discovery_query_seen"], true);
        assert_eq!(
            request_debugs[1]["fields"]["discovery_legacy_openapi_query_seen"],
            true
        );
        assert_eq!(
            request_debugs[1]["fields"]["discovery_surface_fanout"]["distinct_surfaces"],
            2
        );
        assert_eq!(
            request_debugs[1]["fields"]["discovery_recon_score"]["repeated_discovery_score"],
            2
        );
        assert_eq!(
            request_debugs[1]["fields"]["discovery_recon_score"]["query_score"],
            1
        );
        assert_eq!(
            request_debugs[1]["fields"]["discovery_recon_score"]["legacy_openapi_query_score"],
            2
        );
        assert_eq!(
            request_debugs[1]["fields"]["discovery_recon_score"]["total"],
            5
        );
        assert_eq!(
            request_debugs[1]["fields"]["discovery_recon_score"]["threshold"],
            5
        );

        let surface_debugs: Vec<Value> = debug_values(&debug_log_path)
            .into_iter()
            .filter(|event| event["event"].as_str() == Some("surface_action_selected"))
            .collect();
        assert_eq!(surface_debugs[1]["fields"]["policy_state"], "rate_limited");
        assert_eq!(
            surface_debugs[1]["fields"]["surface_action"]["type"],
            "rate_limited"
        );
    }

    #[test]
    fn runtime_rate_limits_suspicious_recon_persistence_after_blind_decoy_write_probe() {
        let event_log_path = unique_temp_path("aggregated-decoy-write-rate-limit-events.jsonl");
        let debug_log_path = unique_temp_path("aggregated-decoy-write-rate-limit-debug.jsonl");
        let original = r#"<!doctype html><html><body><main>docs</main></body></html>"#;
        let (upstream, _upstream_handle) = spawn_upstream_sequence([
            html_response(original),
            json_response(r#"{"mode":"upstream"}"#),
        ]);
        let mut runtime = test_runtime_with_m1_controller_and_debug_log(
            upstream,
            &event_log_path,
            &debug_log_path,
            unique_temp_path("aggregated-decoy-write-rate-limit-control.txt"),
        );
        runtime.ingress_transport_auth_secret = Some(Arc::<str>::from("edge-secret"));
        let cookie = cookie_header();
        let headers = [
            (session::INGRESS_ACTOR_KIND_HEADER_NAME, "agentic_browser"),
            (session::INGRESS_VENDOR_SCORE_HEADER_NAME, "35"),
            (
                session::INGRESS_VENDOR_SCORE_KIND_HEADER_NAME,
                "automation_likelihood_inverse",
            ),
            (session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
        ];

        let first_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &request_with_cookie("GET", "/docs?topic=imports", &cookie, &headers),
        ));
        let second_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &post_request_with_cookie("/api/v2/import/reconcile", &cookie, &headers),
        ));
        let third_response = parse_downstream_response(&run_runtime_request(
            runtime,
            &request_with_cookie("GET", "/docs", &cookie, &headers),
        ));

        assert_eq!(first_response.status, 200);
        assert_eq!(second_response.status, 202);
        assert_eq!(third_response.status, 429);
        assert_eq!(header_values(&third_response, "retry-after"), vec!["30"]);

        let request_events = events_of_type(&event_log_path, "request_seen");
        assert_eq!(request_events.len(), 3);
        assert_eq!(request_events[0]["policy_state"], "observe");
        assert_eq!(
            request_events[0]["kind"]["routing_decision"],
            "protected_upstream"
        );
        assert_eq!(request_events[1]["policy_state"], "suspicious");
        assert_eq!(
            request_events[1]["kind"]["routing_decision"],
            "eidolon_owned"
        );
        assert_eq!(
            request_events[1]["kind"]["discovery_recon_score"]["decoy_write_probe_score"],
            2
        );
        assert_eq!(request_events[2]["policy_state"], "rate_limited");
        assert_eq!(
            request_events[2]["kind"]["routing_decision"],
            "rate_limited"
        );
        assert_eq!(
            request_events[2]["kind"]["discovery_recon_score"]["repeated_discovery_score"],
            2
        );
        assert_eq!(
            request_events[2]["kind"]["discovery_recon_score"]["query_score"],
            1
        );
        assert_eq!(
            request_events[2]["kind"]["discovery_recon_score"]["decoy_write_probe_score"],
            2
        );
        assert_eq!(
            request_events[2]["kind"]["discovery_recon_score"]["total"],
            5
        );
        assert_eq!(
            request_events[2]["kind"]["discovery_recon_score"]["threshold"],
            5
        );

        let policy_changes = events_of_type(&event_log_path, "policy_changed");
        assert_eq!(policy_changes.len(), 2);
        assert_eq!(policy_changes[0]["kind"]["from"], "observe");
        assert_eq!(policy_changes[0]["kind"]["to"], "suspicious");
        assert_eq!(policy_changes[1]["kind"]["from"], "suspicious");
        assert_eq!(policy_changes[1]["kind"]["to"], "rate_limited");
        assert!(policy_changes[0]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("decoy_write_probe_seen=true")));
        assert!(policy_changes[0]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("decoy_write_probe_score=2")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason
                .contains("suspicious discovery recon persistence moved session to rate limited")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("path=/docs")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("discovery_requests=2")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("query_seen=true")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("decoy_write_probe_seen=true")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("repeated_discovery_score=2")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("query_score=1")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("decoy_write_probe_score=2")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("recon_score=5")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("recon_rate_limit_threshold=5")));
        assert_eq!(
            policy_changes[1]["kind"]["persistence"]["pre_containment_persistence_class"],
            "discovery_recon"
        );

        assert_event_type_absent(&event_log_path, "bait_action_observed");

        let request_debugs: Vec<Value> = debug_values(&debug_log_path)
            .into_iter()
            .filter(|event| event["event"].as_str() == Some("request_received"))
            .collect();
        assert_eq!(request_debugs.len(), 3);
        assert_eq!(request_debugs[2]["fields"]["policy_state"], "rate_limited");
        assert_eq!(request_debugs[2]["fields"]["path"], "/docs");
        assert_eq!(request_debugs[2]["fields"]["query_present"], false);
        assert_eq!(request_debugs[2]["fields"]["discovery_request_count"], 2);
        assert_eq!(request_debugs[2]["fields"]["discovery_query_seen"], true);
        assert_eq!(
            request_debugs[2]["fields"]["discovery_decoy_write_probe_seen"],
            true
        );
        assert_eq!(
            request_debugs[2]["fields"]["discovery_recon_score"]["repeated_discovery_score"],
            2
        );
        assert_eq!(
            request_debugs[2]["fields"]["discovery_recon_score"]["query_score"],
            1
        );
        assert_eq!(
            request_debugs[2]["fields"]["discovery_recon_score"]["decoy_write_probe_score"],
            2
        );
        assert_eq!(
            request_debugs[2]["fields"]["discovery_recon_score"]["total"],
            5
        );
        assert_eq!(
            request_debugs[2]["fields"]["discovery_recon_score"]["threshold"],
            5
        );

        let surface_debugs: Vec<Value> = debug_values(&debug_log_path)
            .into_iter()
            .filter(|event| event["event"].as_str() == Some("surface_action_selected"))
            .collect();
        assert_eq!(surface_debugs[2]["fields"]["policy_state"], "rate_limited");
        assert_eq!(
            surface_debugs[2]["fields"]["surface_action"]["type"],
            "rate_limited"
        );
    }

    #[test]
    fn runtime_rate_limits_suspicious_recon_on_second_distinct_blind_write_probe() {
        let path = write_bait_profile(fanout_write_probe_profile_json());
        let loaded = load_bait_profile(&path).expect("fanout write profile should load");
        let event_log_path =
            unique_temp_path("aggregated-decoy-write-fanout-rate-limit-events.jsonl");
        let debug_log_path =
            unique_temp_path("aggregated-decoy-write-fanout-rate-limit-debug.jsonl");
        let original = r#"<!doctype html><html><body><main>docs</main></body></html>"#;
        let (upstream, _upstream_handle) = spawn_upstream_sequence([
            html_response(original),
            json_response(r#"{"mode":"reconcile"}"#),
        ]);
        let mut runtime = test_runtime_with_bait_profile(
            upstream,
            &event_log_path,
            unique_temp_path("aggregated-decoy-write-fanout-rate-limit-control.txt"),
            loaded,
            None,
        );
        runtime.debug_log = Some(Arc::new(Mutex::new(
            FileDebugLogWriter::open(&debug_log_path).expect("debug log should open"),
        )));
        runtime.ingress_transport_auth_secret = Some(Arc::<str>::from("edge-secret"));
        let cookie = cookie_header();
        let headers = [
            (session::INGRESS_ACTOR_KIND_HEADER_NAME, "agentic_browser"),
            (session::INGRESS_VENDOR_SCORE_HEADER_NAME, "35"),
            (
                session::INGRESS_VENDOR_SCORE_KIND_HEADER_NAME,
                "automation_likelihood_inverse",
            ),
            (session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
        ];

        let first_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &request_with_cookie("GET", "/docs?topic=imports", &cookie, &headers),
        ));
        let second_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &post_request_with_cookie("/api/v2/import/reconcile", &cookie, &headers),
        ));
        let third_response = parse_downstream_response(&run_runtime_request(
            runtime,
            &post_request_with_cookie("/api/v2/import/validate", &cookie, &headers),
        ));

        assert_eq!(first_response.status, 200);
        assert_eq!(second_response.status, 202);
        assert_eq!(third_response.status, 429);
        assert_eq!(header_values(&third_response, "retry-after"), vec!["30"]);

        let request_events = events_of_type(&event_log_path, "request_seen");
        assert_eq!(request_events.len(), 3);
        assert_eq!(request_events[1]["policy_state"], "suspicious");
        assert_eq!(
            request_events[1]["kind"]["routing_decision"],
            "eidolon_owned"
        );
        assert_eq!(request_events[2]["policy_state"], "rate_limited");
        assert_eq!(request_events[2]["kind"]["path"], "/api/v2/import/validate");
        assert_eq!(
            request_events[2]["kind"]["routing_decision"],
            "rate_limited"
        );
        assert_eq!(
            request_events[2]["kind"]["discovery_recon_score"]["repeated_discovery_score"],
            Value::Null
        );
        assert_eq!(
            request_events[2]["kind"]["discovery_recon_score"]["query_score"],
            1
        );
        assert_eq!(
            request_events[2]["kind"]["discovery_recon_score"]["decoy_write_probe_score"],
            3
        );
        assert_eq!(
            request_events[2]["kind"]["discovery_recon_score"]
                ["decoy_write_probe_path_fanout_bonus"],
            1
        );
        assert_eq!(
            request_events[2]["kind"]["discovery_recon_score"]["total"],
            5
        );
        assert_eq!(
            request_events[2]["kind"]["discovery_recon_score"]["threshold"],
            5
        );

        let policy_changes = events_of_type(&event_log_path, "policy_changed");
        assert_eq!(policy_changes.len(), 2);
        assert_eq!(policy_changes[0]["kind"]["from"], "observe");
        assert_eq!(policy_changes[0]["kind"]["to"], "suspicious");
        assert_eq!(policy_changes[1]["kind"]["from"], "suspicious");
        assert_eq!(policy_changes[1]["kind"]["to"], "rate_limited");
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("path=/api/v2/import/validate")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("query_seen=true")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("decoy_write_probe_count=2")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("decoy_write_probe_path_classes=2")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("repeated_discovery_score=0")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("decoy_write_probe_score=3")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("decoy_write_probe_path_fanout_bonus=1")));
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("recon_score=5")));

        assert_event_type_absent(&event_log_path, "bait_action_observed");

        let request_debugs: Vec<Value> = debug_values(&debug_log_path)
            .into_iter()
            .filter(|event| event["event"].as_str() == Some("request_received"))
            .collect();
        assert_eq!(request_debugs.len(), 3);
        assert_eq!(request_debugs[2]["fields"]["policy_state"], "rate_limited");
        assert_eq!(
            request_debugs[2]["fields"]["path"],
            "/api/v2/import/validate"
        );
        assert_eq!(request_debugs[2]["fields"]["query_present"], false);
        assert_eq!(request_debugs[2]["fields"]["discovery_request_count"], 1);
        assert_eq!(request_debugs[2]["fields"]["discovery_query_seen"], true);
        assert_eq!(
            request_debugs[2]["fields"]["discovery_decoy_write_probe_count"],
            2
        );
        assert_eq!(
            request_debugs[2]["fields"]["discovery_decoy_write_probe_path_classes"],
            2
        );
        assert_eq!(
            request_debugs[2]["fields"]["discovery_recon_score"]["repeated_discovery_score"],
            0
        );
        assert_eq!(
            request_debugs[2]["fields"]["discovery_recon_score"]["query_score"],
            1
        );
        assert_eq!(
            request_debugs[2]["fields"]["discovery_recon_score"]["decoy_write_probe_score"],
            3
        );
        assert_eq!(
            request_debugs[2]["fields"]["discovery_recon_score"]
                ["decoy_write_probe_path_fanout_bonus"],
            1
        );
        assert_eq!(
            request_debugs[2]["fields"]["discovery_recon_score"]["total"],
            5
        );
        assert_eq!(
            request_debugs[2]["fields"]["discovery_recon_score"]["threshold"],
            5
        );

        let surface_debugs: Vec<Value> = debug_values(&debug_log_path)
            .into_iter()
            .filter(|event| event["event"].as_str() == Some("surface_action_selected"))
            .collect();
        assert_eq!(surface_debugs[2]["fields"]["policy_state"], "rate_limited");
        assert_eq!(
            surface_debugs[2]["fields"]["surface_action"]["type"],
            "rate_limited"
        );
    }

    #[test]
    fn runtime_blocks_after_rate_limited_decoy_write_recon_retry() {
        let event_log_path = unique_temp_path("aggregated-decoy-write-recon-blocked-events.jsonl");
        let debug_log_path = unique_temp_path("aggregated-decoy-write-recon-blocked-debug.jsonl");
        let original = r#"<!doctype html><html><body><main>docs</main></body></html>"#;
        let (upstream, _upstream_handle) = spawn_upstream_sequence([
            html_response(original),
            json_response(r#"{"mode":"upstream"}"#),
        ]);
        let mut runtime = test_runtime_with_m1_controller_and_debug_log(
            upstream,
            &event_log_path,
            &debug_log_path,
            unique_temp_path("aggregated-decoy-write-recon-blocked-control.txt"),
        );
        runtime.ingress_transport_auth_secret = Some(Arc::<str>::from("edge-secret"));
        let cookie = cookie_header();
        let headers = [
            (session::INGRESS_ACTOR_KIND_HEADER_NAME, "agentic_browser"),
            (session::INGRESS_VENDOR_SCORE_HEADER_NAME, "35"),
            (
                session::INGRESS_VENDOR_SCORE_KIND_HEADER_NAME,
                "automation_likelihood_inverse",
            ),
            (session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
        ];

        let first_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &request_with_cookie("GET", "/docs?topic=imports", &cookie, &headers),
        ));
        let second_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &post_request_with_cookie("/api/v2/import/reconcile", &cookie, &headers),
        ));
        let third_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &request_with_cookie("GET", "/docs", &cookie, &headers),
        ));
        let fourth_response = parse_downstream_response(&run_runtime_request(
            runtime,
            &request_with_cookie("GET", "/docs", &cookie, &headers),
        ));

        assert_eq!(first_response.status, 200);
        assert_eq!(second_response.status, 202);
        assert_eq!(third_response.status, 429);
        assert_eq!(fourth_response.status, 403);
        assert_eq!(header_values(&third_response, "retry-after"), vec!["30"]);

        let request_events = events_of_type(&event_log_path, "request_seen");
        assert_eq!(request_events.len(), 4);
        assert_eq!(request_events[0]["policy_state"], "observe");
        assert_eq!(
            request_events[0]["kind"]["routing_decision"],
            "protected_upstream"
        );
        assert_eq!(request_events[1]["policy_state"], "suspicious");
        assert_eq!(
            request_events[1]["kind"]["routing_decision"],
            "eidolon_owned"
        );
        assert_eq!(
            request_events[1]["kind"]["discovery_recon_score"]["decoy_write_probe_score"],
            2
        );
        assert_eq!(request_events[2]["policy_state"], "rate_limited");
        assert_eq!(
            request_events[2]["kind"]["routing_decision"],
            "rate_limited"
        );
        assert_eq!(request_events[3]["policy_state"], "blocked");
        assert_eq!(
            request_events[3]["kind"]["routing_decision"],
            "eidolon_owned"
        );
        assert_eq!(
            request_events[3]["kind"]["discovery_recon_score"]["repeated_discovery_score"],
            2
        );
        assert_eq!(
            request_events[3]["kind"]["discovery_recon_score"]["query_score"],
            1
        );
        assert_eq!(
            request_events[3]["kind"]["discovery_recon_score"]["decoy_write_probe_score"],
            2
        );
        assert_eq!(
            request_events[3]["kind"]["discovery_recon_score"]["total"],
            5
        );
        assert_eq!(
            request_events[3]["kind"]["discovery_recon_score"]["threshold"],
            5
        );

        let policy_decisions = events_of_type(&event_log_path, "policy_decision");
        assert_eq!(policy_decisions.len(), 3);
        assert!(policy_decisions[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| {
                reason.contains("rate-limited discovery recon retry moved session to blocked")
            }));
        assert!(policy_decisions[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("decoy_write_probe_seen=true")));
        assert!(policy_decisions[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("decoy_write_probe_score=2")));

        let policy_changes = events_of_type(&event_log_path, "policy_changed");
        assert_eq!(policy_changes.len(), 3);
        assert_eq!(policy_changes[0]["kind"]["from"], "observe");
        assert_eq!(policy_changes[0]["kind"]["to"], "suspicious");
        assert_eq!(policy_changes[1]["kind"]["from"], "suspicious");
        assert_eq!(policy_changes[1]["kind"]["to"], "rate_limited");
        assert_eq!(policy_changes[2]["kind"]["from"], "rate_limited");
        assert_eq!(policy_changes[2]["kind"]["to"], "blocked");
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| {
                reason.contains("rate-limited discovery recon retry moved session to blocked")
            }));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("path=/docs")));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("discovery_requests=3")));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("distinct_surfaces=1")));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("query_seen=true")));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("decoy_write_probe_seen=true")));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("repeated_discovery_score=2")));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("query_score=1")));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("decoy_write_probe_score=2")));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("recon_score=5")));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("recon_block_threshold=5")));

        assert_event_type_absent(&event_log_path, "bait_action_observed");

        let request_debugs: Vec<Value> = debug_values(&debug_log_path)
            .into_iter()
            .filter(|event| event["event"].as_str() == Some("request_received"))
            .collect();
        assert_eq!(request_debugs.len(), 4);
        assert_eq!(request_debugs[3]["fields"]["policy_state"], "blocked");
        assert_eq!(request_debugs[3]["fields"]["path"], "/docs");
        assert_eq!(request_debugs[3]["fields"]["query_present"], false);
        assert_eq!(request_debugs[3]["fields"]["discovery_request_count"], 3);
        assert_eq!(request_debugs[3]["fields"]["discovery_query_seen"], true);
        assert_eq!(
            request_debugs[3]["fields"]["discovery_decoy_write_probe_seen"],
            true
        );
        assert_eq!(
            request_debugs[3]["fields"]["discovery_surface_fanout"]["distinct_surfaces"],
            1
        );
        assert_eq!(
            request_debugs[3]["fields"]["discovery_recon_score"]["repeated_discovery_score"],
            2
        );
        assert_eq!(
            request_debugs[3]["fields"]["discovery_recon_score"]["query_score"],
            1
        );
        assert_eq!(
            request_debugs[3]["fields"]["discovery_recon_score"]["decoy_write_probe_score"],
            2
        );
        assert_eq!(
            request_debugs[3]["fields"]["discovery_recon_score"]["total"],
            5
        );
        assert_eq!(
            request_debugs[3]["fields"]["discovery_recon_score"]["threshold"],
            5
        );

        let surface_debugs: Vec<Value> = debug_values(&debug_log_path)
            .into_iter()
            .filter(|event| event["event"].as_str() == Some("surface_action_selected"))
            .collect();
        assert_eq!(surface_debugs[3]["fields"]["policy_state"], "blocked");
        assert!(surface_debugs[3]["fields"]["policy_reason"]
            .as_str()
            .is_some_and(|reason| {
                reason.contains("rate-limited discovery recon retry moved session to blocked")
            }));
        assert!(surface_debugs[3]["fields"]["policy_reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("decoy_write_probe_seen=true")));
        assert!(surface_debugs[3]["fields"]["policy_reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("decoy_write_probe_score=2")));
        assert_eq!(
            surface_debugs[3]["fields"]["surface_action"]["type"],
            "eidolon_owned"
        );
    }

    #[test]
    fn runtime_blocks_after_rate_limited_blind_write_fanout_retry() {
        let path = write_bait_profile(fanout_write_probe_profile_json());
        let loaded = load_bait_profile(&path).expect("fanout write profile should load");
        let event_log_path = unique_temp_path("aggregated-decoy-write-fanout-blocked-events.jsonl");
        let debug_log_path = unique_temp_path("aggregated-decoy-write-fanout-blocked-debug.jsonl");
        let original = r#"<!doctype html><html><body><main>docs</main></body></html>"#;
        let (upstream, _upstream_handle) = spawn_upstream_sequence([
            html_response(original),
            json_response(r#"{"mode":"reconcile"}"#),
        ]);
        let mut runtime = test_runtime_with_bait_profile(
            upstream,
            &event_log_path,
            unique_temp_path("aggregated-decoy-write-fanout-blocked-control.txt"),
            loaded,
            None,
        );
        runtime.debug_log = Some(Arc::new(Mutex::new(
            FileDebugLogWriter::open(&debug_log_path).expect("debug log should open"),
        )));
        runtime.ingress_transport_auth_secret = Some(Arc::<str>::from("edge-secret"));
        let cookie = cookie_header();
        let headers = [
            (session::INGRESS_ACTOR_KIND_HEADER_NAME, "agentic_browser"),
            (session::INGRESS_VENDOR_SCORE_HEADER_NAME, "35"),
            (
                session::INGRESS_VENDOR_SCORE_KIND_HEADER_NAME,
                "automation_likelihood_inverse",
            ),
            (session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
        ];

        let first_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &request_with_cookie("GET", "/docs?topic=imports", &cookie, &headers),
        ));
        let second_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &post_request_with_cookie("/api/v2/import/reconcile", &cookie, &headers),
        ));
        let third_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &post_request_with_cookie("/api/v2/import/validate", &cookie, &headers),
        ));
        let fourth_response = parse_downstream_response(&run_runtime_request(
            runtime,
            &post_request_with_cookie("/api/v2/import/validate", &cookie, &headers),
        ));

        assert_eq!(first_response.status, 200);
        assert_eq!(second_response.status, 202);
        assert_eq!(third_response.status, 429);
        assert_eq!(fourth_response.status, 403);
        assert_eq!(header_values(&third_response, "retry-after"), vec!["30"]);

        let request_events = events_of_type(&event_log_path, "request_seen");
        assert_eq!(request_events.len(), 4);
        assert_eq!(request_events[2]["policy_state"], "rate_limited");
        assert_eq!(
            request_events[2]["kind"]["routing_decision"],
            "rate_limited"
        );
        assert_eq!(request_events[3]["policy_state"], "blocked");
        assert_eq!(request_events[3]["kind"]["path"], "/api/v2/import/validate");
        assert_eq!(
            request_events[3]["kind"]["routing_decision"],
            "eidolon_owned"
        );
        assert_eq!(
            request_events[3]["kind"]["discovery_recon_score"]["repeated_discovery_score"],
            Value::Null
        );
        assert_eq!(
            request_events[3]["kind"]["discovery_recon_score"]["query_score"],
            1
        );
        assert_eq!(
            request_events[3]["kind"]["discovery_recon_score"]["decoy_write_probe_score"],
            3
        );
        assert_eq!(
            request_events[3]["kind"]["discovery_recon_score"]
                ["decoy_write_probe_path_fanout_bonus"],
            1
        );
        assert_eq!(
            request_events[3]["kind"]["discovery_recon_score"]["total"],
            5
        );
        assert_eq!(
            request_events[3]["kind"]["discovery_recon_score"]["threshold"],
            5
        );

        let policy_decisions = events_of_type(&event_log_path, "policy_decision");
        assert_eq!(policy_decisions.len(), 3);
        assert!(policy_decisions[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| {
                reason.contains("rate-limited discovery recon retry moved session to blocked")
            }));
        assert!(policy_decisions[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("decoy_write_probe_count=2")));
        assert!(policy_decisions[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("decoy_write_probe_path_classes=2")));
        assert!(policy_decisions[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("decoy_write_probe_path_fanout_bonus=1")));

        let policy_changes = events_of_type(&event_log_path, "policy_changed");
        assert_eq!(policy_changes.len(), 3);
        assert_eq!(policy_changes[1]["kind"]["to"], "rate_limited");
        assert_eq!(policy_changes[2]["kind"]["from"], "rate_limited");
        assert_eq!(policy_changes[2]["kind"]["to"], "blocked");
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("path=/api/v2/import/validate")));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("discovery_requests=1")));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("query_seen=true")));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("decoy_write_probe_count=2")));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("decoy_write_probe_path_classes=2")));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("repeated_discovery_score=0")));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("decoy_write_probe_score=3")));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("decoy_write_probe_path_fanout_bonus=1")));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("recon_score=5")));
        assert_eq!(
            policy_changes[2]["kind"]["persistence"]["pre_containment_persistence_kind"],
            "write_recon_retry"
        );
        assert_eq!(
            policy_changes[2]["kind"]["persistence"]["pre_containment_persistence_class"],
            "write_recon"
        );

        assert_event_type_absent(&event_log_path, "bait_action_observed");

        let request_debugs: Vec<Value> = debug_values(&debug_log_path)
            .into_iter()
            .filter(|event| event["event"].as_str() == Some("request_received"))
            .collect();
        assert_eq!(request_debugs.len(), 4);
        assert_eq!(request_debugs[3]["fields"]["policy_state"], "blocked");
        assert_eq!(
            request_debugs[3]["fields"]["path"],
            "/api/v2/import/validate"
        );
        assert_eq!(request_debugs[3]["fields"]["query_present"], false);
        assert_eq!(request_debugs[3]["fields"]["discovery_request_count"], 1);
        assert_eq!(request_debugs[3]["fields"]["discovery_query_seen"], true);
        assert_eq!(
            request_debugs[3]["fields"]["discovery_decoy_write_probe_count"],
            2
        );
        assert_eq!(
            request_debugs[3]["fields"]["discovery_decoy_write_probe_path_classes"],
            2
        );
        assert_eq!(
            request_debugs[3]["fields"]["discovery_recon_score"]["repeated_discovery_score"],
            0
        );
        assert_eq!(
            request_debugs[3]["fields"]["discovery_recon_score"]["query_score"],
            1
        );
        assert_eq!(
            request_debugs[3]["fields"]["discovery_recon_score"]["decoy_write_probe_score"],
            3
        );
        assert_eq!(
            request_debugs[3]["fields"]["discovery_recon_score"]
                ["decoy_write_probe_path_fanout_bonus"],
            1
        );
        assert_eq!(
            request_debugs[3]["fields"]["discovery_recon_score"]["total"],
            5
        );
        assert_eq!(
            request_debugs[3]["fields"]["discovery_recon_score"]["threshold"],
            5
        );

        let surface_debugs: Vec<Value> = debug_values(&debug_log_path)
            .into_iter()
            .filter(|event| event["event"].as_str() == Some("surface_action_selected"))
            .collect();
        assert_eq!(surface_debugs[3]["fields"]["policy_state"], "blocked");
        assert_eq!(
            surface_debugs[3]["fields"]["surface_action"]["type"],
            "eidolon_owned"
        );
    }

    #[test]
    fn runtime_blocks_after_rate_limited_legacy_openapi_recon_retry() {
        let event_log_path = unique_temp_path("aggregated-openapi-recon-blocked-events.jsonl");
        let debug_log_path = unique_temp_path("aggregated-openapi-recon-blocked-debug.jsonl");
        let mut runtime = test_runtime_with_m1_controller_and_debug_log(
            closed_upstream(),
            &event_log_path,
            &debug_log_path,
            unique_temp_path("aggregated-openapi-recon-blocked-control.txt"),
        );
        runtime.ingress_transport_auth_secret = Some(Arc::<str>::from("edge-secret"));
        let cookie = cookie_header();
        let headers = [
            (session::INGRESS_ACTOR_KIND_HEADER_NAME, "agentic_browser"),
            (session::INGRESS_VENDOR_SCORE_HEADER_NAME, "35"),
            (
                session::INGRESS_VENDOR_SCORE_KIND_HEADER_NAME,
                "automation_likelihood_inverse",
            ),
            (session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
        ];

        let first_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &request_with_cookie(
                "GET",
                "/openapi.json?eidolon_surface=legacy-import",
                &cookie,
                &headers,
            ),
        ));
        let second_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &request_with_cookie("GET", "/docs", &cookie, &headers),
        ));
        let third_response = parse_downstream_response(&run_runtime_request(
            runtime,
            &request_with_cookie("GET", "/docs", &cookie, &headers),
        ));

        assert_eq!(first_response.status, 200);
        assert_eq!(second_response.status, 429);
        assert_eq!(third_response.status, 403);
        assert_eq!(header_values(&second_response, "retry-after"), vec!["30"]);

        let request_events = events_of_type(&event_log_path, "request_seen");
        assert_eq!(request_events.len(), 3);
        assert_eq!(request_events[0]["policy_state"], "suspicious");
        assert_eq!(
            request_events[0]["kind"]["routing_decision"],
            "eidolon_owned"
        );
        assert_eq!(request_events[1]["policy_state"], "rate_limited");
        assert_eq!(
            request_events[1]["kind"]["routing_decision"],
            "rate_limited"
        );
        assert_eq!(request_events[2]["policy_state"], "blocked");
        assert_eq!(
            request_events[2]["kind"]["routing_decision"],
            "eidolon_owned"
        );
        assert_eq!(
            request_events[2]["kind"]["discovery_recon_score"]["threshold"],
            5
        );
        let policy_decisions = events_of_type(&event_log_path, "policy_decision");
        assert_eq!(policy_decisions.len(), 2);
        assert!(policy_decisions[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| {
                reason.contains("rate-limited discovery recon retry moved session to blocked")
            }));

        let policy_changes = events_of_type(&event_log_path, "policy_changed");
        assert_eq!(policy_changes.len(), 3);
        assert_eq!(policy_changes[2]["kind"]["from"], "rate_limited");
        assert_eq!(policy_changes[2]["kind"]["to"], "blocked");
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| {
                reason.contains("rate-limited discovery recon retry moved session to blocked")
            }));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("path=/docs")));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("discovery_requests=3")));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("distinct_surfaces=2")));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("query_seen=true")));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("legacy_openapi_query_seen=true")));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("repeated_discovery_score=2")));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("query_score=1")));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("legacy_openapi_query_score=2")));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("recon_score=5")));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("recon_block_threshold=5")));

        let request_debugs: Vec<Value> = debug_values(&debug_log_path)
            .into_iter()
            .filter(|event| event["event"].as_str() == Some("request_received"))
            .collect();
        assert_eq!(request_debugs.len(), 3);
        assert_eq!(request_debugs[2]["fields"]["policy_state"], "blocked");
        assert_eq!(request_debugs[2]["fields"]["path"], "/docs");
        assert_eq!(request_debugs[2]["fields"]["query_present"], false);
        assert_eq!(request_debugs[2]["fields"]["discovery_request_count"], 3);
        assert_eq!(request_debugs[2]["fields"]["discovery_query_seen"], true);
        assert_eq!(
            request_debugs[2]["fields"]["discovery_legacy_openapi_query_seen"],
            true
        );
        assert_eq!(
            request_debugs[2]["fields"]["discovery_surface_fanout"]["distinct_surfaces"],
            2
        );
        assert_eq!(
            request_debugs[2]["fields"]["discovery_recon_score"]["repeated_discovery_score"],
            2
        );
        assert_eq!(
            request_debugs[2]["fields"]["discovery_recon_score"]["query_score"],
            1
        );
        assert_eq!(
            request_debugs[2]["fields"]["discovery_recon_score"]["legacy_openapi_query_score"],
            2
        );
        assert_eq!(
            request_debugs[2]["fields"]["discovery_recon_score"]["total"],
            5
        );
        assert_eq!(
            request_debugs[2]["fields"]["discovery_recon_score"]["threshold"],
            5
        );

        let surface_debugs: Vec<Value> = debug_values(&debug_log_path)
            .into_iter()
            .filter(|event| event["event"].as_str() == Some("surface_action_selected"))
            .collect();
        assert_eq!(surface_debugs[2]["fields"]["policy_state"], "blocked");
        assert_eq!(
            surface_debugs[2]["fields"]["policy_reason"],
            "rate-limited discovery recon retry moved session to blocked: path=/docs actor_kind=agentic_browser vendor_score=35 discovery_requests=3 distinct_surfaces=2 query_seen=true legacy_openapi_query_seen=true linked_bait_surface_seen=false linked_bait_surface_classes=0 decoy_write_probe_seen=false decoy_write_probe_count=0 decoy_write_probe_path_classes=0 detection_count=0 repeated_discovery_score=2 query_score=1 legacy_openapi_query_score=2 linked_bait_surface_score=0 linked_bait_class_fanout_bonus=0 decoy_write_probe_score=0 decoy_write_probe_path_fanout_bonus=0 detection_score=0 recon_score=5 recon_block_threshold=5"
        );
        assert_eq!(
            surface_debugs[2]["fields"]["surface_action"]["type"],
            "eidolon_owned"
        );
    }

    #[test]
    fn runtime_aggregates_medium_score_linked_bait_surface_probe_to_suspicious() {
        let event_log_path = unique_temp_path("aggregated-linked-bait-suspicious-events.jsonl");
        let debug_log_path = unique_temp_path("aggregated-linked-bait-suspicious-debug.jsonl");
        let original = r#"<!doctype html><html><body><main>docs</main></body></html>"#;
        let (upstream, upstream_handle) = spawn_upstream(html_response(original));
        let mut runtime = test_runtime_with_m1_controller_and_debug_log(
            upstream,
            &event_log_path,
            &debug_log_path,
            unique_temp_path("aggregated-linked-bait-suspicious-control.txt"),
        );
        runtime.ingress_transport_auth_secret = Some(Arc::<str>::from("edge-secret"));
        let cookie = cookie_header();
        let headers = [
            (session::INGRESS_ACTOR_KIND_HEADER_NAME, "agentic_browser"),
            (session::INGRESS_VENDOR_SCORE_HEADER_NAME, "35"),
            (
                session::INGRESS_VENDOR_SCORE_KIND_HEADER_NAME,
                "automation_likelihood_inverse",
            ),
            (session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
        ];

        let first_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &request_with_cookie("GET", "/docs?topic=imports", &cookie, &headers),
        ));
        must_join(upstream_handle.join(), "upstream thread should join");
        let second_response = parse_downstream_response(&run_runtime_request(
            runtime,
            &request_with_cookie("GET", "/docs/legacy-import", &cookie, &headers),
        ));
        let second_body = must_ok(
            String::from_utf8(second_response.body),
            "body should be utf8",
        );

        assert_eq!(first_response.status, 200);
        assert_eq!(second_response.status, 200);
        assert!(second_body.contains("X-Migration-Trace"));
        assert!(second_body.contains("/api/v2/import/reconcile"));

        let request_events = events_of_type(&event_log_path, "request_seen");
        assert_eq!(request_events.len(), 2);
        assert_eq!(request_events[0]["policy_state"], "observe");
        assert_eq!(
            request_events[0]["kind"]["routing_decision"],
            "protected_upstream"
        );
        assert_eq!(request_events[1]["policy_state"], "suspicious");
        assert_eq!(
            request_events[1]["kind"]["routing_decision"],
            "eidolon_owned"
        );
        assert_eq!(request_events[1]["kind"]["path"], "/docs/legacy-import");

        let policy_changed = first_event_of_type(&event_log_path, "policy_changed");
        assert_eq!(policy_changed["kind"]["from"], "observe");
        assert_eq!(policy_changed["kind"]["to"], "suspicious");
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains(
                "multi-signal discovery recon aggregation promoted request to suspicious"
            )));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("path=/docs/legacy-import")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("discovery_requests=1")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("query_seen=true")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("linked_bait_surface_seen=true")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("linked_bait_surface_classes=1")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("detection_count=0")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("linked_bait_surface_score=2")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("recon_score=3")));

        let request_debugs: Vec<Value> = debug_values(&debug_log_path)
            .into_iter()
            .filter(|event| event["event"].as_str() == Some("request_received"))
            .collect();
        assert_eq!(request_debugs.len(), 2);
        assert_eq!(request_debugs[1]["fields"]["policy_state"], "suspicious");
        assert_eq!(request_debugs[1]["fields"]["path"], "/docs/legacy-import");
        assert_eq!(request_debugs[1]["fields"]["query_present"], false);
        assert_eq!(request_debugs[1]["fields"]["discovery_request_count"], 1);
        assert_eq!(request_debugs[1]["fields"]["discovery_query_seen"], true);
        assert_eq!(
            request_debugs[1]["fields"]["discovery_legacy_openapi_query_seen"],
            false
        );
        assert_eq!(
            request_debugs[1]["fields"]["discovery_linked_bait_surface_seen"],
            true
        );
        assert_eq!(
            request_debugs[1]["fields"]["discovery_linked_bait_surface_classes"],
            1
        );
        assert_eq!(
            request_debugs[1]["fields"]["discovery_recon_score"]["total"],
            3
        );

        let surface_debug = debug_values(&debug_log_path)
            .into_iter()
            .rfind(|event| event["event"].as_str() == Some("surface_action_selected"))
            .expect("second request should record a surface action");
        assert_eq!(surface_debug["fields"]["policy_state"], "suspicious");
        assert_eq!(
            surface_debug["fields"]["candidate_surface_action"]["type"],
            "eidolon_owned"
        );
        assert_eq!(
            surface_debug["fields"]["surface_action"]["type"],
            "eidolon_owned"
        );
        assert_eq!(
            surface_debug["fields"]["trusted_ingress_softened_surface"],
            false
        );

        let bait_exposed = first_event_of_type(&event_log_path, "bait_exposed");
        assert_eq!(bait_exposed["kind"]["bait_id"], "rel_2025_04_b7f2");
        assert_eq!(bait_exposed["kind"]["surface"], "/docs/legacy-import");
    }

    #[test]
    fn runtime_aggregates_medium_score_hidden_route_probe_to_suspicious() {
        let event_log_path = unique_temp_path("aggregated-hidden-route-suspicious-events.jsonl");
        let debug_log_path = unique_temp_path("aggregated-hidden-route-suspicious-debug.jsonl");
        let original = r#"<!doctype html><html><body><main>docs</main></body></html>"#;
        let (upstream, upstream_handle) = spawn_upstream(html_response(original));
        let mut runtime = test_runtime_with_m1_controller_and_debug_log(
            upstream,
            &event_log_path,
            &debug_log_path,
            unique_temp_path("aggregated-hidden-route-suspicious-control.txt"),
        );
        runtime.ingress_transport_auth_secret = Some(Arc::<str>::from("edge-secret"));
        let cookie = cookie_header();
        let headers = [
            (session::INGRESS_ACTOR_KIND_HEADER_NAME, "agentic_browser"),
            (session::INGRESS_VENDOR_SCORE_HEADER_NAME, "35"),
            (
                session::INGRESS_VENDOR_SCORE_KIND_HEADER_NAME,
                "automation_likelihood_inverse",
            ),
            (session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
        ];

        let first_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &request_with_cookie("GET", "/docs?topic=imports", &cookie, &headers),
        ));
        must_join(upstream_handle.join(), "upstream thread should join");
        let second_response = parse_downstream_response(&run_runtime_request(
            runtime,
            &request_with_cookie(
                "GET",
                "/customer/import-recovery-checklist",
                &cookie,
                &headers,
            ),
        ));
        let second_body = must_ok(
            String::from_utf8(second_response.body),
            "body should be utf8",
        );

        assert_eq!(first_response.status, 200);
        assert_eq!(second_response.status, 200);
        assert!(second_body.contains("X-Hidden-Route-Trace"));
        assert!(second_body.contains("hidden_route_2026_05_d91c"));
        assert!(second_body.contains("/api/v2/import/reconcile"));

        let request_events = events_of_type(&event_log_path, "request_seen");
        assert_eq!(request_events.len(), 2);
        assert_eq!(request_events[0]["policy_state"], "observe");
        assert_eq!(
            request_events[0]["kind"]["routing_decision"],
            "protected_upstream"
        );
        assert_eq!(request_events[1]["policy_state"], "suspicious");
        assert_eq!(
            request_events[1]["kind"]["routing_decision"],
            "eidolon_owned"
        );
        assert_eq!(
            request_events[1]["kind"]["path"],
            "/customer/import-recovery-checklist"
        );

        let policy_changed = first_event_of_type(&event_log_path, "policy_changed");
        assert_eq!(policy_changed["kind"]["from"], "observe");
        assert_eq!(policy_changed["kind"]["to"], "suspicious");
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains(
                "multi-signal discovery recon aggregation promoted request to suspicious"
            )));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("path=/customer/import-recovery-checklist")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("discovery_requests=1")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("query_seen=true")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("linked_bait_surface_seen=true")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("linked_bait_surface_classes=1")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("detection_count=0")));

        let request_debugs: Vec<Value> = debug_values(&debug_log_path)
            .into_iter()
            .filter(|event| event["event"].as_str() == Some("request_received"))
            .collect();
        assert_eq!(request_debugs.len(), 2);
        assert_eq!(request_debugs[1]["fields"]["policy_state"], "suspicious");
        assert_eq!(
            request_debugs[1]["fields"]["path"],
            "/customer/import-recovery-checklist"
        );
        assert_eq!(request_debugs[1]["fields"]["query_present"], false);
        assert_eq!(request_debugs[1]["fields"]["discovery_request_count"], 1);
        assert_eq!(request_debugs[1]["fields"]["discovery_query_seen"], true);
        assert_eq!(
            request_debugs[1]["fields"]["discovery_legacy_openapi_query_seen"],
            false
        );
        assert_eq!(
            request_debugs[1]["fields"]["discovery_linked_bait_surface_seen"],
            true
        );
        assert_eq!(
            request_debugs[1]["fields"]["discovery_linked_bait_surface_classes"],
            1
        );

        let surface_debug = debug_values(&debug_log_path)
            .into_iter()
            .rfind(|event| event["event"].as_str() == Some("surface_action_selected"))
            .expect("second request should record a surface action");
        assert_eq!(surface_debug["fields"]["policy_state"], "suspicious");
        assert_eq!(
            surface_debug["fields"]["candidate_surface_action"]["type"],
            "eidolon_owned"
        );
        assert_eq!(
            surface_debug["fields"]["surface_action"]["type"],
            "eidolon_owned"
        );
        assert_eq!(
            surface_debug["fields"]["trusted_ingress_softened_surface"],
            false
        );

        let bait_exposed = first_event_of_type(&event_log_path, "bait_exposed");
        assert_eq!(bait_exposed["kind"]["bait_id"], "hidden_route_trace");
        assert_eq!(
            bait_exposed["kind"]["surface"],
            "/customer/import-recovery-checklist"
        );
    }

    #[test]
    fn runtime_aggregates_medium_score_js_helper_probe_to_suspicious() {
        let event_log_path = unique_temp_path("aggregated-js-helper-suspicious-events.jsonl");
        let debug_log_path = unique_temp_path("aggregated-js-helper-suspicious-debug.jsonl");
        let original = r#"<!doctype html><html><body><main>docs</main></body></html>"#;
        let (upstream, upstream_handle) = spawn_upstream(html_response(original));
        let mut runtime = test_runtime_with_m1_controller_and_debug_log(
            upstream,
            &event_log_path,
            &debug_log_path,
            unique_temp_path("aggregated-js-helper-suspicious-control.txt"),
        );
        runtime.ingress_transport_auth_secret = Some(Arc::<str>::from("edge-secret"));
        let cookie = cookie_header();
        let headers = [
            (session::INGRESS_ACTOR_KIND_HEADER_NAME, "agentic_browser"),
            (session::INGRESS_VENDOR_SCORE_HEADER_NAME, "35"),
            (
                session::INGRESS_VENDOR_SCORE_KIND_HEADER_NAME,
                "automation_likelihood_inverse",
            ),
            (session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
        ];

        let first_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &request_with_cookie("GET", "/docs?topic=imports", &cookie, &headers),
        ));
        must_join(upstream_handle.join(), "upstream thread should join");
        let second_response = parse_downstream_response(&run_runtime_request(
            runtime,
            &request_with_cookie("GET", "/assets/import-helper.js", &cookie, &headers),
        ));
        let second_body = must_ok(
            String::from_utf8(second_response.body),
            "body should be utf8",
        );

        assert_eq!(first_response.status, 200);
        assert_eq!(second_response.status, 200);
        assert!(second_body.contains("window.__eidolonImportWorker"));
        assert!(second_body.contains("X-Import-Worker"));
        assert!(second_body.contains("worker_2026_05_c19b"));
        assert!(second_body.contains("/api/v2/import/reconcile"));

        let request_events = events_of_type(&event_log_path, "request_seen");
        assert_eq!(request_events.len(), 2);
        assert_eq!(request_events[0]["policy_state"], "observe");
        assert_eq!(
            request_events[0]["kind"]["routing_decision"],
            "protected_upstream"
        );
        assert_eq!(request_events[1]["policy_state"], "suspicious");
        assert_eq!(
            request_events[1]["kind"]["routing_decision"],
            "eidolon_owned"
        );
        assert_eq!(
            request_events[1]["kind"]["path"],
            "/assets/import-helper.js"
        );

        let policy_changed = first_event_of_type(&event_log_path, "policy_changed");
        assert_eq!(policy_changed["kind"]["from"], "observe");
        assert_eq!(policy_changed["kind"]["to"], "suspicious");
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains(
                "multi-signal discovery recon aggregation promoted request to suspicious"
            )));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("path=/assets/import-helper.js")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("discovery_requests=1")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("query_seen=true")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("linked_bait_surface_seen=true")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("linked_bait_surface_classes=1")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("detection_count=0")));

        let request_debugs: Vec<Value> = debug_values(&debug_log_path)
            .into_iter()
            .filter(|event| event["event"].as_str() == Some("request_received"))
            .collect();
        assert_eq!(request_debugs.len(), 2);
        assert_eq!(request_debugs[1]["fields"]["policy_state"], "suspicious");
        assert_eq!(
            request_debugs[1]["fields"]["path"],
            "/assets/import-helper.js"
        );
        assert_eq!(request_debugs[1]["fields"]["query_present"], false);
        assert_eq!(request_debugs[1]["fields"]["discovery_request_count"], 1);
        assert_eq!(request_debugs[1]["fields"]["discovery_query_seen"], true);
        assert_eq!(
            request_debugs[1]["fields"]["discovery_legacy_openapi_query_seen"],
            false
        );
        assert_eq!(
            request_debugs[1]["fields"]["discovery_linked_bait_surface_seen"],
            true
        );
        assert_eq!(
            request_debugs[1]["fields"]["discovery_linked_bait_surface_classes"],
            1
        );

        let surface_debug = debug_values(&debug_log_path)
            .into_iter()
            .rfind(|event| event["event"].as_str() == Some("surface_action_selected"))
            .expect("second request should record a surface action");
        assert_eq!(surface_debug["fields"]["policy_state"], "suspicious");
        assert_eq!(
            surface_debug["fields"]["candidate_surface_action"]["type"],
            "eidolon_owned"
        );
        assert_eq!(
            surface_debug["fields"]["surface_action"]["type"],
            "eidolon_owned"
        );
        assert_eq!(
            surface_debug["fields"]["trusted_ingress_softened_surface"],
            false
        );

        let bait_exposed = first_event_of_type(&event_log_path, "bait_exposed");
        assert_eq!(bait_exposed["kind"]["bait_id"], "js_worker_resume_trace");
        assert_eq!(bait_exposed["kind"]["surface"], "/assets/import-helper.js");
    }

    #[test]
    fn runtime_aggregates_medium_score_multiple_linked_bait_classes_to_suspicious() {
        let event_log_path =
            unique_temp_path("aggregated-multi-linked-classes-suspicious-events.jsonl");
        let debug_log_path =
            unique_temp_path("aggregated-multi-linked-classes-suspicious-debug.jsonl");
        let original = r#"<!doctype html><html><body><main>docs</main></body></html>"#;
        let (upstream, upstream_handle) = spawn_upstream(html_response(original));
        let mut runtime = test_runtime_with_m1_controller_and_debug_log(
            upstream,
            &event_log_path,
            &debug_log_path,
            unique_temp_path("aggregated-multi-linked-classes-suspicious-control.txt"),
        );
        runtime.ingress_transport_auth_secret = Some(Arc::<str>::from("edge-secret"));
        let cookie = cookie_header();
        let headers = [
            (session::INGRESS_ACTOR_KIND_HEADER_NAME, "agentic_browser"),
            (session::INGRESS_VENDOR_SCORE_HEADER_NAME, "35"),
            (
                session::INGRESS_VENDOR_SCORE_KIND_HEADER_NAME,
                "automation_likelihood_inverse",
            ),
            (session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
        ];

        let first_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &request_with_cookie("GET", "/docs", &cookie, &headers),
        ));
        must_join(upstream_handle.join(), "upstream thread should join");
        let second_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &request_with_cookie("GET", "/docs/legacy-import", &cookie, &headers),
        ));
        let third_response = parse_downstream_response(&run_runtime_request(
            runtime,
            &request_with_cookie("GET", "/assets/import-helper.js", &cookie, &headers),
        ));
        let second_body = must_ok(
            String::from_utf8(second_response.body),
            "body should be utf8",
        );
        let third_body = must_ok(
            String::from_utf8(third_response.body),
            "body should be utf8",
        );

        assert_eq!(first_response.status, 200);
        assert_eq!(second_response.status, 200);
        assert_eq!(third_response.status, 200);
        assert!(second_body.contains("X-Migration-Trace"));
        assert!(third_body.contains("window.__eidolonImportWorker"));
        assert!(third_body.contains("X-Import-Worker"));
        assert!(third_body.contains("/api/v2/import/reconcile"));

        let request_events = events_of_type(&event_log_path, "request_seen");
        assert_eq!(request_events.len(), 3);
        assert_eq!(request_events[0]["policy_state"], "observe");
        assert_eq!(
            request_events[0]["kind"]["routing_decision"],
            "protected_upstream"
        );
        assert_eq!(request_events[1]["policy_state"], "observe");
        assert_eq!(
            request_events[1]["kind"]["routing_decision"],
            "eidolon_owned"
        );
        assert_eq!(request_events[1]["kind"]["path"], "/docs/legacy-import");
        assert_eq!(request_events[2]["policy_state"], "suspicious");
        assert_eq!(
            request_events[2]["kind"]["routing_decision"],
            "eidolon_owned"
        );
        assert_eq!(
            request_events[2]["kind"]["path"],
            "/assets/import-helper.js"
        );

        let policy_changed = first_event_of_type(&event_log_path, "policy_changed");
        assert_eq!(policy_changed["kind"]["from"], "observe");
        assert_eq!(policy_changed["kind"]["to"], "suspicious");
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains(
                "multi-signal discovery recon aggregation promoted request to suspicious"
            )));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("path=/assets/import-helper.js")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("discovery_requests=1")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("query_seen=false")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("linked_bait_surface_seen=true")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("linked_bait_surface_classes=2")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("detection_count=0")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("linked_bait_surface_score=2")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("linked_bait_class_fanout_bonus=1")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("recon_score=3")));

        let request_debugs: Vec<Value> = debug_values(&debug_log_path)
            .into_iter()
            .filter(|event| event["event"].as_str() == Some("request_received"))
            .collect();
        assert_eq!(request_debugs.len(), 3);
        assert_eq!(request_debugs[1]["fields"]["policy_state"], "observe");
        assert_eq!(request_debugs[1]["fields"]["path"], "/docs/legacy-import");
        assert_eq!(request_debugs[1]["fields"]["discovery_query_seen"], false);
        assert_eq!(
            request_debugs[1]["fields"]["discovery_linked_bait_surface_seen"],
            true
        );
        assert_eq!(
            request_debugs[1]["fields"]["discovery_linked_bait_surface_classes"],
            1
        );
        assert_eq!(request_debugs[2]["fields"]["policy_state"], "suspicious");
        assert_eq!(
            request_debugs[2]["fields"]["path"],
            "/assets/import-helper.js"
        );
        assert_eq!(request_debugs[2]["fields"]["discovery_request_count"], 1);
        assert_eq!(request_debugs[2]["fields"]["discovery_query_seen"], false);
        assert_eq!(
            request_debugs[2]["fields"]["discovery_linked_bait_surface_seen"],
            true
        );
        assert_eq!(
            request_debugs[2]["fields"]["discovery_linked_bait_surface_classes"],
            2
        );
        assert_eq!(
            request_debugs[2]["fields"]["discovery_recon_score"]["total"],
            3
        );
        assert_eq!(
            request_debugs[2]["fields"]["discovery_recon_score"]["linked_bait_class_fanout_bonus"],
            1
        );

        let bait_exposed_events = events_of_type(&event_log_path, "bait_exposed");
        assert_eq!(bait_exposed_events.len(), 2);
        assert_eq!(
            bait_exposed_events[0]["kind"]["bait_id"],
            "rel_2025_04_b7f2"
        );
        assert_eq!(
            bait_exposed_events[1]["kind"]["bait_id"],
            "js_worker_resume_trace"
        );
        assert_eq!(
            bait_exposed_events[1]["kind"]["surface"],
            "/assets/import-helper.js"
        );
    }

    #[test]
    fn runtime_aggregates_medium_score_openapi_anchored_linked_fanout_to_suspicious() {
        let event_log_path =
            unique_temp_path("aggregated-openapi-linked-fanout-suspicious-events.jsonl");
        let debug_log_path =
            unique_temp_path("aggregated-openapi-linked-fanout-suspicious-debug.jsonl");
        let original = r#"{"openapi":"3.0.3","info":{"title":"demo","version":"0"},"paths":{}}"#;
        let (upstream, upstream_handle) = spawn_upstream(json_response(original));
        let mut runtime = test_runtime_with_m1_controller_and_debug_log(
            upstream,
            &event_log_path,
            &debug_log_path,
            unique_temp_path("aggregated-openapi-linked-fanout-suspicious-control.txt"),
        );
        runtime.ingress_transport_auth_secret = Some(Arc::<str>::from("edge-secret"));
        let cookie = cookie_header();
        let headers = [
            (session::INGRESS_ACTOR_KIND_HEADER_NAME, "agentic_browser"),
            (session::INGRESS_VENDOR_SCORE_HEADER_NAME, "35"),
            (
                session::INGRESS_VENDOR_SCORE_KIND_HEADER_NAME,
                "automation_likelihood_inverse",
            ),
            (session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
        ];

        let first_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &request_with_cookie("GET", "/openapi.json", &cookie, &headers),
        ));
        must_join(upstream_handle.join(), "upstream thread should join");
        let second_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &request_with_cookie("GET", "/docs/legacy-import", &cookie, &headers),
        ));
        let third_response = parse_downstream_response(&run_runtime_request(
            runtime,
            &request_with_cookie("GET", "/assets/import-helper.js", &cookie, &headers),
        ));
        let first_body: Value = must_ok(
            serde_json::from_slice(&first_response.body),
            "first body should be json",
        );
        let second_body = must_ok(
            String::from_utf8(second_response.body),
            "second body should be utf8",
        );
        let third_body = must_ok(
            String::from_utf8(third_response.body),
            "third body should be utf8",
        );

        assert_eq!(first_response.status, 200);
        assert_eq!(second_response.status, 200);
        assert_eq!(third_response.status, 200);
        assert_eq!(first_body["openapi"].as_str(), Some("3.0.3"));
        assert_eq!(
            first_body["paths"]["/api/v2/import/reconcile"]["post"]["parameters"][0]["name"],
            "X-OpenAPI-Trace"
        );
        assert!(second_body.contains("X-Migration-Trace"));
        assert!(third_body.contains("window.__eidolonImportWorker"));
        assert!(third_body.contains("X-Import-Worker"));
        assert!(third_body.contains("/api/v2/import/reconcile"));

        let request_events = events_of_type(&event_log_path, "request_seen");
        assert_eq!(request_events.len(), 3);
        assert_eq!(request_events[0]["policy_state"], "observe");
        assert_eq!(
            request_events[0]["kind"]["routing_decision"],
            "protected_upstream"
        );
        assert_eq!(request_events[0]["kind"]["path"], "/openapi.json");
        assert_eq!(request_events[1]["policy_state"], "observe");
        assert_eq!(
            request_events[1]["kind"]["routing_decision"],
            "eidolon_owned"
        );
        assert_eq!(request_events[1]["kind"]["path"], "/docs/legacy-import");
        assert_eq!(request_events[2]["policy_state"], "suspicious");
        assert_eq!(
            request_events[2]["kind"]["routing_decision"],
            "eidolon_owned"
        );
        assert_eq!(
            request_events[2]["kind"]["path"],
            "/assets/import-helper.js"
        );

        let policy_changed = first_event_of_type(&event_log_path, "policy_changed");
        assert_eq!(policy_changed["kind"]["from"], "observe");
        assert_eq!(policy_changed["kind"]["to"], "suspicious");
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains(
                "multi-signal discovery recon aggregation promoted request to suspicious"
            )));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("path=/assets/import-helper.js")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("discovery_requests=1")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("query_seen=false")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("legacy_openapi_query_seen=false")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("linked_bait_surface_seen=true")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("linked_bait_surface_classes=2")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("detection_count=0")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("linked_bait_surface_score=2")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("linked_bait_class_fanout_bonus=1")));
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("recon_score=3")));

        let request_debugs: Vec<Value> = debug_values(&debug_log_path)
            .into_iter()
            .filter(|event| event["event"].as_str() == Some("request_received"))
            .collect();
        assert_eq!(request_debugs.len(), 3);
        assert_eq!(request_debugs[0]["fields"]["path"], "/openapi.json");
        assert_eq!(
            request_debugs[0]["fields"]["discovery_surface_fanout"]["docs_seen"],
            false
        );
        assert_eq!(
            request_debugs[0]["fields"]["discovery_surface_fanout"]["openapi_seen"],
            true
        );
        assert_eq!(request_debugs[0]["fields"]["discovery_request_count"], 1);
        assert_eq!(request_debugs[0]["fields"]["discovery_query_seen"], false);
        assert_eq!(
            request_debugs[0]["fields"]["discovery_linked_bait_surface_seen"],
            false
        );
        assert_eq!(
            request_debugs[0]["fields"]["discovery_linked_bait_surface_classes"],
            0
        );
        assert_eq!(request_debugs[1]["fields"]["policy_state"], "observe");
        assert_eq!(request_debugs[1]["fields"]["path"], "/docs/legacy-import");
        assert_eq!(request_debugs[1]["fields"]["discovery_query_seen"], false);
        assert_eq!(
            request_debugs[1]["fields"]["discovery_linked_bait_surface_seen"],
            true
        );
        assert_eq!(
            request_debugs[1]["fields"]["discovery_linked_bait_surface_classes"],
            1
        );
        assert_eq!(request_debugs[2]["fields"]["policy_state"], "suspicious");
        assert_eq!(
            request_debugs[2]["fields"]["path"],
            "/assets/import-helper.js"
        );
        assert_eq!(request_debugs[2]["fields"]["discovery_request_count"], 1);
        assert_eq!(request_debugs[2]["fields"]["discovery_query_seen"], false);
        assert_eq!(
            request_debugs[2]["fields"]["discovery_linked_bait_surface_seen"],
            true
        );
        assert_eq!(
            request_debugs[2]["fields"]["discovery_linked_bait_surface_classes"],
            2
        );
        assert_eq!(
            request_debugs[2]["fields"]["discovery_recon_score"]["total"],
            3
        );
        assert_eq!(
            request_debugs[2]["fields"]["discovery_recon_score"]["linked_bait_class_fanout_bonus"],
            1
        );

        let bait_exposed_events = events_of_type(&event_log_path, "bait_exposed");
        assert_eq!(bait_exposed_events.len(), 3);
        assert_eq!(
            bait_exposed_events[0]["kind"]["bait_id"],
            "openapi_reconcile_trace"
        );
        assert_eq!(bait_exposed_events[0]["kind"]["surface"], "/openapi.json");
        assert_eq!(
            bait_exposed_events[1]["kind"]["bait_id"],
            "rel_2025_04_b7f2"
        );
        assert_eq!(
            bait_exposed_events[2]["kind"]["bait_id"],
            "js_worker_resume_trace"
        );
        assert_eq!(
            bait_exposed_events[2]["kind"]["surface"],
            "/assets/import-helper.js"
        );
    }

    #[test]
    fn trusted_identity_is_not_promoted_to_suspicious_by_low_score_discovery_request() {
        let event_log_path = unique_temp_path("trusted-low-score-discovery-events.jsonl");
        let debug_log_path = unique_temp_path("trusted-low-score-discovery-debug.jsonl");
        let original = r#"<!doctype html><html><body><main>docs</main></body></html>"#;
        let (upstream, upstream_handle) = spawn_upstream(html_response(original));
        let mut runtime = test_runtime_with_m1_controller_and_debug_log(
            upstream,
            &event_log_path,
            &debug_log_path,
            unique_temp_path("trusted-low-score-discovery-control.txt"),
        );
        runtime.ingress_transport_auth_secret = Some(Arc::<str>::from("edge-secret"));

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &request_with_cookie(
                "GET",
                "/docs?topic=imports",
                &cookie_header(),
                &[
                    (session::INGRESS_IDENTITY_SOURCE_HEADER_NAME, "signed_agent"),
                    (session::INGRESS_TRUST_TIER_HEADER_NAME, "signed_attested"),
                    (session::INGRESS_IDENTITY_LABEL_HEADER_NAME, "signed-agent"),
                    (session::INGRESS_ACTOR_KIND_HEADER_NAME, "agentic_browser"),
                    (session::INGRESS_VENDOR_SCORE_HEADER_NAME, "12"),
                    (
                        session::INGRESS_VENDOR_SCORE_KIND_HEADER_NAME,
                        "automation_likelihood_inverse",
                    ),
                    (session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
                ],
            ),
        ));
        assert!(
            upstream_handle.join().is_ok(),
            "upstream thread should join"
        );
        let Ok(body) = String::from_utf8(response.body) else {
            panic!("body should be utf8");
        };

        assert_eq!(response.status, 200);
        assert_eq!(body, original);

        let request_event = first_event_of_type(&event_log_path, "request_seen");
        assert_eq!(request_event["policy_state"], "observe");
        assert_event_type_absent(&event_log_path, "policy_changed");
        assert_policy_decision_reason_contains(
            &event_log_path,
            "trusted ingress identity suppressed bait surface intervention",
        );

        let surface_debug = first_debug_event(&debug_log_path, "surface_action_selected");
        assert_eq!(
            surface_debug["fields"]["trusted_ingress_softened_surface"],
            true
        );
    }

    #[test]
    fn runtime_ignores_forged_explicit_ingress_headers_without_transport_auth() {
        let event_log_path = unique_temp_path("forged-ingress-identity-events.jsonl");
        let debug_log_path = unique_temp_path("forged-ingress-identity-debug.jsonl");
        let runtime = test_runtime_with_m1_controller_and_debug_log(
            closed_upstream(),
            &event_log_path,
            &debug_log_path,
            unique_temp_path("forged-ingress-identity-control.txt"),
        );

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &request_with_cookie(
                "GET",
                "/docs/legacy-import",
                &cookie_header(),
                &[
                    (session::INGRESS_IDENTITY_SOURCE_HEADER_NAME, "signed_agent"),
                    (session::INGRESS_TRUST_TIER_HEADER_NAME, "signed_attested"),
                    (
                        session::INGRESS_IDENTITY_LABEL_HEADER_NAME,
                        "forged-edge-agent",
                    ),
                    (session::INGRESS_VENDOR_SCORE_HEADER_NAME, "91"),
                    (session::INGRESS_EDGE_ACTION_HEADER_NAME, "allow"),
                ],
            ),
        ));

        assert_eq!(response.status, 200);
        let request_event = first_event_of_type(&event_log_path, "request_seen");
        assert_eq!(request_event["kind"]["ingress_identity"]["source"], "none");
        assert!(request_event["kind"]["ingress_signals"].is_null());
        assert_eq!(
            request_event["kind"]["routing_decision"].as_str(),
            Some("eidolon_owned")
        );

        let surface_debug = first_debug_event(&debug_log_path, "surface_action_selected");
        assert_eq!(
            surface_debug["fields"]["surface_action"]["type"],
            "eidolon_owned"
        );
        assert_eq!(
            surface_debug["fields"]["trusted_ingress_softened_surface"],
            false
        );
    }

    #[test]
    fn expired_authenticated_ingress_identity_does_not_soften_bait_surface() {
        let event_log_path = unique_temp_path("expired-ingress-identity-events.jsonl");
        let debug_log_path = unique_temp_path("expired-ingress-identity-debug.jsonl");
        let original = r#"{"openapi":"3.0.3","info":{"title":"demo","version":"0"},"paths":{}}"#;
        let (upstream, upstream_handle) = spawn_upstream(json_response(original));
        let runtime = test_runtime_with_m1_controller_and_debug_log(
            upstream,
            &event_log_path,
            &debug_log_path,
            unique_temp_path("expired-ingress-identity-control.txt"),
        );
        let mut runtime = runtime;
        runtime.ingress_transport_auth_secret = Some(Arc::<str>::from("edge-secret"));

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &request_with_cookie(
                "GET",
                "/openapi.json",
                &cookie_header(),
                &[
                    (session::INGRESS_IDENTITY_SOURCE_HEADER_NAME, "signed_agent"),
                    (session::INGRESS_TRUST_TIER_HEADER_NAME, "signed_attested"),
                    (
                        session::INGRESS_IDENTITY_LABEL_HEADER_NAME,
                        "expired-edge-agent",
                    ),
                    (
                        session::INGRESS_IDENTITY_EXPIRES_AT_HEADER_NAME,
                        "2000-01-01T00:00:00Z",
                    ),
                    (session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
                ],
            ),
        ));
        must_join(upstream_handle.join(), "upstream thread should join");
        let body: Value = must_ok(
            serde_json::from_slice(&response.body),
            "body should be rewritten openapi json",
        );

        assert_eq!(response.status, 200);
        assert!(body["paths"]["/api/v2/import/reconcile"].is_object());
        let request_event = first_event_of_type(&event_log_path, "request_seen");
        assert_eq!(
            request_event["kind"]["ingress_identity"]["source"],
            "signed_agent"
        );
        assert_eq!(
            request_event["kind"]["ingress_identity"]["trust_tier"],
            "weakly_asserted"
        );
        assert_eq!(
            request_event["kind"]["ingress_identity"]["label"],
            "expired-edge-agent"
        );
        assert_eq!(
            request_event["kind"]["ingress_identity"]["expires_at"],
            "2000-01-01T00:00:00Z"
        );
        assert_eq!(
            request_event["kind"]["routing_decision"].as_str(),
            Some("protected_upstream")
        );

        let surface_debug = first_debug_event(&debug_log_path, "surface_action_selected");
        assert_eq!(
            surface_debug["fields"]["surface_action"]["type"],
            "rewritten_upstream"
        );
        assert_eq!(
            surface_debug["fields"]["trusted_ingress_softened_surface"],
            false
        );
    }

    #[test]
    fn proxy_never_forwards_reserved_eidolon_headers_upstream() {
        let event_log_path = unique_temp_path("strip-eidolon-headers-events.jsonl");
        let (upstream, upstream_handle) =
            spawn_upstream(html_response("<html><body>upstream</body></html>"));
        let mut runtime = test_runtime(
            upstream,
            &event_log_path,
            unique_temp_path("strip-eidolon-headers-control.txt"),
            SurfaceAction::ProtectedUpstream,
        );
        runtime.ingress_transport_auth_secret = Some(Arc::<str>::from("edge-secret"));

        let _response = run_runtime_request(
            runtime,
            &request_with_cookie(
                "GET",
                "/health",
                &cookie_header(),
                &[
                    (session::INGRESS_IDENTITY_SOURCE_HEADER_NAME, "signed_agent"),
                    (session::INGRESS_TRUST_TIER_HEADER_NAME, "signed_attested"),
                    (session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
                    ("X-Eidolon-Ingress-Vendor-Score", "91"),
                ],
            ),
        );
        let upstream_request = must_join(upstream_handle.join(), "upstream thread should join");
        let upstream_request = must_ok(
            String::from_utf8(upstream_request),
            "request should be utf8",
        );

        assert!(!upstream_request.contains("X-Eidolon-Ingress-Identity-Source:"));
        assert!(!upstream_request.contains("X-Eidolon-Ingress-Trust-Tier:"));
        assert!(!upstream_request.contains("X-Eidolon-Ingress-Transport-Auth:"));
        assert!(!upstream_request.contains("X-Eidolon-Ingress-Vendor-Score:"));
    }

    #[test]
    fn runtime_records_local_trust_config_identity_when_explicit_headers_are_absent() {
        let event_log_path = unique_temp_path("local-trust-events.jsonl");
        let debug_log_path = unique_temp_path("local-trust-debug.jsonl");
        let (upstream, upstream_handle) =
            spawn_upstream(html_response("<html><body>upstream</body></html>"));
        let mut runtime = test_runtime_with_m1_controller_and_debug_log(
            upstream,
            &event_log_path,
            &debug_log_path,
            unique_temp_path("local-trust-control.txt"),
        );
        let config_path = write_ingress_trust_config(
            r#"{
              "schema_version": 1,
              "entries": [
                {
                  "label": "internal-crawler",
                  "source": "local_allowlist",
                  "trust_tier": "allowlisted",
                  "methods": ["GET"],
                  "path_prefixes": ["/docs"],
                  "required_headers": [
                    { "name": "X-Eidolon-Trusted-Actor", "value": "internal-crawler" }
                  ]
                }
              ]
            }"#,
        );
        runtime.ingress_identity_resolver = Arc::new(must_ok(
            ingress_identity::load_ingress_identity_resolver(&config_path),
            "ingress trust config should load",
        ));

        let request = request_with_cookie(
            "GET",
            "/docs/legacy-import",
            &cookie_header(),
            &[("X-Eidolon-Trusted-Actor", "internal-crawler")],
        );
        let _response = run_runtime_request(runtime, &request);
        upstream_handle.join().expect("upstream thread should join");

        let request_event = first_event_of_type(&event_log_path, "request_seen");
        assert_eq!(
            request_event["kind"]["ingress_identity"]["source"],
            "local_allowlist"
        );
        assert_eq!(
            request_event["kind"]["ingress_identity"]["trust_tier"],
            "allowlisted"
        );
        assert_eq!(
            request_event["kind"]["ingress_identity"]["label"],
            "internal-crawler"
        );
    }

    #[test]
    fn runtime_prefers_stronger_local_trust_identity_over_weaker_explicit_claim() {
        let event_log_path = unique_temp_path("local-trust-precedence-events.jsonl");
        let debug_log_path = unique_temp_path("local-trust-precedence-debug.jsonl");
        let (upstream, upstream_handle) =
            spawn_upstream(html_response("<html><body>upstream</body></html>"));
        let mut runtime = test_runtime_with_m1_controller_and_debug_log(
            upstream,
            &event_log_path,
            &debug_log_path,
            unique_temp_path("local-trust-precedence-control.txt"),
        );
        let config_path = write_ingress_trust_config(
            r#"{
              "schema_version": 1,
              "entries": [
                {
                  "label": "internal-crawler",
                  "source": "local_allowlist",
                  "trust_tier": "allowlisted",
                  "methods": ["GET"],
                  "path_prefixes": ["/docs"],
                  "required_headers": [
                    { "name": "X-Eidolon-Trusted-Actor", "value": "internal-crawler" }
                  ]
                }
              ]
            }"#,
        );
        runtime.ingress_identity_resolver = Arc::new(must_ok(
            ingress_identity::load_ingress_identity_resolver(&config_path),
            "ingress trust config should load",
        ));
        runtime.ingress_transport_auth_secret = Some(Arc::<str>::from("edge-secret"));

        let request = request_with_cookie(
            "GET",
            "/docs/legacy-import",
            &cookie_header(),
            &[
                (session::INGRESS_IDENTITY_SOURCE_HEADER_NAME, "verified_bot"),
                (session::INGRESS_TRUST_TIER_HEADER_NAME, "weakly_asserted"),
                (session::INGRESS_IDENTITY_LABEL_HEADER_NAME, "edge-bot"),
                (session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
                ("X-Eidolon-Trusted-Actor", "internal-crawler"),
            ],
        );
        let _response = run_runtime_request(runtime, &request);
        upstream_handle.join().expect("upstream thread should join");

        let request_event = first_event_of_type(&event_log_path, "request_seen");
        assert_eq!(
            request_event["kind"]["ingress_identity"]["source"],
            "local_allowlist"
        );
        assert_eq!(
            request_event["kind"]["ingress_identity"]["trust_tier"],
            "allowlisted"
        );
        assert_eq!(
            request_event["kind"]["ingress_identity"]["label"],
            "internal-crawler"
        );
    }

    #[test]
    fn runtime_prefers_stronger_explicit_identity_over_local_allowlist() {
        let event_log_path = unique_temp_path("explicit-trust-precedence-events.jsonl");
        let debug_log_path = unique_temp_path("explicit-trust-precedence-debug.jsonl");
        let (upstream, upstream_handle) =
            spawn_upstream(html_response("<html><body>upstream</body></html>"));
        let mut runtime = test_runtime_with_m1_controller_and_debug_log(
            upstream,
            &event_log_path,
            &debug_log_path,
            unique_temp_path("explicit-trust-precedence-control.txt"),
        );
        let config_path = write_ingress_trust_config(
            r#"{
              "schema_version": 1,
              "entries": [
                {
                  "label": "internal-crawler",
                  "source": "local_allowlist",
                  "trust_tier": "allowlisted",
                  "methods": ["GET"],
                  "path_prefixes": ["/docs"],
                  "required_headers": [
                    { "name": "X-Eidolon-Trusted-Actor", "value": "internal-crawler" }
                  ]
                }
              ]
            }"#,
        );
        runtime.ingress_identity_resolver = Arc::new(must_ok(
            ingress_identity::load_ingress_identity_resolver(&config_path),
            "ingress trust config should load",
        ));
        runtime.ingress_transport_auth_secret = Some(Arc::<str>::from("edge-secret"));

        let request = request_with_cookie(
            "GET",
            "/docs/legacy-import",
            &cookie_header(),
            &[
                (session::INGRESS_IDENTITY_SOURCE_HEADER_NAME, "signed_agent"),
                (session::INGRESS_TRUST_TIER_HEADER_NAME, "signed_attested"),
                (session::INGRESS_IDENTITY_LABEL_HEADER_NAME, "signed-agent"),
                (session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
                ("X-Eidolon-Trusted-Actor", "internal-crawler"),
            ],
        );
        let _response = run_runtime_request(runtime, &request);
        upstream_handle.join().expect("upstream thread should join");

        let request_event = first_event_of_type(&event_log_path, "request_seen");
        assert_eq!(
            request_event["kind"]["ingress_identity"]["source"],
            "signed_agent"
        );
        assert_eq!(
            request_event["kind"]["ingress_identity"]["trust_tier"],
            "signed_attested"
        );
        assert_eq!(
            request_event["kind"]["ingress_identity"]["label"],
            "signed-agent"
        );
    }

    #[test]
    fn configured_authenticated_explicit_rule_can_soften_docs_surface() {
        let event_log_path = unique_temp_path("explicit-auth-rule-soften-events.jsonl");
        let debug_log_path = unique_temp_path("explicit-auth-rule-soften-debug.jsonl");
        let original =
            r#"<!doctype html><html><body><main>docs explicit softening</main></body></html>"#;
        let (upstream, upstream_handle) = spawn_upstream(html_response(original));
        let mut runtime = test_runtime_with_m1_controller_and_debug_log(
            upstream,
            &event_log_path,
            &debug_log_path,
            unique_temp_path("explicit-auth-rule-soften-control.txt"),
        );
        let config_path = write_ingress_trust_config(
            r#"{
              "schema_version": 1,
              "authenticated_entries": [
                {
                  "label": "docs-signed-agent",
                  "source": "signed_agent",
                  "trust_tier": "signed_attested",
                  "verified_categories": ["AI Assistant"],
                  "methods": ["GET"],
                  "path_prefixes": ["/docs", "/openapi.json"],
                  "bait_soften_path_prefixes": ["/docs"]
                }
              ]
            }"#,
        );
        runtime.ingress_identity_resolver = Arc::new(must_ok(
            ingress_identity::load_ingress_identity_resolver(&config_path),
            "ingress trust config should load",
        ));
        runtime.ingress_transport_auth_secret = Some(Arc::<str>::from("edge-secret"));

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &request_with_cookie(
                "GET",
                "/docs?topic=imports",
                &cookie_header(),
                &[
                    (session::INGRESS_IDENTITY_SOURCE_HEADER_NAME, "signed_agent"),
                    (session::INGRESS_TRUST_TIER_HEADER_NAME, "signed_attested"),
                    (
                        session::INGRESS_IDENTITY_LABEL_HEADER_NAME,
                        "docs-signed-agent",
                    ),
                    (
                        session::INGRESS_VERIFIED_CATEGORY_HEADER_NAME,
                        "AI Assistant",
                    ),
                    (session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
                ],
            ),
        ));
        upstream_handle.join().expect("upstream thread should join");
        let body = String::from_utf8(response.body).expect("body should be utf8");

        assert_eq!(response.status, 200);
        assert_eq!(body, original);
        let request_event = first_event_of_type(&event_log_path, "request_seen");
        assert_eq!(
            request_event["kind"]["ingress_identity"]["source"],
            "signed_agent"
        );
        assert_eq!(
            request_event["kind"]["ingress_identity"]["trust_tier"],
            "signed_attested"
        );
        assert_eq!(
            request_event["kind"]["trusted_ingress_soften_match"]["label"],
            "docs-signed-agent"
        );
        assert_eq!(
            request_event["kind"]["trusted_ingress_soften_match"]["verified_categories"],
            serde_json::json!(["AI Assistant"])
        );
        assert_eq!(
            request_event["kind"]["trusted_ingress_soften_match"]["request_path_softened"],
            true
        );
        let surface_debug = first_debug_event(&debug_log_path, "surface_action_selected");
        assert_eq!(
            surface_debug["fields"]["surface_action"]["type"],
            "protected_upstream"
        );
        assert_eq!(
            surface_debug["fields"]["trusted_ingress_softened_surface"],
            true
        );
    }

    #[test]
    fn more_specific_authenticated_explicit_rule_wins_over_broader_match() {
        let event_log_path = unique_temp_path("explicit-auth-rule-specificity-events.jsonl");
        let debug_log_path = unique_temp_path("explicit-auth-rule-specificity-debug.jsonl");
        let original =
            r#"<!doctype html><html><body><main>docs explicit specificity</main></body></html>"#;
        let (upstream, upstream_handle) = spawn_upstream(html_response(original));
        let mut runtime = test_runtime_with_m1_controller_and_debug_log(
            upstream,
            &event_log_path,
            &debug_log_path,
            unique_temp_path("explicit-auth-rule-specificity-control.txt"),
        );
        let config_path = write_ingress_trust_config(
            r#"{
              "schema_version": 1,
              "authenticated_entries": [
                {
                  "label": "docs-signed-agent",
                  "source": "signed_agent",
                  "trust_tier": "signed_attested",
                  "methods": ["GET"],
                  "path_prefixes": ["/docs", "/openapi.json"]
                },
                {
                  "label": "docs-signed-agent",
                  "source": "signed_agent",
                  "trust_tier": "signed_attested",
                  "verified_categories": ["AI Assistant"],
                  "methods": ["GET"],
                  "path_prefixes": ["/docs"],
                  "bait_soften_path_prefixes": ["/docs"]
                }
              ]
            }"#,
        );
        runtime.ingress_identity_resolver = Arc::new(must_ok(
            ingress_identity::load_ingress_identity_resolver(&config_path),
            "ingress trust config should load",
        ));
        runtime.ingress_transport_auth_secret = Some(Arc::<str>::from("edge-secret"));

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &request_with_cookie(
                "GET",
                "/docs?topic=imports",
                &cookie_header(),
                &[
                    (session::INGRESS_IDENTITY_SOURCE_HEADER_NAME, "signed_agent"),
                    (session::INGRESS_TRUST_TIER_HEADER_NAME, "signed_attested"),
                    (
                        session::INGRESS_IDENTITY_LABEL_HEADER_NAME,
                        "docs-signed-agent",
                    ),
                    (
                        session::INGRESS_VERIFIED_CATEGORY_HEADER_NAME,
                        "AI Assistant",
                    ),
                    (session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
                ],
            ),
        ));
        upstream_handle.join().expect("upstream thread should join");
        let body = String::from_utf8(response.body).expect("body should be utf8");

        assert_eq!(response.status, 200);
        assert_eq!(body, original);
        let request_event = first_event_of_type(&event_log_path, "request_seen");
        assert_eq!(
            request_event["kind"]["trusted_ingress_soften_match"]["path_prefixes"],
            serde_json::json!(["/docs"])
        );
        assert_eq!(
            request_event["kind"]["trusted_ingress_soften_match"]["verified_categories"],
            serde_json::json!(["AI Assistant"])
        );
        assert_eq!(
            request_event["kind"]["trusted_ingress_soften_match"]["request_path_softened"],
            true
        );
        let surface_debug = first_debug_event(&debug_log_path, "surface_action_selected");
        assert_eq!(
            surface_debug["fields"]["surface_action"]["type"],
            "protected_upstream"
        );
        assert_eq!(
            surface_debug["fields"]["trusted_ingress_softened_surface"],
            true
        );
    }

    #[test]
    fn unmatched_authenticated_explicit_rule_degrades_to_weakly_asserted_and_stays_baited() {
        let event_log_path = unique_temp_path("explicit-auth-rule-mismatch-events.jsonl");
        let debug_log_path = unique_temp_path("explicit-auth-rule-mismatch-debug.jsonl");
        let original =
            r#"<!doctype html><html><body><main>docs explicit mismatch</main></body></html>"#;
        let (upstream, upstream_handle) = spawn_upstream(html_response(original));
        let mut runtime = test_runtime_with_m1_controller_and_debug_log(
            upstream,
            &event_log_path,
            &debug_log_path,
            unique_temp_path("explicit-auth-rule-mismatch-control.txt"),
        );
        let config_path = write_ingress_trust_config(
            r#"{
              "schema_version": 1,
              "authenticated_entries": [
                {
                  "label": "docs-signed-agent",
                  "source": "signed_agent",
                  "trust_tier": "signed_attested",
                  "verified_categories": ["AI Assistant"],
                  "methods": ["GET"],
                  "path_prefixes": ["/docs", "/openapi.json"],
                  "bait_soften_path_prefixes": ["/docs"]
                }
              ]
            }"#,
        );
        runtime.ingress_identity_resolver = Arc::new(must_ok(
            ingress_identity::load_ingress_identity_resolver(&config_path),
            "ingress trust config should load",
        ));
        runtime.ingress_transport_auth_secret = Some(Arc::<str>::from("edge-secret"));

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &request_with_cookie(
                "GET",
                "/docs?topic=imports",
                &cookie_header(),
                &[
                    (session::INGRESS_IDENTITY_SOURCE_HEADER_NAME, "signed_agent"),
                    (session::INGRESS_TRUST_TIER_HEADER_NAME, "signed_attested"),
                    (
                        session::INGRESS_IDENTITY_LABEL_HEADER_NAME,
                        "wrong-signed-agent",
                    ),
                    (
                        session::INGRESS_VERIFIED_CATEGORY_HEADER_NAME,
                        "AI Assistant",
                    ),
                    (session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
                ],
            ),
        ));
        upstream_handle.join().expect("upstream thread should join");
        let body = String::from_utf8(response.body).expect("body should be utf8");

        assert_eq!(response.status, 200);
        assert_ne!(body, original);
        let request_event = first_event_of_type(&event_log_path, "request_seen");
        assert_eq!(
            request_event["kind"]["ingress_identity"]["source"],
            "signed_agent"
        );
        assert_eq!(
            request_event["kind"]["ingress_identity"]["trust_tier"],
            "weakly_asserted"
        );
        assert_eq!(
            request_event["kind"]["ingress_identity"]["label"],
            "wrong-signed-agent"
        );
        assert_eq!(
            request_event["kind"]["authenticated_ingress_rule_rejection"]["label"],
            "docs-signed-agent"
        );
        assert_eq!(
            request_event["kind"]["authenticated_ingress_rule_rejection"]["reason"],
            "label_mismatch"
        );
        assert_eq!(
            request_event["kind"]["authenticated_ingress_rule_rejection"]["verified_categories"],
            serde_json::json!(["AI Assistant"])
        );
        assert!(request_event["kind"]["trusted_ingress_soften_match"].is_null());
        let request_debug = first_debug_event(&debug_log_path, "request_received");
        assert_eq!(
            request_debug["fields"]["authenticated_ingress_rule_rejection"]["reason"],
            "label_mismatch"
        );
        let surface_debug = first_debug_event(&debug_log_path, "surface_action_selected");
        assert_eq!(
            surface_debug["fields"]["surface_action"]["type"],
            "rewritten_upstream"
        );
        assert_eq!(
            surface_debug["fields"]["trusted_ingress_softened_surface"],
            false
        );
    }

    #[test]
    fn trusted_identity_suppresses_direct_bait_surface_intervention() {
        let event_log_path = unique_temp_path("trusted-direct-softening-events.jsonl");
        let debug_log_path = unique_temp_path("trusted-direct-softening-debug.jsonl");
        let original = "<html><body>upstream-not-found</body></html>";
        let (upstream, upstream_handle) =
            spawn_upstream(html_response_with_status(404, "Not Found", original));
        let mut runtime = test_runtime_with_m1_controller_and_debug_log(
            upstream,
            &event_log_path,
            &debug_log_path,
            unique_temp_path("trusted-direct-softening-control.txt"),
        );
        let config_path = write_ingress_trust_config(
            r#"{
              "schema_version": 1,
              "entries": [
                {
                  "label": "internal-crawler",
                  "source": "local_allowlist",
                  "trust_tier": "allowlisted",
                  "methods": ["GET"],
                  "path_prefixes": ["/docs"],
                  "required_headers": [
                    { "name": "X-Eidolon-Trusted-Actor", "value": "internal-crawler" }
                  ]
                }
              ]
            }"#,
        );
        runtime.ingress_identity_resolver = Arc::new(must_ok(
            ingress_identity::load_ingress_identity_resolver(&config_path),
            "ingress trust config should load",
        ));

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &request_with_cookie(
                "GET",
                "/docs/legacy-import",
                &cookie_header(),
                &[("X-Eidolon-Trusted-Actor", "internal-crawler")],
            ),
        ));
        upstream_handle.join().expect("upstream thread should join");
        let body = String::from_utf8(response.body).expect("body should be utf8");

        assert_eq!(response.status, 404);
        assert_eq!(body, original);
        assert_event_routing(&event_log_path, "request_seen", "protected_upstream");
        assert_policy_decision_reason_contains(
            &event_log_path,
            "trusted ingress identity suppressed bait surface intervention",
        );
        assert_event_routing(&event_log_path, "response_served", "protected_upstream");
        assert_event_type_absent(&event_log_path, "bait_exposed");

        let surface_debug = first_debug_event(&debug_log_path, "surface_action_selected");
        assert_eq!(
            surface_debug["fields"]["candidate_surface_action"]["type"],
            "eidolon_owned"
        );
        assert_eq!(
            surface_debug["fields"]["surface_action"]["type"],
            "protected_upstream"
        );
        assert_eq!(
            surface_debug["fields"]["trusted_ingress_softened_surface"],
            true
        );
    }

    #[test]
    fn trusted_identity_suppresses_docs_rewrite_intervention() {
        let event_log_path = unique_temp_path("trusted-rewrite-softening-events.jsonl");
        let debug_log_path = unique_temp_path("trusted-rewrite-softening-debug.jsonl");
        let original = r#"<!doctype html><html><body><main>docs</main></body></html>"#;
        let (upstream, upstream_handle) = spawn_upstream(html_response(original));
        let mut runtime = test_runtime_with_m1_controller_and_debug_log(
            upstream,
            &event_log_path,
            &debug_log_path,
            unique_temp_path("trusted-rewrite-softening-control.txt"),
        );
        let config_path = write_ingress_trust_config(
            r#"{
              "schema_version": 1,
              "entries": [
                {
                  "label": "internal-crawler",
                  "source": "local_allowlist",
                  "trust_tier": "allowlisted",
                  "methods": ["GET"],
                  "path_prefixes": ["/docs"],
                  "required_headers": [
                    { "name": "X-Eidolon-Trusted-Actor", "value": "internal-crawler" }
                  ]
                }
              ]
            }"#,
        );
        runtime.ingress_identity_resolver = Arc::new(must_ok(
            ingress_identity::load_ingress_identity_resolver(&config_path),
            "ingress trust config should load",
        ));

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &request_with_cookie(
                "GET",
                "/docs?topic=imports",
                &cookie_header(),
                &[("X-Eidolon-Trusted-Actor", "internal-crawler")],
            ),
        ));
        upstream_handle.join().expect("upstream thread should join");
        let body = String::from_utf8(response.body).expect("body should be utf8");

        assert_eq!(response.status, 200);
        assert_eq!(body, original);
        assert_event_routing(&event_log_path, "request_seen", "protected_upstream");
        assert_policy_decision_reason_contains(
            &event_log_path,
            "trusted ingress identity suppressed bait surface intervention",
        );
        assert_event_routing(&event_log_path, "response_served", "protected_upstream");
        assert_event_type_absent(&event_log_path, "bait_exposed");

        let surface_debug = first_debug_event(&debug_log_path, "surface_action_selected");
        assert_eq!(
            surface_debug["fields"]["candidate_surface_action"]["type"],
            "rewritten_upstream"
        );
        assert_eq!(
            surface_debug["fields"]["surface_action"]["type"],
            "protected_upstream"
        );
        assert_eq!(
            surface_debug["fields"]["trusted_ingress_softened_surface"],
            true
        );
    }

    #[test]
    fn trusted_identity_does_not_suppress_unconfigured_bait_surface() {
        let event_log_path = unique_temp_path("trusted-unconfigured-softening-events.jsonl");
        let debug_log_path = unique_temp_path("trusted-unconfigured-softening-debug.jsonl");
        let mut runtime = test_runtime_with_m1_controller_and_debug_log(
            closed_upstream(),
            &event_log_path,
            &debug_log_path,
            unique_temp_path("trusted-unconfigured-softening-control.txt"),
        );
        runtime.ingress_transport_auth_secret = Some(Arc::<str>::from("edge-secret"));

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &request_with_cookie(
                "GET",
                "/assets/import-helper.js",
                &cookie_header(),
                &[
                    (
                        session::INGRESS_IDENTITY_SOURCE_HEADER_NAME,
                        "operator_override",
                    ),
                    (session::INGRESS_TRUST_TIER_HEADER_NAME, "allowlisted"),
                    (
                        session::INGRESS_IDENTITY_LABEL_HEADER_NAME,
                        "internal-crawler",
                    ),
                    (session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
                ],
            ),
        ));
        let body = String::from_utf8(response.body).expect("body should be utf8");

        assert_eq!(response.status, 200);
        assert!(body.contains("/api/v2/import/reconcile"));
        assert_event_routing(&event_log_path, "request_seen", "eidolon_owned");
        assert_event_routing(&event_log_path, "policy_decision", "eidolon_owned");
        assert_event_routing(&event_log_path, "response_served", "eidolon_owned");

        let exposure = first_event_of_type(&event_log_path, "bait_exposed");
        assert_eq!(exposure["kind"]["bait_id"], "js_worker_resume_trace");

        let surface_debug = first_debug_event(&debug_log_path, "surface_action_selected");
        assert_eq!(
            surface_debug["fields"]["candidate_surface_action"]["type"],
            "eidolon_owned"
        );
        assert_eq!(
            surface_debug["fields"]["surface_action"]["type"],
            "eidolon_owned"
        );
        assert_eq!(
            surface_debug["fields"]["trusted_ingress_softened_surface"],
            false
        );
    }

    #[test]
    fn local_allowlist_softening_scope_can_narrow_global_prefixes() {
        let config_path = write_ingress_trust_config(
            r#"{
              "schema_version": 1,
              "entries": [
                {
                  "label": "docs-crawler",
                  "source": "local_allowlist",
                  "trust_tier": "allowlisted",
                  "methods": ["GET"],
                  "path_prefixes": ["/docs", "/openapi.json"],
                  "bait_soften_path_prefixes": ["/docs"],
                  "required_headers": [
                    { "name": "X-Eidolon-Trusted-Actor", "value": "docs-crawler" }
                  ]
                }
              ]
            }"#,
        );

        let docs_event_log_path = unique_temp_path("scoped-trusted-docs-events.jsonl");
        let docs_debug_log_path = unique_temp_path("scoped-trusted-docs-debug.jsonl");
        let docs_original = r#"<!doctype html><html><body><main>docs</main></body></html>"#;
        let (docs_upstream, docs_upstream_handle) = spawn_upstream(html_response(docs_original));
        let mut docs_runtime = test_runtime_with_m1_controller_and_debug_log(
            docs_upstream,
            &docs_event_log_path,
            &docs_debug_log_path,
            unique_temp_path("scoped-trusted-docs-control.txt"),
        );
        docs_runtime.ingress_identity_resolver = Arc::new(must_ok(
            ingress_identity::load_ingress_identity_resolver(&config_path),
            "ingress trust config should load",
        ));

        let docs_response = parse_downstream_response(&run_runtime_request(
            docs_runtime,
            &request_with_cookie(
                "GET",
                "/docs?topic=imports",
                &cookie_header(),
                &[("X-Eidolon-Trusted-Actor", "docs-crawler")],
            ),
        ));
        docs_upstream_handle
            .join()
            .expect("upstream thread should join");
        let docs_body = String::from_utf8(docs_response.body).expect("body should be utf8");

        assert_eq!(docs_response.status, 200);
        assert_eq!(docs_body, docs_original);
        assert_event_routing(&docs_event_log_path, "request_seen", "protected_upstream");
        let docs_request_event = first_event_of_type(&docs_event_log_path, "request_seen");
        assert_eq!(
            docs_request_event["kind"]["trusted_ingress_soften_match"]["label"],
            "docs-crawler"
        );
        assert_eq!(
            docs_request_event["kind"]["trusted_ingress_soften_match"]["request_path_softened"],
            true
        );
        assert_event_type_absent(&docs_event_log_path, "bait_exposed");
        let docs_surface_debug = first_debug_event(&docs_debug_log_path, "surface_action_selected");
        assert_eq!(
            docs_surface_debug["fields"]["trusted_ingress_softened_surface"],
            true
        );
        assert_eq!(
            docs_surface_debug["fields"]["trusted_ingress_local_soften_path_prefixes"],
            json!(["/docs"])
        );

        let openapi_event_log_path = unique_temp_path("scoped-trusted-openapi-events.jsonl");
        let openapi_debug_log_path = unique_temp_path("scoped-trusted-openapi-debug.jsonl");
        let openapi_original =
            r#"{"openapi":"3.0.3","info":{"title":"demo","version":"0"},"paths":{}}"#;
        let (openapi_upstream, openapi_upstream_handle) =
            spawn_upstream(json_response(openapi_original));
        let mut openapi_runtime = test_runtime_with_m1_controller_and_debug_log(
            openapi_upstream,
            &openapi_event_log_path,
            &openapi_debug_log_path,
            unique_temp_path("scoped-trusted-openapi-control.txt"),
        );
        openapi_runtime.ingress_identity_resolver = Arc::new(must_ok(
            ingress_identity::load_ingress_identity_resolver(&config_path),
            "ingress trust config should load",
        ));

        let openapi_response = parse_downstream_response(&run_runtime_request(
            openapi_runtime,
            &request_with_cookie(
                "GET",
                "/openapi.json",
                &cookie_header(),
                &[("X-Eidolon-Trusted-Actor", "docs-crawler")],
            ),
        ));
        openapi_upstream_handle
            .join()
            .expect("upstream thread should join");
        let openapi_body: Value =
            serde_json::from_slice(&openapi_response.body).expect("body should be json");

        assert_eq!(openapi_response.status, 200);
        assert!(openapi_body["paths"]["/api/v2/import/reconcile"].is_object());
        let openapi_request_event = first_event_of_type(&openapi_event_log_path, "request_seen");
        assert_eq!(
            openapi_request_event["kind"]["trusted_ingress_soften_match"]["label"],
            "docs-crawler"
        );
        assert_eq!(
            openapi_request_event["kind"]["trusted_ingress_soften_match"]["request_path_softened"],
            false
        );
        assert_event_routing(
            &openapi_event_log_path,
            "policy_decision",
            "rewritten_upstream",
        );
        let exposure = first_event_of_type(&openapi_event_log_path, "bait_exposed");
        assert_eq!(exposure["kind"]["surface"], "/openapi.json");
        let openapi_surface_debug =
            first_debug_event(&openapi_debug_log_path, "surface_action_selected");
        assert_eq!(
            openapi_surface_debug["fields"]["trusted_ingress_softened_surface"],
            false
        );
        assert_eq!(
            openapi_surface_debug["fields"]["trusted_ingress_local_soften_path_prefixes"],
            json!(["/docs"])
        );
    }

    #[test]
    fn local_allowlist_source_cidrs_must_match_client_peer() {
        let loopback_config_path = write_ingress_trust_config(
            r#"{
              "schema_version": 1,
              "entries": [
                {
                  "label": "docs-crawler",
                  "source": "local_allowlist",
                  "trust_tier": "allowlisted",
                  "methods": ["GET"],
                  "path_prefixes": ["/docs"],
                  "bait_soften_path_prefixes": ["/docs"],
                  "source_cidrs": ["127.0.0.1"],
                  "required_headers": [
                    { "name": "X-Eidolon-Trusted-Actor", "value": "docs-crawler" }
                  ]
                }
              ]
            }"#,
        );

        let loopback_event_log_path = unique_temp_path("trusted-source-cidr-loopback-events.jsonl");
        let loopback_debug_log_path = unique_temp_path("trusted-source-cidr-loopback-debug.jsonl");
        let loopback_original =
            r#"<!doctype html><html><body><main>docs source scope</main></body></html>"#;
        let (loopback_upstream, loopback_upstream_handle) =
            spawn_upstream(html_response(loopback_original));
        let mut loopback_runtime = test_runtime_with_m1_controller_and_debug_log(
            loopback_upstream,
            &loopback_event_log_path,
            &loopback_debug_log_path,
            unique_temp_path("trusted-source-cidr-loopback-control.txt"),
        );
        loopback_runtime.ingress_identity_resolver = Arc::new(must_ok(
            ingress_identity::load_ingress_identity_resolver(&loopback_config_path),
            "ingress trust config should load",
        ));

        let loopback_response = parse_downstream_response(&run_runtime_request(
            loopback_runtime,
            &request_with_cookie(
                "GET",
                "/docs?topic=imports",
                &cookie_header(),
                &[("X-Eidolon-Trusted-Actor", "docs-crawler")],
            ),
        ));
        loopback_upstream_handle
            .join()
            .expect("upstream thread should join");
        let loopback_body = String::from_utf8(loopback_response.body).expect("body should be utf8");

        assert_eq!(loopback_response.status, 200);
        assert_eq!(loopback_body, loopback_original);
        let loopback_request_event = first_event_of_type(&loopback_event_log_path, "request_seen");
        assert_eq!(
            loopback_request_event["kind"]["ingress_identity"]["source"],
            "local_allowlist"
        );
        assert_eq!(
            loopback_request_event["kind"]["trusted_ingress_soften_match"]["label"],
            "docs-crawler"
        );
        assert_event_type_absent(&loopback_event_log_path, "bait_exposed");

        let disallowed_config_path = write_ingress_trust_config(
            r#"{
              "schema_version": 1,
              "entries": [
                {
                  "label": "docs-crawler",
                  "source": "local_allowlist",
                  "trust_tier": "allowlisted",
                  "methods": ["GET"],
                  "path_prefixes": ["/docs"],
                  "bait_soften_path_prefixes": ["/docs"],
                  "source_cidrs": ["10.0.0.0/8"],
                  "required_headers": [
                    { "name": "X-Eidolon-Trusted-Actor", "value": "docs-crawler" }
                  ]
                }
              ]
            }"#,
        );

        let disallowed_event_log_path =
            unique_temp_path("trusted-source-cidr-disallowed-events.jsonl");
        let disallowed_debug_log_path =
            unique_temp_path("trusted-source-cidr-disallowed-debug.jsonl");
        let disallowed_original =
            r#"<!doctype html><html><body><main>docs source scope disallowed</main></body></html>"#;
        let (disallowed_upstream, disallowed_upstream_handle) =
            spawn_upstream(html_response(disallowed_original));
        let mut disallowed_runtime = test_runtime_with_m1_controller_and_debug_log(
            disallowed_upstream,
            &disallowed_event_log_path,
            &disallowed_debug_log_path,
            unique_temp_path("trusted-source-cidr-disallowed-control.txt"),
        );
        disallowed_runtime.ingress_identity_resolver = Arc::new(must_ok(
            ingress_identity::load_ingress_identity_resolver(&disallowed_config_path),
            "ingress trust config should load",
        ));

        let disallowed_response = parse_downstream_response(&run_runtime_request(
            disallowed_runtime,
            &request_with_cookie(
                "GET",
                "/docs?topic=imports",
                &cookie_header(),
                &[("X-Eidolon-Trusted-Actor", "docs-crawler")],
            ),
        ));
        disallowed_upstream_handle
            .join()
            .expect("upstream thread should join");
        let disallowed_body =
            String::from_utf8(disallowed_response.body).expect("body should be utf8");

        assert_eq!(disallowed_response.status, 200);
        assert_ne!(disallowed_body, disallowed_original);
        let disallowed_request_event =
            first_event_of_type(&disallowed_event_log_path, "request_seen");
        assert_eq!(
            disallowed_request_event["kind"]["ingress_identity"]["source"],
            "none"
        );
        assert_eq!(
            disallowed_request_event["kind"]["local_ingress_trust_scope_rejection"]["label"],
            "docs-crawler"
        );
        assert_eq!(
            disallowed_request_event["kind"]["local_ingress_trust_scope_rejection"]["reason"],
            "source_cidr_mismatch"
        );
        assert!(disallowed_request_event["kind"]["trusted_ingress_soften_match"].is_null());
        assert_event_routing(
            &disallowed_event_log_path,
            "policy_decision",
            "rewritten_upstream",
        );
        let disallowed_surface_debug =
            first_debug_event(&disallowed_debug_log_path, "surface_action_selected");
        assert_eq!(
            disallowed_surface_debug["fields"]["trusted_ingress_softened_surface"],
            false
        );
        let disallowed_request_debug =
            first_debug_event(&disallowed_debug_log_path, "request_received");
        assert_eq!(
            disallowed_request_debug["fields"]["local_ingress_trust_scope_rejection"]["reason"],
            "source_cidr_mismatch"
        );
    }

    #[test]
    fn local_allowlist_hosts_must_match_request_host() {
        let allowed_config_path = write_ingress_trust_config(
            r#"{
              "schema_version": 1,
              "entries": [
                {
                  "label": "docs-crawler",
                  "source": "local_allowlist",
                  "trust_tier": "allowlisted",
                  "methods": ["GET"],
                  "path_prefixes": ["/docs"],
                  "bait_soften_path_prefixes": ["/docs"],
                  "hosts": ["proxy.local"],
                  "required_headers": [
                    { "name": "X-Eidolon-Trusted-Actor", "value": "docs-crawler" }
                  ]
                }
              ]
            }"#,
        );

        let allowed_event_log_path = unique_temp_path("trusted-host-allowed-events.jsonl");
        let allowed_debug_log_path = unique_temp_path("trusted-host-allowed-debug.jsonl");
        let allowed_original =
            r#"<!doctype html><html><body><main>docs host scope</main></body></html>"#;
        let (allowed_upstream, allowed_upstream_handle) =
            spawn_upstream(html_response(allowed_original));
        let mut allowed_runtime = test_runtime_with_m1_controller_and_debug_log(
            allowed_upstream,
            &allowed_event_log_path,
            &allowed_debug_log_path,
            unique_temp_path("trusted-host-allowed-control.txt"),
        );
        allowed_runtime.ingress_identity_resolver = Arc::new(must_ok(
            ingress_identity::load_ingress_identity_resolver(&allowed_config_path),
            "ingress trust config should load",
        ));

        let allowed_response = parse_downstream_response(&run_runtime_request(
            allowed_runtime,
            &request_with_cookie(
                "GET",
                "/docs?topic=imports",
                &cookie_header(),
                &[("X-Eidolon-Trusted-Actor", "docs-crawler")],
            ),
        ));
        allowed_upstream_handle
            .join()
            .expect("upstream thread should join");
        let allowed_body = String::from_utf8(allowed_response.body).expect("body should be utf8");

        assert_eq!(allowed_response.status, 200);
        assert_eq!(allowed_body, allowed_original);
        let allowed_request_event = first_event_of_type(&allowed_event_log_path, "request_seen");
        assert_eq!(
            allowed_request_event["kind"]["ingress_identity"]["source"],
            "local_allowlist"
        );
        assert_eq!(
            allowed_request_event["kind"]["trusted_ingress_soften_match"]["label"],
            "docs-crawler"
        );

        let disallowed_config_path = write_ingress_trust_config(
            r#"{
              "schema_version": 1,
              "entries": [
                {
                  "label": "docs-crawler",
                  "source": "local_allowlist",
                  "trust_tier": "allowlisted",
                  "methods": ["GET"],
                  "path_prefixes": ["/docs"],
                  "bait_soften_path_prefixes": ["/docs"],
                  "hosts": ["docs.example.test"],
                  "required_headers": [
                    { "name": "X-Eidolon-Trusted-Actor", "value": "docs-crawler" }
                  ]
                }
              ]
            }"#,
        );

        let disallowed_event_log_path = unique_temp_path("trusted-host-disallowed-events.jsonl");
        let disallowed_debug_log_path = unique_temp_path("trusted-host-disallowed-debug.jsonl");
        let disallowed_original =
            r#"<!doctype html><html><body><main>docs host scope disallowed</main></body></html>"#;
        let (disallowed_upstream, disallowed_upstream_handle) =
            spawn_upstream(html_response(disallowed_original));
        let mut disallowed_runtime = test_runtime_with_m1_controller_and_debug_log(
            disallowed_upstream,
            &disallowed_event_log_path,
            &disallowed_debug_log_path,
            unique_temp_path("trusted-host-disallowed-control.txt"),
        );
        disallowed_runtime.ingress_identity_resolver = Arc::new(must_ok(
            ingress_identity::load_ingress_identity_resolver(&disallowed_config_path),
            "ingress trust config should load",
        ));

        let disallowed_response = parse_downstream_response(&run_runtime_request(
            disallowed_runtime,
            &request_with_cookie(
                "GET",
                "/docs?topic=imports",
                &cookie_header(),
                &[("X-Eidolon-Trusted-Actor", "docs-crawler")],
            ),
        ));
        disallowed_upstream_handle
            .join()
            .expect("upstream thread should join");
        let disallowed_body =
            String::from_utf8(disallowed_response.body).expect("body should be utf8");

        assert_eq!(disallowed_response.status, 200);
        assert_ne!(disallowed_body, disallowed_original);
        let disallowed_request_event =
            first_event_of_type(&disallowed_event_log_path, "request_seen");
        assert_eq!(
            disallowed_request_event["kind"]["ingress_identity"]["source"],
            "none"
        );
        assert_eq!(
            disallowed_request_event["kind"]["local_ingress_trust_scope_rejection"]["label"],
            "docs-crawler"
        );
        assert_eq!(
            disallowed_request_event["kind"]["local_ingress_trust_scope_rejection"]["reason"],
            "host_mismatch"
        );
        assert_eq!(
            disallowed_request_event["kind"]["local_ingress_trust_scope_rejection"]["hosts"][0],
            "docs.example.test"
        );
        assert!(disallowed_request_event["kind"]["trusted_ingress_soften_match"].is_null());
        let disallowed_surface_debug =
            first_debug_event(&disallowed_debug_log_path, "request_received");
        assert_eq!(
            disallowed_surface_debug["fields"]["request_host"],
            "proxy.local"
        );
        assert_eq!(
            disallowed_surface_debug["fields"]["local_ingress_trust_scope_rejection"]["reason"],
            "host_mismatch"
        );
    }

    #[test]
    fn local_allowlist_user_agents_must_match_request_user_agent() {
        let allowed_config_path = write_ingress_trust_config(
            r#"{
              "schema_version": 1,
              "entries": [
                {
                  "label": "docs-crawler",
                  "source": "local_allowlist",
                  "trust_tier": "allowlisted",
                  "methods": ["GET"],
                  "path_prefixes": ["/docs"],
                  "bait_soften_path_prefixes": ["/docs"],
                  "user_agent_substrings": ["eidolon-docs-crawler"],
                  "required_headers": [
                    { "name": "X-Eidolon-Trusted-Actor", "value": "docs-crawler" }
                  ]
                }
              ]
            }"#,
        );

        let allowed_event_log_path = unique_temp_path("trusted-ua-allowed-events.jsonl");
        let allowed_debug_log_path = unique_temp_path("trusted-ua-allowed-debug.jsonl");
        let allowed_original =
            r#"<!doctype html><html><body><main>docs ua scope</main></body></html>"#;
        let (allowed_upstream, allowed_upstream_handle) =
            spawn_upstream(html_response(allowed_original));
        let mut allowed_runtime = test_runtime_with_m1_controller_and_debug_log(
            allowed_upstream,
            &allowed_event_log_path,
            &allowed_debug_log_path,
            unique_temp_path("trusted-ua-allowed-control.txt"),
        );
        allowed_runtime.ingress_identity_resolver = Arc::new(must_ok(
            ingress_identity::load_ingress_identity_resolver(&allowed_config_path),
            "ingress trust config should load",
        ));

        let allowed_response = parse_downstream_response(&run_runtime_request(
            allowed_runtime,
            &request_with_cookie(
                "GET",
                "/docs?topic=imports",
                &cookie_header(),
                &[
                    ("X-Eidolon-Trusted-Actor", "docs-crawler"),
                    ("User-Agent", "Eidolon-Docs-Crawler/1.0"),
                ],
            ),
        ));
        allowed_upstream_handle
            .join()
            .expect("upstream thread should join");
        let allowed_body = String::from_utf8(allowed_response.body).expect("body should be utf8");

        assert_eq!(allowed_response.status, 200);
        assert_eq!(allowed_body, allowed_original);
        let allowed_request_event = first_event_of_type(&allowed_event_log_path, "request_seen");
        assert_eq!(
            allowed_request_event["kind"]["ingress_identity"]["source"],
            "local_allowlist"
        );
        assert_eq!(
            allowed_request_event["kind"]["trusted_ingress_soften_match"]["label"],
            "docs-crawler"
        );
        assert_eq!(
            allowed_request_event["kind"]["trusted_ingress_soften_match"]["user_agent_substrings"]
                [0],
            "eidolon-docs-crawler"
        );

        let disallowed_config_path = write_ingress_trust_config(
            r#"{
              "schema_version": 1,
              "entries": [
                {
                  "label": "docs-crawler",
                  "source": "local_allowlist",
                  "trust_tier": "allowlisted",
                  "methods": ["GET"],
                  "path_prefixes": ["/docs"],
                  "bait_soften_path_prefixes": ["/docs"],
                  "user_agent_substrings": ["eidolon-docs-crawler"],
                  "required_headers": [
                    { "name": "X-Eidolon-Trusted-Actor", "value": "docs-crawler" }
                  ]
                }
              ]
            }"#,
        );

        let disallowed_event_log_path = unique_temp_path("trusted-ua-disallowed-events.jsonl");
        let disallowed_debug_log_path = unique_temp_path("trusted-ua-disallowed-debug.jsonl");
        let disallowed_original =
            r#"<!doctype html><html><body><main>docs ua scope disallowed</main></body></html>"#;
        let (disallowed_upstream, disallowed_upstream_handle) =
            spawn_upstream(html_response(disallowed_original));
        let mut disallowed_runtime = test_runtime_with_m1_controller_and_debug_log(
            disallowed_upstream,
            &disallowed_event_log_path,
            &disallowed_debug_log_path,
            unique_temp_path("trusted-ua-disallowed-control.txt"),
        );
        disallowed_runtime.ingress_identity_resolver = Arc::new(must_ok(
            ingress_identity::load_ingress_identity_resolver(&disallowed_config_path),
            "ingress trust config should load",
        ));

        let disallowed_response = parse_downstream_response(&run_runtime_request(
            disallowed_runtime,
            &request_with_cookie(
                "GET",
                "/docs?topic=imports",
                &cookie_header(),
                &[
                    ("X-Eidolon-Trusted-Actor", "docs-crawler"),
                    ("User-Agent", "Mozilla/5.0"),
                ],
            ),
        ));
        disallowed_upstream_handle
            .join()
            .expect("upstream thread should join");
        let disallowed_body =
            String::from_utf8(disallowed_response.body).expect("body should be utf8");

        assert_eq!(disallowed_response.status, 200);
        assert_ne!(disallowed_body, disallowed_original);
        let disallowed_request_event =
            first_event_of_type(&disallowed_event_log_path, "request_seen");
        assert_eq!(
            disallowed_request_event["kind"]["ingress_identity"]["source"],
            "none"
        );
        assert_eq!(
            disallowed_request_event["kind"]["local_ingress_trust_scope_rejection"]["label"],
            "docs-crawler"
        );
        assert_eq!(
            disallowed_request_event["kind"]["local_ingress_trust_scope_rejection"]["reason"],
            "user_agent_mismatch"
        );
        assert_eq!(
            disallowed_request_event["kind"]["local_ingress_trust_scope_rejection"]
                ["user_agent_substrings"][0],
            "eidolon-docs-crawler"
        );
        assert!(disallowed_request_event["kind"]["trusted_ingress_soften_match"].is_null());
        let disallowed_request_debug =
            first_debug_event(&disallowed_debug_log_path, "request_received");
        assert_eq!(
            disallowed_request_debug["fields"]["local_ingress_trust_scope_rejection"]["reason"],
            "user_agent_mismatch"
        );
    }

    #[test]
    fn local_allowlist_required_headers_must_match() {
        let config_path = write_ingress_trust_config(
            r#"{
              "schema_version": 1,
              "entries": [
                {
                  "label": "docs-crawler",
                  "source": "local_allowlist",
                  "trust_tier": "allowlisted",
                  "methods": ["GET"],
                  "path_prefixes": ["/docs"],
                  "bait_soften_path_prefixes": ["/docs"],
                  "required_headers": [
                    { "name": "X-Eidolon-Trusted-Actor", "value": "docs-crawler" }
                  ]
                }
              ]
            }"#,
        );

        let allowed_event_log_path =
            unique_temp_path("trusted-required-header-allowed-events.jsonl");
        let allowed_debug_log_path =
            unique_temp_path("trusted-required-header-allowed-debug.jsonl");
        let allowed_original =
            r#"<!doctype html><html><body><main>docs required header scope</main></body></html>"#;
        let (allowed_upstream, allowed_upstream_handle) =
            spawn_upstream(html_response(allowed_original));
        let mut allowed_runtime = test_runtime_with_m1_controller_and_debug_log(
            allowed_upstream,
            &allowed_event_log_path,
            &allowed_debug_log_path,
            unique_temp_path("trusted-required-header-allowed-control.txt"),
        );
        allowed_runtime.ingress_identity_resolver = Arc::new(must_ok(
            ingress_identity::load_ingress_identity_resolver(&config_path),
            "ingress trust config should load",
        ));

        let allowed_response = parse_downstream_response(&run_runtime_request(
            allowed_runtime,
            &request_with_cookie(
                "GET",
                "/docs?topic=imports",
                &cookie_header(),
                &[("X-Eidolon-Trusted-Actor", "docs-crawler")],
            ),
        ));
        allowed_upstream_handle
            .join()
            .expect("upstream thread should join");
        let allowed_body = String::from_utf8(allowed_response.body).expect("body should be utf8");

        assert_eq!(allowed_response.status, 200);
        assert_eq!(allowed_body, allowed_original);
        let allowed_request_event = first_event_of_type(&allowed_event_log_path, "request_seen");
        assert_eq!(
            allowed_request_event["kind"]["ingress_identity"]["source"],
            "local_allowlist"
        );
        assert_eq!(
            allowed_request_event["kind"]["trusted_ingress_soften_match"]["label"],
            "docs-crawler"
        );
        assert_eq!(
            allowed_request_event["kind"]["trusted_ingress_soften_match"]["required_header_names"]
                [0],
            "X-Eidolon-Trusted-Actor"
        );
        assert_eq!(
            allowed_request_event["kind"]["trusted_ingress_soften_match"]["methods"][0],
            "GET"
        );

        let missing_event_log_path =
            unique_temp_path("trusted-required-header-missing-events.jsonl");
        let missing_debug_log_path =
            unique_temp_path("trusted-required-header-missing-debug.jsonl");
        let missing_original = r#"<!doctype html><html><body><main>docs required header scope missing</main></body></html>"#;
        let (missing_upstream, missing_upstream_handle) =
            spawn_upstream(html_response(missing_original));
        let mut missing_runtime = test_runtime_with_m1_controller_and_debug_log(
            missing_upstream,
            &missing_event_log_path,
            &missing_debug_log_path,
            unique_temp_path("trusted-required-header-missing-control.txt"),
        );
        missing_runtime.ingress_identity_resolver = Arc::new(must_ok(
            ingress_identity::load_ingress_identity_resolver(&config_path),
            "ingress trust config should load",
        ));

        let missing_response = parse_downstream_response(&run_runtime_request(
            missing_runtime,
            &request_with_cookie("GET", "/docs?topic=imports", &cookie_header(), &[]),
        ));
        missing_upstream_handle
            .join()
            .expect("upstream thread should join");
        let missing_body = String::from_utf8(missing_response.body).expect("body should be utf8");

        assert_eq!(missing_response.status, 200);
        assert_ne!(missing_body, missing_original);
        let missing_request_event = first_event_of_type(&missing_event_log_path, "request_seen");
        assert_eq!(
            missing_request_event["kind"]["ingress_identity"]["source"],
            "none"
        );
        assert_eq!(
            missing_request_event["kind"]["local_ingress_trust_scope_rejection"]["reason"],
            "required_header_missing"
        );
        assert_eq!(
            missing_request_event["kind"]["local_ingress_trust_scope_rejection"]
                ["required_header_names"][0],
            "X-Eidolon-Trusted-Actor"
        );
        assert!(missing_request_event["kind"]["trusted_ingress_soften_match"].is_null());
        let missing_request_debug = first_debug_event(&missing_debug_log_path, "request_received");
        assert_eq!(
            missing_request_debug["fields"]["local_ingress_trust_scope_rejection"]["reason"],
            "required_header_missing"
        );

        let wrong_event_log_path = unique_temp_path("trusted-required-header-wrong-events.jsonl");
        let wrong_debug_log_path = unique_temp_path("trusted-required-header-wrong-debug.jsonl");
        let wrong_original = r#"<!doctype html><html><body><main>docs required header scope wrong</main></body></html>"#;
        let (wrong_upstream, wrong_upstream_handle) = spawn_upstream(html_response(wrong_original));
        let mut wrong_runtime = test_runtime_with_m1_controller_and_debug_log(
            wrong_upstream,
            &wrong_event_log_path,
            &wrong_debug_log_path,
            unique_temp_path("trusted-required-header-wrong-control.txt"),
        );
        wrong_runtime.ingress_identity_resolver = Arc::new(must_ok(
            ingress_identity::load_ingress_identity_resolver(&config_path),
            "ingress trust config should load",
        ));

        let wrong_response = parse_downstream_response(&run_runtime_request(
            wrong_runtime,
            &request_with_cookie(
                "GET",
                "/docs?topic=imports",
                &cookie_header(),
                &[("X-Eidolon-Trusted-Actor", "wrong-crawler")],
            ),
        ));
        wrong_upstream_handle
            .join()
            .expect("upstream thread should join");
        let wrong_body = String::from_utf8(wrong_response.body).expect("body should be utf8");

        assert_eq!(wrong_response.status, 200);
        assert_ne!(wrong_body, wrong_original);
        let wrong_request_event = first_event_of_type(&wrong_event_log_path, "request_seen");
        assert_eq!(
            wrong_request_event["kind"]["ingress_identity"]["source"],
            "none"
        );
        assert_eq!(
            wrong_request_event["kind"]["local_ingress_trust_scope_rejection"]["reason"],
            "required_header_value_mismatch"
        );
        assert_eq!(
            wrong_request_event["kind"]["local_ingress_trust_scope_rejection"]
                ["required_header_names"][0],
            "X-Eidolon-Trusted-Actor"
        );
        assert!(wrong_request_event["kind"]["trusted_ingress_soften_match"].is_null());
        let wrong_request_debug = first_debug_event(&wrong_debug_log_path, "request_received");
        assert_eq!(
            wrong_request_debug["fields"]["local_ingress_trust_scope_rejection"]["reason"],
            "required_header_value_mismatch"
        );
    }

    #[test]
    fn local_allowlist_path_scope_mismatches_are_exposed() {
        let config_path = write_ingress_trust_config(
            r#"{
              "schema_version": 1,
              "entries": [
                {
                  "label": "docs-crawler",
                  "source": "local_allowlist",
                  "trust_tier": "allowlisted",
                  "methods": ["GET"],
                  "path_prefixes": ["/docs", "/openapi.json"],
                  "bait_soften_path_prefixes": ["/docs"],
                  "required_headers": [
                    { "name": "X-Eidolon-Trusted-Actor", "value": "docs-crawler" }
                  ]
                }
              ]
            }"#,
        );

        let event_log_path = unique_temp_path("trusted-path-scope-events.jsonl");
        let debug_log_path = unique_temp_path("trusted-path-scope-debug.jsonl");
        let original = r#"<!doctype html><html><body><main>linked route path scope mismatch</main></body></html>"#;
        let mut runtime = test_runtime_with_m1_controller_and_debug_log(
            closed_upstream(),
            &event_log_path,
            &debug_log_path,
            unique_temp_path("trusted-path-scope-control.txt"),
        );
        runtime.ingress_identity_resolver = Arc::new(must_ok(
            ingress_identity::load_ingress_identity_resolver(&config_path),
            "ingress trust config should load",
        ));

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &request_with_cookie(
                "GET",
                "/customer/import-recovery-checklist?topic=imports",
                &cookie_header(),
                &[("X-Eidolon-Trusted-Actor", "docs-crawler")],
            ),
        ));
        let body = String::from_utf8(response.body).expect("body should be utf8");

        assert_eq!(response.status, 200);
        assert_ne!(body, original);
        let request_event = first_event_of_type(&event_log_path, "request_seen");
        assert_eq!(request_event["kind"]["ingress_identity"]["source"], "none");
        assert_eq!(
            request_event["kind"]["local_ingress_trust_scope_rejection"]["label"],
            "docs-crawler"
        );
        assert_eq!(
            request_event["kind"]["local_ingress_trust_scope_rejection"]["reason"],
            "path_mismatch"
        );
        assert_eq!(
            request_event["kind"]["local_ingress_trust_scope_rejection"]["methods"][0],
            "GET"
        );
        assert_eq!(
            request_event["kind"]["local_ingress_trust_scope_rejection"]["path_prefixes"],
            serde_json::json!(["/docs", "/openapi.json"])
        );
        assert!(request_event["kind"]["trusted_ingress_soften_match"].is_null());
        let request_debug = first_debug_event(&debug_log_path, "request_received");
        assert_eq!(
            request_debug["fields"]["local_ingress_trust_scope_rejection"]["reason"],
            "path_mismatch"
        );
        let surface_debug = first_debug_event(&debug_log_path, "surface_action_selected");
        assert_eq!(
            surface_debug["fields"]["trusted_ingress_softened_surface"],
            false
        );
    }

    #[test]
    fn local_allowlist_method_scope_mismatches_are_exposed() {
        let config_path = write_ingress_trust_config(
            r#"{
              "schema_version": 1,
              "entries": [
                {
                  "label": "docs-crawler",
                  "source": "local_allowlist",
                  "trust_tier": "allowlisted",
                  "methods": ["GET"],
                  "path_prefixes": ["/docs", "/openapi.json"],
                  "bait_soften_path_prefixes": ["/docs"],
                  "required_headers": [
                    { "name": "X-Eidolon-Trusted-Actor", "value": "docs-crawler" }
                  ]
                }
              ]
            }"#,
        );

        let event_log_path = unique_temp_path("trusted-method-scope-events.jsonl");
        let debug_log_path = unique_temp_path("trusted-method-scope-debug.jsonl");
        let original =
            r#"<!doctype html><html><body><main>docs method scope mismatch</main></body></html>"#;
        let (upstream, upstream_handle) = spawn_upstream(html_response(original));
        let mut runtime = test_runtime_with_m1_controller_and_debug_log(
            upstream,
            &event_log_path,
            &debug_log_path,
            unique_temp_path("trusted-method-scope-control.txt"),
        );
        runtime.ingress_identity_resolver = Arc::new(must_ok(
            ingress_identity::load_ingress_identity_resolver(&config_path),
            "ingress trust config should load",
        ));

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &request_with_cookie(
                "POST",
                "/docs?topic=imports",
                &cookie_header(),
                &[("X-Eidolon-Trusted-Actor", "docs-crawler")],
            ),
        ));
        upstream_handle.join().expect("upstream thread should join");
        assert_eq!(response.status, 200);
        let request_event = first_event_of_type(&event_log_path, "request_seen");
        assert_eq!(request_event["kind"]["ingress_identity"]["source"], "none");
        assert_eq!(
            request_event["kind"]["local_ingress_trust_scope_rejection"]["label"],
            "docs-crawler"
        );
        assert_eq!(
            request_event["kind"]["local_ingress_trust_scope_rejection"]["reason"],
            "method_mismatch"
        );
        assert_eq!(
            request_event["kind"]["local_ingress_trust_scope_rejection"]["methods"],
            serde_json::json!(["GET"])
        );
        assert_eq!(
            request_event["kind"]["local_ingress_trust_scope_rejection"]["path_prefixes"],
            serde_json::json!(["/docs", "/openapi.json"])
        );
        assert!(request_event["kind"]["trusted_ingress_soften_match"].is_null());
        let request_debug = first_debug_event(&debug_log_path, "request_received");
        assert_eq!(
            request_debug["fields"]["local_ingress_trust_scope_rejection"]["reason"],
            "method_mismatch"
        );
        let surface_debug = first_debug_event(&debug_log_path, "surface_action_selected");
        assert_eq!(
            surface_debug["fields"]["trusted_ingress_softened_surface"],
            false
        );
    }

    #[test]
    fn local_allowlist_not_yet_active_entries_remain_baited() {
        let config_path = write_ingress_trust_config(
            r#"{
              "schema_version": 1,
              "entries": [
                {
                  "label": "docs-crawler",
                  "source": "local_allowlist",
                  "trust_tier": "allowlisted",
                  "not_before": "2999-01-01T00:00:00Z",
                  "methods": ["GET"],
                  "path_prefixes": ["/docs"],
                  "bait_soften_path_prefixes": ["/docs"],
                  "required_headers": [
                    { "name": "X-Eidolon-Trusted-Actor", "value": "docs-crawler" }
                  ]
                }
              ]
            }"#,
        );

        let event_log_path = unique_temp_path("trusted-not-before-events.jsonl");
        let debug_log_path = unique_temp_path("trusted-not-before-debug.jsonl");
        let original =
            r#"<!doctype html><html><body><main>docs not-before scope</main></body></html>"#;
        let (upstream, upstream_handle) = spawn_upstream(html_response(original));
        let mut runtime = test_runtime_with_m1_controller_and_debug_log(
            upstream,
            &event_log_path,
            &debug_log_path,
            unique_temp_path("trusted-not-before-control.txt"),
        );
        runtime.ingress_identity_resolver = Arc::new(must_ok(
            ingress_identity::load_ingress_identity_resolver(&config_path),
            "ingress trust config should load",
        ));

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &request_with_cookie(
                "GET",
                "/docs?topic=imports",
                &cookie_header(),
                &[("X-Eidolon-Trusted-Actor", "docs-crawler")],
            ),
        ));
        upstream_handle.join().expect("upstream thread should join");
        let body = String::from_utf8(response.body).expect("body should be utf8");

        assert_eq!(response.status, 200);
        assert_ne!(body, original);
        let request_event = first_event_of_type(&event_log_path, "request_seen");
        assert_eq!(request_event["kind"]["ingress_identity"]["source"], "none");
        assert_eq!(
            request_event["kind"]["local_ingress_trust_scope_rejection"]["label"],
            "docs-crawler"
        );
        assert_eq!(
            request_event["kind"]["local_ingress_trust_scope_rejection"]["reason"],
            "not_yet_active"
        );
        assert_eq!(
            request_event["kind"]["local_ingress_trust_scope_rejection"]["not_before"],
            "2999-01-01T00:00:00Z"
        );
        assert!(request_event["kind"]["trusted_ingress_soften_match"].is_null());
        let request_debug = first_debug_event(&debug_log_path, "request_received");
        assert_eq!(
            request_debug["fields"]["local_ingress_trust_scope_rejection"]["reason"],
            "not_yet_active"
        );
        assert_eq!(
            request_debug["fields"]["local_ingress_trust_scope_rejection"]["not_before"],
            "2999-01-01T00:00:00Z"
        );
    }

    #[test]
    fn runtime_default_controller_serves_demo_owned_surface() {
        let event_log_path = unique_temp_path("default-owned-events.jsonl");
        let runtime = test_runtime_with_m1_controller(
            must_ok(
                parse_upstream(DEFAULT_UPSTREAM, false),
                "default upstream should parse",
            ),
            &event_log_path,
            unique_temp_path("default-owned-control.txt"),
        );

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &get_request("/docs/legacy-import"),
        ));
        let body = String::from_utf8(response.body).expect("body should be utf8");

        assert_eq!(response.status, 200);
        assert!(body.contains("/api/v2/import/reconcile"));
        assert!(body.contains("X-Migration-Trace"));
        assert_event_routing(&event_log_path, "request_seen", "eidolon_owned");
        assert_event_routing(&event_log_path, "policy_decision", "eidolon_owned");
        assert_event_routing(&event_log_path, "response_served", "eidolon_owned");

        let exposure = first_event_of_type(&event_log_path, "bait_exposed");
        assert_eq!(exposure["kind"]["bait_id"], "rel_2025_04_b7f2");
        assert_eq!(exposure["kind"]["surface"], "/docs/legacy-import");
        assert!(exposure["kind"]["exposure_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("exp-")));
    }

    #[test]
    fn runtime_default_controller_rewrites_demo_openapi_when_requested() {
        let event_log_path = unique_temp_path("default-rewrite-events.jsonl");
        let original = r#"{"openapi":"3.0.3","info":{"title":"demo","version":"0"},"paths":{}}"#;
        let (upstream, upstream_handle) = spawn_upstream(json_response(original));
        let runtime = test_runtime_with_m1_controller(
            upstream,
            &event_log_path,
            unique_temp_path("default-rewrite-control.txt"),
        );

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &get_request("/openapi.json?eidolon_surface=legacy-import"),
        ));
        must_join(upstream_handle.join(), "upstream thread should join");
        let rewritten: Value = serde_json::from_slice(&response.body).unwrap();

        assert!(rewritten["paths"]["/api/v2/import/reconcile"].is_object());
        let operation = &rewritten["paths"]["/api/v2/import/reconcile"]["post"];
        assert_eq!(
            operation["summary"].as_str(),
            Some("Customer import reconciliation endpoint")
        );
        assert!(operation["description"]
            .as_str()
            .is_some_and(|description| description.contains("customer-controlled import")));
        assert_eq!(
            operation["tags"],
            json!(["customer-imports", "legacy-reconciliation"])
        );
        assert_eq!(operation["parameters"][0]["name"], "X-OpenAPI-Trace");
        assert!(operation["parameters"][0]["description"]
            .as_str()
            .is_some_and(|description| description.contains("external client requests")));
        assert_eq!(
            operation["requestBody"]["content"]["application/json"]["schema"]["required"],
            json!(["source_url", "tenant_id"])
        );
        assert_event_routing(&event_log_path, "request_seen", "protected_upstream");
        assert_event_routing(&event_log_path, "policy_decision", "rewritten_upstream");
        assert_event_routing(&event_log_path, "response_served", "rewritten_upstream");

        let exposure = first_event_of_type(&event_log_path, "bait_exposed");
        assert_eq!(exposure["kind"]["bait_id"], "openapi_reconcile_trace");
        assert_eq!(
            exposure["kind"]["surface"],
            "/openapi.json?eidolon_surface=<redacted>"
        );
    }

    #[test]
    fn runtime_default_controller_rewrites_plain_openapi_for_discovery() {
        let event_log_path = unique_temp_path("plain-openapi-rewrite-events.jsonl");
        let original = r#"{"openapi":"3.0.3","info":{"title":"demo","version":"0"},"paths":{}}"#;
        let (upstream, upstream_handle) = spawn_upstream(json_response(original));
        let runtime = test_runtime_with_m1_controller(
            upstream,
            &event_log_path,
            unique_temp_path("plain-openapi-rewrite-control.txt"),
        );

        let response =
            parse_downstream_response(&run_runtime_request(runtime, &get_request("/openapi.json")));
        must_join(upstream_handle.join(), "upstream thread should join");
        let rewritten: Value = serde_json::from_slice(&response.body).unwrap();

        assert!(rewritten["paths"]["/api/v2/import/reconcile"].is_object());
        assert_eq!(
            rewritten["paths"]["/api/v2/import/reconcile"]["post"]["parameters"][0]["name"],
            "X-OpenAPI-Trace"
        );
        assert!(rewritten["paths"]["/api/v2/import/reconcile"]["post"]["requestBody"].is_object());
        assert_event_routing(&event_log_path, "request_seen", "protected_upstream");
        assert_event_routing(&event_log_path, "policy_decision", "rewritten_upstream");
        assert_event_routing(&event_log_path, "response_served", "rewritten_upstream");

        let exposure = first_event_of_type(&event_log_path, "bait_exposed");
        assert_eq!(exposure["kind"]["bait_id"], "openapi_reconcile_trace");
        assert_eq!(exposure["kind"]["surface"], "/openapi.json");
    }

    #[test]
    fn runtime_default_controller_does_not_rewrite_unknown_openapi_query() {
        let event_log_path = unique_temp_path("unknown-openapi-query-events.jsonl");
        let original = r#"{"openapi":"3.0.3","info":{"title":"demo","version":"0"},"paths":{}}"#;
        let (upstream, upstream_handle) = spawn_upstream(json_response(original));
        let runtime = test_runtime_with_m1_controller(
            upstream,
            &event_log_path,
            unique_temp_path("unknown-openapi-query-control.txt"),
        );

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &get_request("/openapi.json?version=prod"),
        ));
        upstream_handle.join().expect("upstream thread should join");

        assert_eq!(response.body, original.as_bytes());
        assert_event_routing(&event_log_path, "request_seen", "protected_upstream");
        assert_event_routing(&event_log_path, "response_served", "protected_upstream");
        assert_event_type_absent(&event_log_path, "policy_decision");
        assert_event_type_absent(&event_log_path, "bait_exposed");
    }

    #[test]
    fn runtime_default_controller_rewrites_docs_with_m3_discovery_links() {
        let event_log_path = unique_temp_path("docs-discovery-events.jsonl");
        let original = r#"<!doctype html><html><body><main>docs</main></body></html>"#;
        let (upstream, upstream_handle) = spawn_upstream(html_response(original));
        let runtime = test_runtime_with_m1_controller(
            upstream,
            &event_log_path,
            unique_temp_path("docs-discovery-control.txt"),
        );

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &get_request("/docs?topic=imports"),
        ));
        upstream_handle.join().expect("upstream thread should join");
        let body = must_ok(String::from_utf8(response.body), "body should be utf8");

        assert_eq!(response.status, 200);
        assert!(body.contains("Customer import recovery controls"));
        assert!(body.contains("Customer import notes"));
        assert!(body.contains("Customer import recovery checklist"));
        assert!(body.contains("Import reconciliation token note"));
        assert!(body.contains("Customer import helper manifest"));
        assert!(body.contains("/docs/legacy-import"));
        assert!(body.contains("/docs/service-token"));
        assert!(body.contains("/customer/import-recovery-checklist"));
        assert!(body.contains("/assets/import-helper.js"));
        assert_event_routing(&event_log_path, "request_seen", "protected_upstream");
        assert_event_routing(&event_log_path, "policy_decision", "rewritten_upstream");
        assert_event_routing(&event_log_path, "response_served", "rewritten_upstream");
        assert_event_type_absent(&event_log_path, "bait_exposed");
    }

    #[test]
    fn runtime_default_controller_does_not_rewrite_non_success_docs() {
        let event_log_path = unique_temp_path("docs-non-success-events.jsonl");
        let original = r#"<!doctype html><html><body><main>not found</main></body></html>"#;
        let (upstream, upstream_handle) =
            spawn_upstream(html_response_with_status(404, "Not Found", original));
        let runtime = test_runtime_with_m1_controller(
            upstream,
            &event_log_path,
            unique_temp_path("docs-non-success-control.txt"),
        );

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &get_request("/docs?topic=imports"),
        ));
        upstream_handle.join().expect("upstream thread should join");

        assert_eq!(response.status, 404);
        assert_eq!(response.body, original.as_bytes());
        assert_event_routing(&event_log_path, "request_seen", "protected_upstream");
        assert_policy_decision_reason_contains(&event_log_path, "non-success upstream response");
        assert_event_routing(&event_log_path, "response_served", "protected_upstream");
        assert_event_type_absent(&event_log_path, "bait_exposed");
    }

    #[test]
    fn runtime_default_controller_serves_m3_direct_bait_surfaces() {
        let event_log_path = unique_temp_path("m3-direct-surfaces-events.jsonl");
        let runtime = test_runtime_with_m1_controller(
            closed_upstream(),
            &event_log_path,
            unique_temp_path("m3-direct-surfaces-control.txt"),
        );
        let registry = BaitRegistry::m3_catalog();

        for bait_class in [
            BaitClass::Docs,
            BaitClass::HiddenRoute,
            BaitClass::FakeCredentialToken,
            BaitClass::JsDiscoveredRoute,
        ] {
            let bait = registry
                .bait_for_class(bait_class)
                .expect("M3 bait should exist");
            let response = parse_downstream_response(&run_runtime_request(
                runtime.clone(),
                &get_request(&bait.surface),
            ));
            let body = String::from_utf8(response.body).expect("body should be utf8");
            let header_name = bait.expected_action.header_name.as_deref().unwrap();
            let header_value = bait.expected_action.header_value.as_deref().unwrap();

            assert_eq!(response.status, 200);
            assert!(body.contains(header_name));
            assert!(body.contains(header_value));
            assert!(body.contains(&bait.expected_action.path));
        }

        let exposure_ids: Vec<String> = events_of_type(&event_log_path, "bait_exposed")
            .into_iter()
            .map(|event| event["kind"]["bait_id"].as_str().unwrap().to_string())
            .collect();

        assert_eq!(exposure_ids.len(), 4);
        assert!(exposure_ids.contains(&"rel_2025_04_b7f2".to_string()));
        assert!(exposure_ids.contains(&"hidden_route_trace".to_string()));
        assert!(exposure_ids.contains(&"fake_service_token".to_string()));
        assert!(exposure_ids.contains(&"js_worker_resume_trace".to_string()));
    }

    #[test]
    fn runtime_correlates_each_m3_bait_action_and_does_not_forward() {
        let baits = BaitRegistry::m3_catalog().baits().to_vec();

        for bait in baits {
            let event_log_path = unique_temp_path("m3-correlated-action-events.jsonl");
            let control_path = unique_temp_path("m3-correlated-action-control.txt");
            let cookie = cookie_header();
            let runtime = if bait.bait_class == BaitClass::OpenApi {
                let original =
                    r#"{"openapi":"3.0.3","info":{"title":"demo","version":"0"},"paths":{}}"#;
                let (upstream, upstream_handle) = spawn_upstream(json_response(original));
                let runtime =
                    test_runtime_with_m1_controller(upstream, &event_log_path, control_path);
                let exposure_response = parse_downstream_response(&run_runtime_request(
                    runtime.clone(),
                    &get_request_with_cookie(&bait.surface, &cookie),
                ));
                must_join(upstream_handle.join(), "upstream thread should join");
                assert_eq!(exposure_response.status, 200);
                runtime
            } else {
                let runtime = test_runtime_with_m1_controller(
                    closed_upstream(),
                    &event_log_path,
                    control_path,
                );
                let exposure_response = parse_downstream_response(&run_runtime_request(
                    runtime.clone(),
                    &get_request_with_cookie(&bait.surface, &cookie),
                ));
                assert_eq!(exposure_response.status, 200);
                runtime
            };
            let header_name = bait.expected_action.header_name.as_deref().unwrap();
            let header_value = bait.expected_action.header_value.as_deref().unwrap();

            let action_response = parse_downstream_response(&run_runtime_request(
                runtime,
                &post_request_with_cookie(
                    &bait.expected_action.path,
                    &cookie,
                    &[(header_name, header_value)],
                ),
            ));

            assert_eq!(action_response.status, 202);
            assert!(must_ok(
                String::from_utf8(action_response.body),
                "body should be utf8"
            )
            .contains(r#""write_committed":false"#));

            let exposure = first_event_of_type(&event_log_path, "bait_exposed");
            let action = first_event_of_type(&event_log_path, "bait_action_observed");
            assert_eq!(exposure["kind"]["bait_id"], bait.id.0);
            assert_eq!(action["kind"]["bait_id"], bait.id.0);
            assert_eq!(
                action["kind"]["exposure_id"],
                exposure["kind"]["exposure_id"]
            );
        }
    }

    #[test]
    fn runtime_default_controller_forwards_non_discovery_json_unchanged() {
        let event_log_path = unique_temp_path("default-forward-events.jsonl");
        let original = r#"{"openapi":"3.0.3","info":{"title":"demo","version":"0"},"paths":{}}"#;
        let (upstream, upstream_handle) = spawn_upstream(json_response(original));
        let runtime = test_runtime_with_m1_controller(
            upstream,
            &event_log_path,
            unique_temp_path("default-forward-control.txt"),
        );

        let response =
            parse_downstream_response(&run_runtime_request(runtime, &get_request("/schema.json")));
        must_join(upstream_handle.join(), "upstream thread should join");

        assert_eq!(response.body, original.as_bytes());
        assert_event_routing(&event_log_path, "request_seen", "protected_upstream");
        assert_event_routing(&event_log_path, "response_served", "protected_upstream");
        assert_event_type_absent(&event_log_path, "policy_decision");
        assert_event_type_absent(&event_log_path, "bait_exposed");
    }

    #[test]
    fn runtime_decodes_chunked_upstream_response_before_downstream_send() {
        let event_log_path = unique_temp_path("chunked-upstream-events.jsonl");
        let (upstream, upstream_handle) = spawn_upstream(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        );
        let runtime = test_runtime(
            upstream,
            &event_log_path,
            unique_temp_path("chunked-upstream-control.txt"),
            SurfaceAction::ProtectedUpstream,
        );

        let response =
            parse_downstream_response(&run_runtime_request(runtime, &get_request("/chunked")));
        upstream_handle.join().expect("upstream thread should join");

        assert_eq!(response.body, b"hello");
        assert!(header_values(&response, "transfer-encoding").is_empty());
        assert_eq!(header_values(&response, "content-length"), vec!["5"]);
        assert_event_routing(&event_log_path, "request_seen", "protected_upstream");
        assert_event_routing(&event_log_path, "response_served", "protected_upstream");
    }

    #[test]
    fn runtime_correlates_same_session_bait_action_and_does_not_forward() {
        let event_log_path = unique_temp_path("bait-action-events.jsonl");
        let runtime = test_runtime_with_m1_controller(
            closed_upstream(),
            &event_log_path,
            unique_temp_path("bait-action-control.txt"),
        );
        let cookie = cookie_header();

        let exposure_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &get_request_with_cookie("/docs/legacy-import", &cookie),
        ));
        let action_response = parse_downstream_response(&run_runtime_request(
            runtime,
            &post_request_with_cookie(
                "/api/v2/import/reconcile",
                &cookie,
                &[("X-Migration-Trace", "rel_2025_04_b7f2")],
            ),
        ));

        assert_eq!(exposure_response.status, 200);
        assert_eq!(action_response.status, 202);
        assert!(String::from_utf8(action_response.body)
            .expect("body should be utf8")
            .contains(r#""write_committed":false"#));

        let exposure = first_event_of_type(&event_log_path, "bait_exposed");
        let action = first_event_of_type(&event_log_path, "bait_action_observed");
        assert_eq!(action["session_id"], exposure["session_id"]);
        assert_eq!(action["kind"]["bait_id"], exposure["kind"]["bait_id"]);
        assert_eq!(
            action["kind"]["exposure_id"],
            exposure["kind"]["exposure_id"]
        );
        assert_eq!(action["kind"]["method"], "POST");
        assert_eq!(action["kind"]["path"], "/api/v2/import/reconcile");
        assert_event_routing(&event_log_path, "request_seen", "eidolon_owned");
        let policy_changed = first_event_of_type(&event_log_path, "policy_changed");
        assert_eq!(policy_changed["kind"]["from"], "observe");
        assert_eq!(policy_changed["kind"]["to"], "controlled_reality");
        assert_eq!(
            first_event_of_type(&event_log_path, "controlled_reality_entered")["policy_state"],
            "controlled_reality"
        );
        assert!(events_of_type(&event_log_path, "response_served")
            .iter()
            .any(|event| event["kind"]["routing_decision"].as_str() == Some("controlled_reality")));

        let events = event_values(&event_log_path);
        let action_index = events
            .iter()
            .position(|event| event["kind"]["type"].as_str() == Some("bait_action_observed"))
            .expect("bait action event should exist");
        assert_eq!(
            events[action_index - 1]["kind"]["type"].as_str(),
            Some("request_seen")
        );
        assert_eq!(
            events[action_index + 1]["kind"]["type"].as_str(),
            Some("policy_changed")
        );
    }

    #[test]
    fn runtime_correlates_bait_action_after_exposure_store_rebuild() {
        let event_log_path = unique_temp_path("rehydrated-bait-action-events.jsonl");
        let session_id = SessionId::new();
        let cookie = format!("eidolon_session={}", minted_cookie_value(session_id));
        let bait = BaitRegistry::m3_catalog()
            .bait_for_class(BaitClass::Docs)
            .expect("docs bait should exist")
            .clone();
        let restored_exposure_id = ExposureId("restored-exposure".to_string());

        {
            let mut event_log =
                FileEventLogWriter::open(&event_log_path).expect("event log should open");
            event_log
                .write_event(&Event::new(
                    session_id,
                    EventSource::SurfaceController,
                    PolicyState::Observe,
                    EventKind::BaitExposed {
                        bait_id: bait.id.clone(),
                        exposure_id: restored_exposure_id.clone(),
                        surface: bait.surface.clone(),
                        header_value_mint: None,
                    },
                ))
                .expect("bait exposure event should write");
        }

        let restored_exposures = BaitExposureStore::from_event_log(&event_log_path)
            .expect("bait exposure store should rebuild");
        let runtime = test_runtime_with_m1_controller_and_bait_exposures(
            closed_upstream(),
            &event_log_path,
            unique_temp_path("rehydrated-bait-action-control.txt"),
            restored_exposures,
        );
        let header_name = bait.expected_action.header_name.as_deref().unwrap();
        let header_value = bait.expected_action.header_value.as_deref().unwrap();

        let action_response = parse_downstream_response(&run_runtime_request(
            runtime,
            &post_request_with_cookie(
                &bait.expected_action.path,
                &cookie,
                &[(header_name, header_value)],
            ),
        ));

        assert_eq!(action_response.status, 202);
        let action = first_event_of_type(&event_log_path, "bait_action_observed");
        assert_eq!(action["session_id"], session_id.0.to_string());
        assert_eq!(action["kind"]["bait_id"], bait.id.0);
        assert_eq!(action["kind"]["exposure_id"], restored_exposure_id.0);
        assert_eq!(
            first_event_of_type(&event_log_path, "policy_changed")["kind"]["to"],
            "controlled_reality"
        );
    }

    #[test]
    fn runtime_bait_action_without_same_session_exposure_is_not_correlated() {
        let event_log_path = unique_temp_path("wrong-session-events.jsonl");
        let runtime = test_runtime_with_m1_controller(
            closed_upstream(),
            &event_log_path,
            unique_temp_path("wrong-session-control.txt"),
        );
        let exposed_cookie = cookie_header();
        let action_cookie = cookie_header();

        parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &get_request_with_cookie("/docs/legacy-import", &exposed_cookie),
        ));
        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &post_request_with_cookie(
                "/api/v2/import/reconcile",
                &action_cookie,
                &[("X-Migration-Trace", "rel_2025_04_b7f2")],
            ),
        ));

        assert_eq!(response.status, 202);
        let exposure = first_event_of_type(&event_log_path, "bait_exposed");
        let action = first_event_of_type(&event_log_path, "bait_action_observed");
        assert_ne!(action["session_id"], exposure["session_id"]);
        assert_eq!(action["kind"]["bait_id"], exposure["kind"]["bait_id"]);
        assert!(action["kind"]["exposure_id"].is_null());
    }

    #[test]
    fn runtime_emits_correlated_action_after_prior_uncorrelated_action() {
        let event_log_path = unique_temp_path("late-correlated-action-events.jsonl");
        let runtime = test_runtime_with_m1_controller(
            closed_upstream(),
            &event_log_path,
            unique_temp_path("late-correlated-action-control.txt"),
        );
        let cookie = cookie_header();

        parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &post_request_with_cookie(
                "/api/v2/import/reconcile",
                &cookie,
                &[("X-Migration-Trace", "rel_2025_04_b7f2")],
            ),
        ));
        parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &get_request_with_cookie("/docs/legacy-import", &cookie),
        ));
        parse_downstream_response(&run_runtime_request(
            runtime,
            &post_request_with_cookie(
                "/api/v2/import/reconcile",
                &cookie,
                &[("X-Migration-Trace", "rel_2025_04_b7f2")],
            ),
        ));

        let exposure = first_event_of_type(&event_log_path, "bait_exposed");
        let actions = events_of_type(&event_log_path, "bait_action_observed");
        assert_eq!(actions.len(), 2);
        assert!(actions[0]["kind"]["exposure_id"].is_null());
        assert_eq!(
            actions[1]["kind"]["exposure_id"],
            exposure["kind"]["exposure_id"]
        );
    }

    #[test]
    fn runtime_logs_repeated_correlated_bait_actions_for_audit() {
        let event_log_path = unique_temp_path("repeated-correlated-action-events.jsonl");
        let runtime = test_runtime_with_m1_controller(
            closed_upstream(),
            &event_log_path,
            unique_temp_path("repeated-correlated-action-control.txt"),
        );
        let cookie = cookie_header();

        parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &get_request_with_cookie("/docs/legacy-import", &cookie),
        ));
        for _ in 0..2 {
            parse_downstream_response(&run_runtime_request(
                runtime.clone(),
                &post_request_with_cookie(
                    "/api/v2/import/reconcile",
                    &cookie,
                    &[("X-Migration-Trace", "rel_2025_04_b7f2")],
                ),
            ));
        }

        let exposure = first_event_of_type(&event_log_path, "bait_exposed");
        let actions = events_of_type(&event_log_path, "bait_action_observed");
        assert_eq!(actions.len(), 1);
        assert_eq!(
            actions[0]["kind"]["exposure_id"],
            exposure["kind"]["exposure_id"]
        );
        assert_eq!(
            events_of_type(&event_log_path, "controlled_reality_entered").len(),
            2
        );
    }

    #[test]
    fn runtime_wrong_bait_header_value_is_logged_and_held_eidolon_owned() {
        let event_log_path = unique_temp_path("near-miss-events.jsonl");
        let (upstream, upstream_handle) = spawn_upstream_sequence(vec![]);
        let runtime = test_runtime_with_m1_controller(
            upstream,
            &event_log_path,
            unique_temp_path("near-miss-control.txt"),
        );
        let cookie = cookie_header();

        parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &get_request_with_cookie("/docs/legacy-import", &cookie),
        ));
        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &post_request_with_cookie(
                "/api/v2/import/reconcile",
                &cookie,
                &[("X-Migration-Trace", "wrong")],
            ),
        ));
        let upstream_requests = must_join(upstream_handle.join(), "upstream thread should join");

        assert_eq!(response.status, 202);
        assert!(
            upstream_requests.is_empty(),
            "wrong-value bait near miss must never reach the protected upstream"
        );
        assert_event_routing(&event_log_path, "request_seen", "eidolon_owned");
        assert_eq!(events_of_type(&event_log_path, "bait_exposed").len(), 1);
        let near_miss = first_event_of_type(&event_log_path, "bait_action_observed");
        assert_eq!(near_miss["policy_state"], "observe");
        assert_eq!(near_miss["kind"]["bait_id"], "rel_2025_04_b7f2");
        assert!(near_miss["kind"]["exposure_id"].is_null());
        assert_eq!(
            events_of_type(&event_log_path, "rate_limit_applied").len(),
            0
        );
    }

    #[test]
    fn runtime_missing_bait_header_on_unsafe_path_is_held_eidolon_owned_without_attribution() {
        let event_log_path = unique_temp_path("missing-bait-header-events.jsonl");
        let (upstream, upstream_handle) = spawn_upstream_sequence(vec![]);
        let runtime = test_runtime_with_m1_controller(
            upstream,
            &event_log_path,
            unique_temp_path("missing-bait-header-control.txt"),
        );
        let cookie = cookie_header();

        parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &get_request_with_cookie("/docs/legacy-import", &cookie),
        ));
        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &post_request_with_cookie("/api/v2/import/reconcile", &cookie, &[]),
        ));
        let upstream_requests = must_join(upstream_handle.join(), "upstream thread should join");

        assert_eq!(response.status, 202);
        assert!(
            upstream_requests.is_empty(),
            "missing-proof bait action must never reach the protected upstream"
        );
        assert_event_routing(&event_log_path, "request_seen", "eidolon_owned");
        assert_eq!(events_of_type(&event_log_path, "bait_exposed").len(), 1);
        assert_event_type_absent(&event_log_path, "bait_action_observed");
        assert_eq!(
            events_of_type(&event_log_path, "rate_limit_applied").len(),
            0
        );
    }

    #[test]
    fn runtime_rate_limits_suspicious_same_bait_near_miss_after_exposure() {
        let event_log_path = unique_temp_path("suspicious-near-miss-events.jsonl");
        let debug_log_path = unique_temp_path("suspicious-near-miss-debug.jsonl");
        let runtime = test_runtime_with_m1_controller_and_debug_log(
            closed_upstream(),
            &event_log_path,
            &debug_log_path,
            unique_temp_path("suspicious-near-miss-control.txt"),
        );
        let cookie = cookie_header();

        parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &get_request_with_cookie("/docs/legacy-import", &cookie),
        ));
        set_runtime_policy_state(&runtime, &cookie, PolicyState::Suspicious);
        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &post_request_with_cookie(
                "/api/v2/import/reconcile",
                &cookie,
                &[("X-Migration-Trace", "wrong")],
            ),
        ));

        assert_eq!(response.status, 429);
        assert_eq!(header_values(&response, "retry-after"), vec!["30"]);

        let near_miss = first_event_of_type(&event_log_path, "bait_action_observed");
        assert_eq!(near_miss["policy_state"], "suspicious");
        assert_eq!(near_miss["kind"]["bait_id"], "rel_2025_04_b7f2");
        assert!(near_miss["kind"]["exposure_id"].is_null());

        let policy_changed = events_of_type(&event_log_path, "policy_changed")
            .into_iter()
            .find(|event| event["kind"]["to"].as_str() == Some("rate_limited"))
            .unwrap_or_else(|| panic!("rate-limited policy change should exist"));
        assert_eq!(policy_changed["kind"]["from"], "suspicious");
        assert_eq!(policy_changed["kind"]["to"], "rate_limited");
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains(
                "suspicious same-bait near miss after exposure moved session to rate limited"
            )));
        assert_eq!(
            policy_changed["kind"]["persistence"]["pre_containment_persistence_class"],
            "same_bait_near_miss"
        );
        let request_seen = events_of_type(&event_log_path, "request_seen")
            .into_iter()
            .find(|event| event["kind"]["path"].as_str() == Some("/api/v2/import/reconcile"))
            .unwrap_or_else(|| panic!("rate-limited request_seen should exist"));
        assert_eq!(request_seen["policy_state"], "rate_limited");
        assert_eq!(request_seen["kind"]["routing_decision"], "rate_limited");
        let rate_limit = first_event_of_type(&event_log_path, "rate_limit_applied");
        assert_eq!(rate_limit["policy_state"], "rate_limited");

        let near_miss_debug = first_debug_event(&debug_log_path, "bait_action_near_miss");
        assert_eq!(near_miss_debug["fields"]["prior_same_bait_exposure"], true);
        let action_debug = first_debug_event(&debug_log_path, "bait_action_observed");
        assert_eq!(action_debug["fields"]["matched_prior_exposure"], false);
        assert_eq!(action_debug["fields"]["prior_same_bait_exposure"], true);
    }

    #[test]
    fn runtime_repeated_rate_limited_same_bait_near_miss_becomes_blocked() {
        let event_log_path = unique_temp_path("blocked-near-miss-events.jsonl");
        let debug_log_path = unique_temp_path("blocked-near-miss-debug.jsonl");
        let runtime = test_runtime_with_m1_controller_and_debug_log(
            closed_upstream(),
            &event_log_path,
            &debug_log_path,
            unique_temp_path("blocked-near-miss-control.txt"),
        );
        let cookie = cookie_header();

        parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &get_request_with_cookie("/docs/legacy-import", &cookie),
        ));
        set_runtime_policy_state(&runtime, &cookie, PolicyState::Suspicious);
        let first_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &post_request_with_cookie(
                "/api/v2/import/reconcile",
                &cookie,
                &[("X-Migration-Trace", "wrong")],
            ),
        ));
        let second_response = parse_downstream_response(&run_runtime_request(
            runtime,
            &post_request_with_cookie(
                "/api/v2/import/reconcile",
                &cookie,
                &[("X-Migration-Trace", "wrong")],
            ),
        ));

        assert_eq!(first_response.status, 429);
        assert_eq!(second_response.status, 403);

        let blocked_change = events_of_type(&event_log_path, "policy_changed")
            .into_iter()
            .find(|event| {
                event["kind"]["from"].as_str() == Some("rate_limited")
                    && event["kind"]["to"].as_str() == Some("blocked")
            })
            .unwrap_or_else(|| panic!("blocked policy change should exist"));
        assert!(blocked_change["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason
                .contains("rate-limited same-bait near miss retry moved session to blocked")));

        let blocked_request = events_of_type(&event_log_path, "request_seen")
            .into_iter()
            .rfind(|event| event["kind"]["path"].as_str() == Some("/api/v2/import/reconcile"))
            .unwrap_or_else(|| panic!("blocked request_seen should exist"));
        assert_eq!(blocked_request["policy_state"], "blocked");
        assert_eq!(blocked_request["kind"]["routing_decision"], "eidolon_owned");

        let bait_actions = events_of_type(&event_log_path, "bait_action_observed");
        assert_eq!(bait_actions.len(), 2);
        assert_eq!(bait_actions[1]["policy_state"], "rate_limited");
        assert_eq!(bait_actions[1]["kind"]["bait_id"], "rel_2025_04_b7f2");
        assert!(bait_actions[1]["kind"]["exposure_id"].is_null());

        let blocked_response = events_of_type(&event_log_path, "response_served")
            .into_iter()
            .rfind(|event| event["policy_state"].as_str() == Some("blocked"))
            .unwrap_or_else(|| panic!("blocked response should exist"));
        assert_eq!(
            blocked_response["kind"]["routing_decision"],
            "eidolon_owned"
        );
        assert_eq!(blocked_response["kind"]["status"], 403);

        let surface_debugs = debug_events(&debug_log_path, "surface_action_selected");
        let last_surface_debug = surface_debugs
            .last()
            .unwrap_or_else(|| panic!("surface debug should exist"));
        assert_eq!(last_surface_debug["fields"]["policy_state"], "rate_limited");
        assert_eq!(
            last_surface_debug["fields"]["controller_surface_action"]["type"],
            "rate_limited"
        );
        assert_eq!(
            last_surface_debug["fields"]["surface_action"]["type"],
            "rate_limited"
        );

        let near_miss_debugs = debug_events(&debug_log_path, "bait_action_near_miss");
        assert_eq!(near_miss_debugs.len(), 2);
        assert_eq!(
            near_miss_debugs[1]["fields"]["prior_same_bait_exposure"],
            true
        );
        let action_debugs = debug_events(&debug_log_path, "bait_action_observed");
        assert_eq!(action_debugs.len(), 2);
        assert_eq!(action_debugs[1]["fields"]["matched_prior_exposure"], false);
        assert_eq!(action_debugs[1]["fields"]["prior_same_bait_exposure"], true);
    }

    #[test]
    fn runtime_rate_limited_exact_bait_action_enters_controlled_reality() {
        let event_log_path = unique_temp_path("rate-limited-exact-action-events.jsonl");
        let debug_log_path = unique_temp_path("rate-limited-exact-action-debug.jsonl");
        let runtime = test_runtime_with_m1_controller_and_debug_log(
            closed_upstream(),
            &event_log_path,
            &debug_log_path,
            unique_temp_path("rate-limited-exact-action-control.txt"),
        );
        let cookie = cookie_header();

        let exposure_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &get_request_with_cookie("/docs/legacy-import", &cookie),
        ));
        set_runtime_policy_state(&runtime, &cookie, PolicyState::Suspicious);
        let near_miss_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &post_request_with_cookie(
                "/api/v2/import/reconcile",
                &cookie,
                &[("X-Migration-Trace", "wrong")],
            ),
        ));
        let action_response = parse_downstream_response(&run_runtime_request(
            runtime,
            &post_request_with_cookie(
                "/api/v2/import/reconcile",
                &cookie,
                &[("X-Migration-Trace", "rel_2025_04_b7f2")],
            ),
        ));

        assert_eq!(exposure_response.status, 200);
        assert_eq!(near_miss_response.status, 429);
        assert_eq!(action_response.status, 202);
        assert!(must_ok(
            String::from_utf8(action_response.body),
            "body should be utf8"
        )
        .contains(r#""write_committed":false"#));

        let exposure = first_event_of_type(&event_log_path, "bait_exposed");
        let controlled_change = events_of_type(&event_log_path, "policy_changed")
            .into_iter()
            .find(|event| {
                event["kind"]["from"].as_str() == Some("rate_limited")
                    && event["kind"]["to"].as_str() == Some("controlled_reality")
            })
            .unwrap_or_else(|| panic!("controlled reality policy change should exist"));
        assert!(controlled_change["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| {
                reason
                    .contains("confirmed bait-derived action moved session into controlled reality")
            }));

        let action_request = events_of_type(&event_log_path, "request_seen")
            .into_iter()
            .rfind(|event| event["kind"]["path"].as_str() == Some("/api/v2/import/reconcile"))
            .unwrap_or_else(|| panic!("exact bait action request_seen should exist"));
        assert_eq!(action_request["policy_state"], "rate_limited");
        assert_eq!(action_request["kind"]["routing_decision"], "eidolon_owned");

        let bait_actions = events_of_type(&event_log_path, "bait_action_observed");
        assert_eq!(bait_actions.len(), 2);
        assert_eq!(bait_actions[1]["policy_state"], "rate_limited");
        assert_eq!(bait_actions[1]["kind"]["bait_id"], "rel_2025_04_b7f2");
        assert_eq!(
            bait_actions[1]["kind"]["exposure_id"],
            exposure["kind"]["exposure_id"]
        );

        let controlled_entry = first_event_of_type(&event_log_path, "controlled_reality_entered");
        assert_eq!(controlled_entry["policy_state"], "controlled_reality");

        let controlled_response = events_of_type(&event_log_path, "response_served")
            .into_iter()
            .rfind(|event| event["policy_state"].as_str() == Some("controlled_reality"))
            .unwrap_or_else(|| panic!("controlled reality response should exist"));
        assert_eq!(
            controlled_response["kind"]["routing_decision"],
            "controlled_reality"
        );
        assert_eq!(controlled_response["kind"]["status"], 202);

        let action_debugs = debug_events(&debug_log_path, "bait_action_observed");
        assert_eq!(action_debugs.len(), 2);
        assert_eq!(action_debugs[1]["fields"]["matched_prior_exposure"], true);
        assert_eq!(action_debugs[1]["fields"]["prior_same_bait_exposure"], true);

        let controlled_debug = debug_events(&debug_log_path, "controlled_reality_action_selected")
            .into_iter()
            .last()
            .unwrap_or_else(|| panic!("controlled reality debug should exist"));
        assert_eq!(controlled_debug["fields"]["depth"], 1);
        assert_eq!(
            controlled_debug["fields"]["action"]["type"],
            "controlled_reality"
        );
    }

    #[test]
    fn runtime_rate_limited_request_without_bait_header_stays_rate_limited() {
        let event_log_path = unique_temp_path("rate-limited-no-header-events.jsonl");
        let runtime = test_runtime_with_m1_controller(
            closed_upstream(),
            &event_log_path,
            unique_temp_path("rate-limited-no-header-control.txt"),
        );
        let cookie = cookie_header();

        parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &get_request_with_cookie("/docs/legacy-import", &cookie),
        ));
        set_runtime_policy_state(&runtime, &cookie, PolicyState::RateLimited);
        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &post_request_with_cookie("/api/v2/import/reconcile", &cookie, &[]),
        ));

        assert_eq!(response.status, 429);
        assert_event_type_absent(&event_log_path, "bait_action_observed");
        assert_eq!(
            events_of_type(&event_log_path, "policy_changed")
                .into_iter()
                .filter(|event| event["kind"]["to"].as_str() == Some("blocked"))
                .count(),
            0
        );
        let request_seen = events_of_type(&event_log_path, "request_seen")
            .into_iter()
            .find(|event| event["kind"]["path"].as_str() == Some("/api/v2/import/reconcile"))
            .unwrap_or_else(|| panic!("rate-limited request_seen should exist"));
        assert_eq!(request_seen["policy_state"], "rate_limited");
        assert_eq!(request_seen["kind"]["routing_decision"], "rate_limited");
    }

    #[test]
    fn runtime_rate_limits_suspicious_openapi_same_bait_near_miss_after_exposure() {
        let event_log_path = unique_temp_path("suspicious-openapi-near-miss-events.jsonl");
        let debug_log_path = unique_temp_path("suspicious-openapi-near-miss-debug.jsonl");
        let runtime = test_runtime_with_m1_controller_and_debug_log(
            closed_upstream(),
            &event_log_path,
            &debug_log_path,
            unique_temp_path("suspicious-openapi-near-miss-control.txt"),
        );
        let cookie = cookie_header();

        set_runtime_policy_state(&runtime, &cookie, PolicyState::Suspicious);
        let promotion_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &get_request_with_cookie("/openapi.json", &cookie),
        ));
        let Ok(rewritten) = serde_json::from_slice::<Value>(&promotion_response.body) else {
            panic!("body should be json");
        };
        assert_eq!(promotion_response.status, 200);
        assert_eq!(
            rewritten["paths"]["/api/v2/import/reconcile"]["post"]["parameters"][0]["name"],
            "X-OpenAPI-Trace"
        );

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &post_request_with_cookie(
                "/api/v2/import/reconcile",
                &cookie,
                &[("X-OpenAPI-Trace", "wrong")],
            ),
        ));

        assert_eq!(response.status, 429);
        assert_eq!(header_values(&response, "retry-after"), vec!["30"]);

        let bait_exposed = first_event_of_type(&event_log_path, "bait_exposed");
        assert_eq!(bait_exposed["kind"]["bait_id"], "openapi_reconcile_trace");
        assert_eq!(bait_exposed["kind"]["surface"], "/openapi.json");

        let near_miss = first_event_of_type(&event_log_path, "bait_action_observed");
        assert_eq!(near_miss["policy_state"], "suspicious");
        assert_eq!(near_miss["kind"]["bait_id"], "openapi_reconcile_trace");
        assert!(near_miss["kind"]["exposure_id"].is_null());

        let policy_changed = events_of_type(&event_log_path, "policy_changed")
            .into_iter()
            .find(|event| event["kind"]["to"].as_str() == Some("rate_limited"))
            .unwrap_or_else(|| panic!("rate-limited policy change should exist"));
        assert_eq!(policy_changed["kind"]["from"], "suspicious");
        assert_eq!(policy_changed["kind"]["to"], "rate_limited");

        let request_seen = events_of_type(&event_log_path, "request_seen")
            .into_iter()
            .find(|event| event["kind"]["path"].as_str() == Some("/api/v2/import/reconcile"))
            .unwrap_or_else(|| panic!("rate-limited request_seen should exist"));
        assert_eq!(request_seen["policy_state"], "rate_limited");
        assert_eq!(request_seen["kind"]["routing_decision"], "rate_limited");

        let near_miss_debug = first_debug_event(&debug_log_path, "bait_action_near_miss");
        assert_eq!(
            near_miss_debug["fields"]["bait_id"],
            "openapi_reconcile_trace"
        );
        assert_eq!(near_miss_debug["fields"]["prior_same_bait_exposure"], true);
        let action_debug = first_debug_event(&debug_log_path, "bait_action_observed");
        assert_eq!(action_debug["fields"]["bait_id"], "openapi_reconcile_trace");
        assert_eq!(action_debug["fields"]["matched_prior_exposure"], false);
        assert_eq!(action_debug["fields"]["prior_same_bait_exposure"], true);
    }

    #[test]
    fn disabled_interventions_fail_closed_for_known_decoy_write_path() {
        let event_log_path = unique_temp_path("disabled-bait-events.jsonl");
        let control_path = unique_temp_path("disabled-bait-control.txt");
        must_ok(
            fs::write(&control_path, "disabled"),
            "control file should write",
        );
        let runtime =
            test_runtime_with_m1_controller(closed_upstream(), &event_log_path, control_path);

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &post_request_with_cookie(
                "/api/v2/import/reconcile",
                &cookie_header(),
                &[("X-Migration-Trace", "rel_2025_04_b7f2")],
            ),
        ));

        assert_eq!(response.status, 403);
        assert!(
            must_ok(String::from_utf8(response.body), "body should be utf8")
                .contains("failed closed")
        );
        assert_event_routing(&event_log_path, "request_seen", "eidolon_owned");
        assert_event_type_absent(&event_log_path, "bait_exposed");
        assert_event_type_absent(&event_log_path, "bait_action_observed");
    }

    fn custom_action_profile_json() -> &'static str {
        r##"{
          "schema_version": 1,
          "profile_id": "custom_action_fail_closed",
          "baits": [
            {
              "id": "custom_action_trace",
              "bait_class": "docs",
              "surface": "/docs/custom-action",
              "surface_kind": "docs",
              "expected_action": {
                "method": "POST",
                "path": "/api/v3/custom-action",
                "header_name": "X-Custom-Trace",
                "header_value": "custom_trace_2026_x9"
              }
            }
          ]
        }"##
    }

    #[test]
    fn runtime_custom_bait_action_path_is_registered_and_held_eidolon_owned() {
        let path = write_bait_profile(custom_action_profile_json());
        let loaded = load_bait_profile(&path).expect("custom profile should load");
        let event_log_path = unique_temp_path("custom-action-fail-closed-events.jsonl");
        let (upstream, upstream_handle) = spawn_upstream_sequence(vec![]);
        let runtime = test_runtime_with_bait_profile(
            upstream,
            &event_log_path,
            unique_temp_path("custom-action-fail-closed-control.txt"),
            loaded,
            None,
        );
        let cookie = cookie_header();

        let mismatched = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &post_request_with_cookie(
                "/api/v3/custom-action",
                &cookie,
                &[("X-Custom-Trace", "wrong")],
            ),
        ));
        let missing = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &post_request_with_cookie("/api/v3/custom-action", &cookie, &[]),
        ));
        let matched = parse_downstream_response(&run_runtime_request(
            runtime,
            &post_request_with_cookie(
                "/api/v3/custom-action",
                &cookie,
                &[("X-Custom-Trace", "custom_trace_2026_x9")],
            ),
        ));
        let upstream_requests = must_join(upstream_handle.join(), "upstream thread should join");

        assert_eq!(mismatched.status, 202);
        assert_eq!(missing.status, 202);
        assert_eq!(matched.status, 202);
        assert!(
            upstream_requests.is_empty(),
            "custom unsafe bait action path must never reach the protected upstream"
        );
        let actions = events_of_type(&event_log_path, "bait_action_observed");
        assert_eq!(
            actions.len(),
            2,
            "headerless probes stay unattributed; presented proofs get outcomes"
        );
        assert!(actions
            .iter()
            .all(|event| event["kind"]["bait_id"] == "custom_action_trace"));
        assert!(actions
            .iter()
            .all(|event| event["kind"]["exposure_id"].is_null()));
    }

    #[test]
    fn disabled_interventions_fail_closed_for_configured_bait_action_path() {
        let path = write_bait_profile(custom_action_profile_json());
        let loaded = load_bait_profile(&path).expect("custom profile should load");
        let event_log_path = unique_temp_path("disabled-custom-action-events.jsonl");
        let control_path = unique_temp_path("disabled-custom-action-control.txt");
        must_ok(
            fs::write(&control_path, "disabled"),
            "control file should write",
        );
        let (upstream, upstream_handle) = spawn_upstream_sequence(vec![]);
        let runtime =
            test_runtime_with_bait_profile(upstream, &event_log_path, control_path, loaded, None);

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &post_request_with_cookie(
                "/api/v3/custom-action",
                &cookie_header(),
                &[("X-Custom-Trace", "custom_trace_2026_x9")],
            ),
        ));
        let upstream_requests = must_join(upstream_handle.join(), "upstream thread should join");

        assert_eq!(response.status, 403);
        assert!(
            upstream_requests.is_empty(),
            "disabled interventions must keep configured bait action paths fail closed"
        );
        assert_event_routing(&event_log_path, "request_seen", "eidolon_owned");
    }

    #[test]
    fn runtime_mints_one_request_id_per_request_and_stamps_every_event() {
        let event_log_path = unique_temp_path("request-id-events.jsonl");
        let runtime = test_runtime_with_m1_controller(
            closed_upstream(),
            &event_log_path,
            unique_temp_path("request-id-control.txt"),
        );
        let cookie = cookie_header();

        let first = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &get_request_with_cookie("/docs/legacy-import", &cookie),
        ));
        let second = parse_downstream_response(&run_runtime_request(
            runtime,
            &get_request_with_cookie("/docs/legacy-import", &cookie),
        ));
        assert_eq!(first.status, 200);
        assert_eq!(second.status, 200);

        let events = event_values(&event_log_path);
        assert!(events.iter().all(|event| event["request_id"].is_string()));
        let request_ids: std::collections::HashSet<&str> = events
            .iter()
            .filter_map(|event| event["request_id"].as_str())
            .collect();
        assert_eq!(
            request_ids.len(),
            2,
            "each request must mint exactly one opaque request id"
        );

        let mut request_seen_count: std::collections::HashMap<&str, usize> =
            std::collections::HashMap::new();
        let mut response_served_count: std::collections::HashMap<&str, usize> =
            std::collections::HashMap::new();
        for event in &events {
            let Some(request_id) = event["request_id"].as_str() else {
                continue;
            };
            match event["kind"]["type"].as_str() {
                Some("request_seen") => {
                    *request_seen_count.entry(request_id).or_default() += 1;
                }
                Some("response_served") => {
                    *response_served_count.entry(request_id).or_default() += 1;
                }
                _ => {}
            }
        }
        for request_id in request_ids {
            assert_eq!(
                request_seen_count.get(request_id),
                Some(&1),
                "request {request_id} must have exactly one request_seen event"
            );
            assert_eq!(
                response_served_count.get(request_id),
                Some(&1),
                "request {request_id} must have exactly one response_served event"
            );
        }
    }

    #[test]
    fn runtime_request_id_events_round_trip_through_trace_reader() {
        let event_log_path = unique_temp_path("request-id-reader-events.jsonl");
        let runtime = test_runtime_with_m1_controller(
            closed_upstream(),
            &event_log_path,
            unique_temp_path("request-id-reader-control.txt"),
        );

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &get_request_with_cookie("/docs/legacy-import", &cookie_header()),
        ));
        assert_eq!(response.status, 200);

        let events = event_values(&event_log_path);
        let first_request_id = events
            .iter()
            .find_map(|event| event["request_id"].as_str())
            .expect("proxy must stamp a request id");
        assert!(
            uuid::Uuid::parse_str(first_request_id).is_ok(),
            "request id must be an opaque UUID"
        );
        assert_ne!(
            first_request_id, "00000000-0000-0000-0000-000000000000",
            "request id must not encode meaningful data"
        );
    }

    #[test]
    fn runtime_path_uses_injected_policy_state_for_intervention_routing() {
        let event_log_path = unique_temp_path("controlled-events.jsonl");
        let runtime = test_runtime(
            must_ok(
                parse_upstream(DEFAULT_UPSTREAM, false),
                "default upstream should parse",
            ),
            &event_log_path,
            unique_temp_path("controlled-control.txt"),
            SurfaceAction::ProtectedUpstream,
        );
        let cookie = cookie_header();
        set_runtime_policy_state(&runtime, &cookie, PolicyState::ControlledReality);

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &get_request_with_cookie("/api/v2/import/reconcile", &cookie),
        ));

        assert_eq!(response.status, 200);
        assert!(
            must_ok(String::from_utf8(response.body), "body should be utf8")
                .contains(r#""synthetic":true"#)
        );
        assert_event_routing(&event_log_path, "request_seen", "controlled_reality");
        assert_event_routing(&event_log_path, "response_served", "controlled_reality");
    }

    #[test]
    fn runtime_rate_limits_after_controlled_reality_action_depth_limit() {
        let event_log_path = unique_temp_path("controlled-rate-limit-events.jsonl");
        let runtime = test_runtime(
            must_ok(
                parse_upstream(DEFAULT_UPSTREAM, false),
                "default upstream should parse",
            ),
            &event_log_path,
            unique_temp_path("controlled-rate-limit-control.txt"),
            SurfaceAction::ProtectedUpstream,
        );
        let cookie = cookie_header();
        set_runtime_policy_state(&runtime, &cookie, PolicyState::ControlledReality);

        let mut response = None;
        for _ in 0..=MAX_CONTROLLED_REALITY_ACTION_DEPTH {
            response = Some(parse_downstream_response(&run_runtime_request(
                runtime.clone(),
                &get_request_with_cookie("/api/v2/import/reconcile", &cookie),
            )));
        }

        let response = response.expect("response should exist");

        assert_eq!(response.status, 429);
        assert_eq!(header_values(&response, "retry-after"), vec!["30"]);
        assert_eq!(
            first_event_of_type(&event_log_path, "rate_limit_applied")["policy_state"],
            "controlled_reality"
        );
        assert!(events_of_type(&event_log_path, "controlled_reality_entered").len() >= 4);
    }

    #[test]
    fn runtime_rate_limit_uses_configured_depth_delay_and_retry_after() {
        let event_log_path = unique_temp_path("controlled-configured-rate-limit-events.jsonl");
        let mut runtime = test_runtime(
            must_ok(
                parse_upstream(DEFAULT_UPSTREAM, false),
                "default upstream should parse",
            ),
            &event_log_path,
            unique_temp_path("controlled-configured-rate-limit-control.txt"),
            SurfaceAction::ProtectedUpstream,
        );
        runtime.controlled_reality_config = ControlledRealityConfig {
            max_action_depth: 1,
            tarpit_delay: Duration::from_millis(0),
            retry_after_seconds: 7,
        };
        let cookie = cookie_header();
        set_runtime_policy_state(&runtime, &cookie, PolicyState::ControlledReality);

        parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &get_request_with_cookie("/api/v2/import/reconcile", &cookie),
        ));
        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &get_request_with_cookie("/api/v2/import/reconcile", &cookie),
        ));

        assert_eq!(response.status, 429);
        assert_eq!(header_values(&response, "retry-after"), vec!["7"]);
        let rate_limit = first_event_of_type(&event_log_path, "rate_limit_applied");
        assert!(rate_limit["kind"]["reason"]
            .as_str()
            .expect("reason should be a string")
            .contains("exceeded limit 1; tarpit delay 0ms"));
    }

    #[test]
    fn runtime_blocks_after_repeated_controlled_reality_depth_limit_probe() {
        let event_log_path = unique_temp_path("controlled-blocked-events.jsonl");
        let debug_log_path = unique_temp_path("controlled-blocked-debug.jsonl");
        let mut runtime = test_runtime(
            must_ok(
                parse_upstream(DEFAULT_UPSTREAM, false),
                "default upstream should parse",
            ),
            &event_log_path,
            unique_temp_path("controlled-blocked-control.txt"),
            SurfaceAction::ProtectedUpstream,
        );
        runtime.debug_log = Some(Arc::new(Mutex::new(must_ok(
            FileDebugLogWriter::open(&debug_log_path),
            "debug log should open",
        ))));
        runtime.controlled_reality_config = ControlledRealityConfig {
            max_action_depth: 1,
            tarpit_delay: Duration::from_millis(0),
            retry_after_seconds: 7,
        };
        let cookie = cookie_header();
        set_runtime_policy_state(&runtime, &cookie, PolicyState::ControlledReality);

        let first_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &get_request_with_cookie("/api/v2/import/reconcile", &cookie),
        ));
        let second_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &get_request_with_cookie("/api/v2/import/reconcile", &cookie),
        ));
        let third_response = parse_downstream_response(&run_runtime_request(
            runtime,
            &get_request_with_cookie("/api/v2/import/reconcile", &cookie),
        ));

        assert_eq!(first_response.status, 200);
        assert_eq!(second_response.status, 429);
        assert_eq!(header_values(&second_response, "retry-after"), vec!["7"]);
        assert_eq!(third_response.status, 403);

        let rate_limit = first_event_of_type(&event_log_path, "rate_limit_applied");
        assert_eq!(rate_limit["policy_state"], "controlled_reality");
        let blocked_change = events_of_type(&event_log_path, "policy_changed")
            .into_iter()
            .find(|event| {
                event["kind"]["from"].as_str() == Some("controlled_reality")
                    && event["kind"]["to"].as_str() == Some("blocked")
            })
            .unwrap_or_else(|| panic!("blocked policy change should exist"));
        assert!(blocked_change["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains(
                "controlled-reality probe continued after depth-limit throttle and moved session to blocked"
            )));
        assert!(blocked_change["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("depth=3")));
        assert_eq!(
            blocked_change["kind"]["persistence"]["post_containment_persistence_kind"],
            "controlled_reality_depth_limit"
        );

        let blocked_request = events_of_type(&event_log_path, "request_seen")
            .into_iter()
            .rfind(|event| event["kind"]["path"].as_str() == Some("/api/v2/import/reconcile"))
            .unwrap_or_else(|| panic!("blocked request_seen should exist"));
        assert_eq!(blocked_request["policy_state"], "blocked");
        assert_eq!(blocked_request["kind"]["routing_decision"], "eidolon_owned");

        let blocked_response = events_of_type(&event_log_path, "response_served")
            .into_iter()
            .rfind(|event| event["policy_state"].as_str() == Some("blocked"))
            .unwrap_or_else(|| panic!("blocked response should exist"));
        assert_eq!(blocked_response["kind"]["status"], 403);
        assert_eq!(
            blocked_response["kind"]["routing_decision"],
            "eidolon_owned"
        );

        let controlled_debug = debug_events(&debug_log_path, "controlled_reality_action_selected")
            .into_iter()
            .last()
            .unwrap_or_else(|| panic!("controlled reality debug should exist"));
        assert_eq!(controlled_debug["fields"]["depth"], 3);
        assert_eq!(controlled_debug["fields"]["depth_limit"], 1);
        assert_eq!(
            controlled_debug["fields"]["action"]["type"],
            "eidolon_owned"
        );
        assert_eq!(controlled_debug["fields"]["transition"]["to"], "blocked");

        let surface_debug = debug_events(&debug_log_path, "surface_action_selected")
            .into_iter()
            .last()
            .unwrap_or_else(|| panic!("surface debug should exist"));
        assert_eq!(surface_debug["fields"]["policy_state"], "blocked");
        assert_eq!(
            surface_debug["fields"]["policy_routing_decision"],
            "eidolon_owned"
        );
        assert_eq!(
            surface_debug["fields"]["surface_action"]["type"],
            "eidolon_owned"
        );
    }

    #[test]
    fn controlled_session_logs_escape_attempt_outside_configured_branch() {
        let event_log_path = unique_temp_path("controlled-escape-events.jsonl");
        let runtime = test_runtime(
            must_ok(
                parse_upstream(DEFAULT_UPSTREAM, false),
                "default upstream should parse",
            ),
            &event_log_path,
            unique_temp_path("controlled-escape-control.txt"),
            SurfaceAction::ProtectedUpstream,
        );
        let cookie = cookie_header();
        set_runtime_policy_state(&runtime, &cookie, PolicyState::ControlledReality);

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &get_request_with_cookie("/api/v1/projects", &cookie),
        ));

        assert_eq!(response.status, 404);
        let escape = first_event_of_type(&event_log_path, "reality_escape_attempt");
        assert_eq!(escape["policy_state"], "controlled_reality");
        assert_eq!(escape["kind"]["method"], "GET");
        assert_eq!(escape["kind"]["path"], "/api/v1/projects");
        assert_eq!(escape["kind"]["routing_decision"], "controlled_reality");
    }

    #[test]
    fn controlled_session_repeated_escape_attempt_becomes_blocked() {
        let event_log_path = unique_temp_path("controlled-escape-blocked-events.jsonl");
        let debug_log_path = unique_temp_path("controlled-escape-blocked-debug.jsonl");
        let mut runtime = test_runtime(
            must_ok(
                parse_upstream(DEFAULT_UPSTREAM, false),
                "default upstream should parse",
            ),
            &event_log_path,
            unique_temp_path("controlled-escape-blocked-control.txt"),
            SurfaceAction::ProtectedUpstream,
        );
        runtime.debug_log = Some(Arc::new(Mutex::new(must_ok(
            FileDebugLogWriter::open(&debug_log_path),
            "debug log should open",
        ))));
        let cookie = cookie_header();
        set_runtime_policy_state(&runtime, &cookie, PolicyState::ControlledReality);

        let first_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &get_request_with_cookie("/api/v1/projects", &cookie),
        ));
        let second_response = parse_downstream_response(&run_runtime_request(
            runtime,
            &get_request_with_cookie("/api/v1/projects", &cookie),
        ));

        assert_eq!(first_response.status, 404);
        assert_eq!(second_response.status, 403);

        let escape_attempts = events_of_type(&event_log_path, "reality_escape_attempt");
        assert_eq!(escape_attempts.len(), 2);
        assert_eq!(escape_attempts[1]["policy_state"], "controlled_reality");
        assert_eq!(escape_attempts[1]["kind"]["path"], "/api/v1/projects");
        assert_eq!(
            escape_attempts[1]["kind"]["routing_decision"],
            "controlled_reality"
        );

        let blocked_change = events_of_type(&event_log_path, "policy_changed")
            .into_iter()
            .find(|event| {
                event["kind"]["from"].as_str() == Some("controlled_reality")
                    && event["kind"]["to"].as_str() == Some("blocked")
            })
            .unwrap_or_else(|| panic!("blocked policy change should exist"));
        assert!(blocked_change["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains(
                "controlled session repeatedly probed outside the controlled-reality branch and moved session to blocked"
            )));
        assert_eq!(
            blocked_change["kind"]["persistence"]["post_containment_persistence_kind"],
            "controlled_reality_branch_escape"
        );

        let blocked_request = events_of_type(&event_log_path, "request_seen")
            .into_iter()
            .rfind(|event| event["kind"]["path"].as_str() == Some("/api/v1/projects"))
            .unwrap_or_else(|| panic!("blocked request_seen should exist"));
        assert_eq!(blocked_request["policy_state"], "blocked");
        assert_eq!(blocked_request["kind"]["routing_decision"], "eidolon_owned");

        let blocked_response = events_of_type(&event_log_path, "response_served")
            .into_iter()
            .rfind(|event| event["policy_state"].as_str() == Some("blocked"))
            .unwrap_or_else(|| panic!("blocked response should exist"));
        assert_eq!(blocked_response["kind"]["status"], 403);
        assert_eq!(
            blocked_response["kind"]["routing_decision"],
            "eidolon_owned"
        );

        let escape_debug = debug_events(&debug_log_path, "reality_escape_attempt")
            .into_iter()
            .last()
            .unwrap_or_else(|| panic!("reality escape debug should exist"));
        assert_eq!(escape_debug["fields"]["attempt_count"], 2);
        assert_eq!(
            escape_debug["fields"]["routing_decision"],
            "controlled_reality"
        );

        let surface_debug = debug_events(&debug_log_path, "surface_action_selected")
            .into_iter()
            .last()
            .unwrap_or_else(|| panic!("surface debug should exist"));
        assert_eq!(surface_debug["fields"]["policy_state"], "blocked");
        assert_eq!(
            surface_debug["fields"]["policy_routing_decision"],
            "eidolon_owned"
        );
        assert_eq!(
            surface_debug["fields"]["surface_action"]["type"],
            "eidolon_owned"
        );
    }

    #[test]
    fn runtime_policy_owned_response_does_not_log_bait_exposure() {
        let event_log_path = unique_temp_path("blocked-no-exposure-events.jsonl");
        let runtime = test_runtime_with_m1_controller(
            must_ok(
                parse_upstream(DEFAULT_UPSTREAM, false),
                "default upstream should parse",
            ),
            &event_log_path,
            unique_temp_path("blocked-no-exposure-control.txt"),
        );
        let cookie = cookie_header();
        set_runtime_policy_state(&runtime, &cookie, PolicyState::Blocked);

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &get_request_with_cookie("/docs/legacy-import", &cookie),
        ));

        assert_eq!(response.status, 403);
        assert_event_routing(&event_log_path, "request_seen", "eidolon_owned");
        assert_event_routing(&event_log_path, "response_served", "eidolon_owned");
        assert_event_type_absent(&event_log_path, "bait_exposed");
    }

    #[test]
    fn runtime_forged_session_cookie_is_not_adopted() {
        let event_log_path = unique_temp_path("forged-cookie-events.jsonl");
        let debug_log_path = unique_temp_path("forged-cookie-debug.jsonl");
        let runtime = test_runtime_with_m1_controller_and_debug_log(
            must_ok(
                parse_upstream(DEFAULT_UPSTREAM, false),
                "default upstream should parse",
            ),
            &event_log_path,
            &debug_log_path,
            unique_temp_path("forged-cookie-control.txt"),
        );
        let forged_uuid = SessionId::new().0;
        let forged_cookie = format!(
            "eidolon_session=v1.1.{}.{}.{}",
            now_unix_secs(),
            forged_uuid,
            "0".repeat(64)
        );

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &get_request_with_cookie("/docs/legacy-import", &forged_cookie),
        ));

        let request_event = first_event_of_type(&event_log_path, "request_seen");
        assert_ne!(
            request_event["session_id"].as_str(),
            Some(forged_uuid.to_string().as_str())
        );
        let set_cookie = response
            .headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case("set-cookie"))
            .expect("forged cookie should be replaced with a minted one");
        assert!(set_cookie.value.starts_with("eidolon_session=v1.1."));
        assert!(!set_cookie.value.contains(&forged_uuid.to_string()));

        let session_debug = first_debug_event(&debug_log_path, "session_resolved");
        assert_eq!(session_debug["fields"]["cookie_outcome"], "bad_signature");
        assert_eq!(session_debug["fields"]["continuity_outcome"], "no_record");
    }

    #[test]
    fn runtime_rapid_cookie_rotation_cannot_reset_blocked_enforcement() {
        let event_log_path = unique_temp_path("rotation-blocked-events.jsonl");
        let debug_log_path = unique_temp_path("rotation-blocked-debug.jsonl");
        let runtime = test_runtime_with_m1_controller_and_debug_log(
            must_ok(
                parse_upstream(DEFAULT_UPSTREAM, false),
                "default upstream should parse",
            ),
            &event_log_path,
            &debug_log_path,
            unique_temp_path("rotation-blocked-control.txt"),
        );
        let cookie = cookie_header();
        let session_id = session_id_from_cookie(&cookie).expect("cookie should parse");
        set_runtime_policy_state(&runtime, &cookie, PolicyState::Blocked);

        let first = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &get_request_with_cookie("/docs/legacy-import", &cookie),
        ));
        assert_eq!(first.status, 403);

        // The attacker discards the cookie, presents a forged one, and rotates
        // again; every request must stay blocked under the enforcement floor.
        // A freshly proxy-minted cookie for an unseen session is not a
        // realistic attacker capability (minting always flows through
        // continuity recovery), so the rotation shapes here are discard,
        // forgery, and malformed values.
        let forged_cookie = format!(
            "eidolon_session=v1.1.{}.{}.{}",
            now_unix_secs(),
            SessionId::new().0,
            "1".repeat(64)
        );
        for attempt in 0..3 {
            let request = match attempt {
                0 => request_with_cookie("GET", "/docs/legacy-import", &forged_cookie, &[]),
                1 => b"GET /docs/legacy-import HTTP/1.1\r\nHost: proxy.local\r\n\r\n".to_vec(),
                _ => request_with_cookie(
                    "GET",
                    "/docs/legacy-import",
                    "eidolon_session=rotated-garbage",
                    &[],
                ),
            };
            let response =
                parse_downstream_response(&run_runtime_request(runtime.clone(), &request));
            assert_eq!(response.status, 403, "attempt {attempt} must stay blocked");
        }

        assert_eq!(
            policy_state_for_session(&runtime, session_id).expect("policy state should load"),
            PolicyState::Blocked
        );
        let resolutions = debug_events(&debug_log_path, "session_resolved");
        let recovered = resolutions
            .iter()
            .filter(|event| event["fields"]["continuity_outcome"] == "recovered")
            .count();
        let cooldown_limited = resolutions
            .iter()
            .filter(|event| event["fields"]["continuity_outcome"] == "cooldown_limited")
            .count();
        assert_eq!(recovered, 1);
        assert_eq!(cooldown_limited, 2);
    }

    #[test]
    fn runtime_audits_forwarded_request_before_upstream_failure() {
        let event_log_path = unique_temp_path("upstream-failure-events.jsonl");
        let runtime = test_runtime(
            closed_upstream(),
            &event_log_path,
            unique_temp_path("upstream-failure-control.txt"),
            SurfaceAction::ProtectedUpstream,
        );

        let (result, response) = run_runtime_request_result(runtime, &get_request("/upstream"));

        assert!(result.is_err());
        assert!(response.is_empty());
        assert_event_routing(&event_log_path, "request_seen", "protected_upstream");
        assert_event_type_absent(&event_log_path, "policy_decision");
    }

    #[test]
    fn runtime_path_audits_rewritten_upstream_only_after_successful_rewrite() {
        let event_log_path = unique_temp_path("rewritten-events.jsonl");
        let (upstream, upstream_handle) =
            spawn_upstream(html_response("<html><body>upstream</body></html>"));
        let runtime = test_runtime(
            upstream,
            &event_log_path,
            unique_temp_path("rewritten-control.txt"),
            html_rewrite_action(r#"<div data-eidolon-surface="test"></div>"#),
        );

        let response =
            parse_downstream_response(&run_runtime_request(runtime, &get_request("/docs")));

        upstream_handle.join().expect("upstream thread should join");
        assert!(String::from_utf8(response.body)
            .expect("body should be utf8")
            .contains(r#"data-eidolon-surface="test""#));
        assert_event_routing(&event_log_path, "request_seen", "protected_upstream");
        assert_event_routing(&event_log_path, "policy_decision", "rewritten_upstream");
        assert_event_routing(&event_log_path, "response_served", "rewritten_upstream");
    }

    #[test]
    fn runtime_path_audits_unchanged_rewrite_as_protected_upstream() {
        let event_log_path = unique_temp_path("unchanged-events.jsonl");
        let (upstream, upstream_handle) = spawn_upstream(json_response(r#"{"status":"ok"}"#));
        let runtime = test_runtime(
            upstream,
            &event_log_path,
            unique_temp_path("unchanged-control.txt"),
            html_rewrite_action(r#"<div data-eidolon-surface="test"></div>"#),
        );

        let response =
            parse_downstream_response(&run_runtime_request(runtime, &get_request("/api")));

        upstream_handle.join().expect("upstream thread should join");
        assert_eq!(response.body, br#"{"status":"ok"}"#);
        assert_event_routing(&event_log_path, "request_seen", "protected_upstream");
        assert_policy_decision_reason_contains(&event_log_path, "made no changes");
        assert_event_routing(&event_log_path, "response_served", "protected_upstream");
    }

    #[test]
    fn runtime_path_audits_refused_rewrite_as_protected_upstream() {
        let event_log_path = unique_temp_path("refused-events.jsonl");
        let original = "<html><body>upstream</body></html>";
        let (upstream, upstream_handle) = spawn_upstream(html_response(original));
        let runtime = test_runtime(
            upstream,
            &event_log_path,
            unique_temp_path("refused-control.txt"),
            html_rewrite_action("<script>alert(1)</script>"),
        );

        let response =
            parse_downstream_response(&run_runtime_request(runtime, &get_request("/docs")));

        upstream_handle.join().expect("upstream thread should join");
        assert_eq!(response.body, original.as_bytes());
        assert_event_routing(&event_log_path, "request_seen", "protected_upstream");
        assert_policy_decision_reason_contains(&event_log_path, "rewrite refused");
        assert_event_routing(&event_log_path, "response_served", "protected_upstream");
    }

    #[test]
    fn disabled_interventions_bypass_surface_controller_at_runtime() {
        let event_log_path = unique_temp_path("disabled-events.jsonl");
        let control_path = unique_temp_path("disabled-control.txt");
        fs::write(&control_path, "disabled").expect("control file should write");
        let (upstream, upstream_handle) = spawn_upstream(json_response(r#"{"mode":"upstream"}"#));
        let runtime = test_runtime(
            upstream,
            &event_log_path,
            control_path,
            SurfaceAction::EidolonOwned {
                response: SurfaceResponse::new(202, Vec::new(), "should not serve"),
            },
        );

        let response =
            parse_downstream_response(&run_runtime_request(runtime, &get_request("/disabled")));
        let upstream_request = upstream_handle.join().expect("upstream thread should join");

        assert!(String::from_utf8(upstream_request)
            .expect("request should be utf8")
            .starts_with("GET /disabled HTTP/1.1\r\n"));
        assert_eq!(response.body, br#"{"mode":"upstream"}"#);
        assert_event_routing(&event_log_path, "request_seen", "protected_upstream");
        assert_event_routing(&event_log_path, "response_served", "protected_upstream");
    }

    #[test]
    fn disabled_interventions_forward_controlled_session_on_next_request() {
        let event_log_path = unique_temp_path("disabled-controlled-events.jsonl");
        let control_path = unique_temp_path("disabled-controlled-control.txt");
        fs::write(&control_path, "disabled").expect("control file should write");
        let (upstream, upstream_handle) = spawn_upstream(json_response(r#"{"mode":"upstream"}"#));
        let runtime = test_runtime(
            upstream,
            &event_log_path,
            control_path,
            SurfaceAction::ProtectedUpstream,
        );
        let cookie = cookie_header();
        set_runtime_policy_state(&runtime, &cookie, PolicyState::ControlledReality);

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &get_request_with_cookie("/api/v1/projects", &cookie),
        ));
        let upstream_request = upstream_handle.join().expect("upstream thread should join");

        assert!(String::from_utf8(upstream_request)
            .expect("request should be utf8")
            .starts_with("GET /api/v1/projects HTTP/1.1\r\n"));
        assert_eq!(response.body, br#"{"mode":"upstream"}"#);
        assert_event_routing(&event_log_path, "request_seen", "protected_upstream");
        assert_event_type_absent(&event_log_path, "reality_escape_attempt");
        assert_policy_decision_reason_contains(&event_log_path, "interventions disabled");
    }

    #[test]
    fn observes_safe_header_presence_without_values() {
        let headers = vec![
            HttpHeader {
                name: "User-Agent".to_string(),
                value: "not logged".to_string(),
            },
            HttpHeader {
                name: "Authorization".to_string(),
                value: "secret".to_string(),
            },
        ];

        let observed = safe_header_observations(&headers);

        assert!(observed
            .iter()
            .any(|header| header.name == "user-agent" && header.present));
        assert!(observed
            .iter()
            .any(|header| header.name == "authorization" && header.present));
        assert!(!observed.iter().any(|header| header.name == "secret"));
    }

    #[test]
    fn debug_path_strips_query_and_fragment_values() {
        assert_eq!(debug_path("/docs?token=secret"), "/docs");
        assert_eq!(debug_path("/docs#secret-fragment"), "/docs");
        assert_eq!(debug_path("/docs#secret-fragment?token=secret"), "/docs");
    }

    #[test]
    fn event_target_redacts_query_values_and_fragments() {
        assert_eq!(
            redacted_event_target("/docs?token=secret&mode=debug#secret-fragment"),
            "/docs?token=<redacted>&mode=<redacted>#<redacted>"
        );
        assert_eq!(
            redacted_event_target("/docs?flag&=secret"),
            "/docs?flag=<redacted>&<redacted>"
        );
        assert_eq!(redacted_event_target("/docs?"), "/docs?<redacted>");
        assert_eq!(redacted_event_target("/docs"), "/docs");
    }

    #[test]
    fn control_file_values_disable_interventions() {
        assert!(intervention_control_disables("disabled"));
        assert!(intervention_control_disables("off\n"));
        assert!(intervention_control_disables("0"));
        assert!(!intervention_control_disables("enabled"));
    }
}
