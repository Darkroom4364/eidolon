use std::{
    collections::{HashMap, HashSet, VecDeque},
    env, fmt, fs,
    io::{self, BufRead, BufReader, Read, Write},
    net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use eidolon_bait::{docs_for_bait, render_bait_for_session, BaitRegistry};
use eidolon_core::{
    Bait, BaitClass, BaitHeaderValueMintStatus, BaitId, DiscoveryReconScore, Event, EventKind,
    EventSource, ExposureId, HeaderValueMint, PolicyState, RoutingDecision, SafeHeaderObservation,
    SessionId, EVENT_SCHEMA_VERSION,
};
use eidolon_proxy::{
    controlled_reality::{
        rate_limited_response, ControlledRealityConfig, ControlledRealityResponder,
        DECOY_RECONCILE_PATH, DEFAULT_RETRY_AFTER_SECONDS, DEFAULT_TARPIT_DELAY,
        MAX_CONTROLLED_REALITY_ACTION_DEPTH, MAX_TARPIT_DELAY,
    },
    debug_log::FileDebugLogWriter,
    event_log::FileEventLogWriter,
    ingress_identity::{self, IngressIdentityResolver},
    policy::{self, InterventionMode},
    policy_store::PolicyStateStore,
    session::{self, SessionContext},
    surface::{
        rewrite_response_body, HtmlInsertion, OpenApiPathInsertion, RewritePlan, SurfaceAction,
        SurfaceController, SurfaceHeader, SurfaceRequestMeta, SurfaceResponse, SurfaceResponseMeta,
    },
};
use serde::Deserialize;
use serde_json::{json, Map, Value};

const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:8080";
const DEFAULT_UPSTREAM: &str = "http://127.0.0.1:9001";
const DEFAULT_EVENT_LOG: &str = "/tmp/eidolon-events.jsonl";
const DEFAULT_INTERVENTION_CONTROL: &str = "/tmp/eidolon-interventions.txt";
const DEFAULT_POLICY_STATE: &str = "/tmp/eidolon-policy-state.json";
const DEFAULT_TRUSTED_BAIT_SOFTEN_PREFIXES: &[&str] = &["/docs", "/openapi.json"];
const DOCS_DISCOVERY_TARGET: &str = "/docs";
const OPENAPI_DISCOVERY_TARGET: &str = "/openapi.json";
const LEGACY_IMPORT_OPENAPI_QUERY: &str = "eidolon_surface=legacy-import";
const DEFAULT_HTTP_PORT: u16 = 80;
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;
const MAX_BAIT_EXPOSURES: usize = 4096;
const MAX_CONCURRENT_CONNECTIONS: usize = 64;
const CLIENT_IO_TIMEOUT: Duration = Duration::from_secs(30);
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const UPSTREAM_IO_TIMEOUT: Duration = Duration::from_secs(30);
const SAFE_HEADER_NAMES: &[&str] = &[
    "accept",
    "authorization",
    "content-type",
    "cookie",
    "referer",
    "user-agent",
    "x-api-key",
    "x-eidolon-ingress-identity-expires-at",
    "x-eidolon-ingress-identity-label",
    "x-eidolon-ingress-identity-source",
    "x-eidolon-ingress-trust-tier",
    "x-eidolon-ingress-verification-strength",
    "x-eidolon-ingress-actor-kind",
    "x-eidolon-ingress-verified-category",
    "x-eidolon-ingress-attestation-ref",
    "x-eidolon-ingress-vendor-score",
    "x-eidolon-ingress-vendor-score-kind",
    "x-eidolon-ingress-vendor-score-scale",
    "x-eidolon-ingress-detection-ids",
    "x-eidolon-ingress-edge-action",
];

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
    ingress_trust_config_path: Option<PathBuf>,
    ingress_transport_auth_secret_path: Option<PathBuf>,
    trusted_bait_soften_path_prefixes: Vec<String>,
    intervention_control_path: PathBuf,
    policy_state_path: PathBuf,
    controlled_reality_config: ControlledRealityConfig,
    owned_cluster_lab: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UpstreamTarget {
    raw: String,
    authority: String,
    connect_addr: String,
}

impl fmt::Display for UpstreamTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.raw)
    }
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

    let (host, port) = parse_authority(authority)?;
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

fn parse_authority(authority: &str) -> Result<(&str, Option<u16>), ConfigError> {
    if let Some(rest) = authority.strip_prefix('[') {
        let Some(close_index) = rest.find(']') else {
            return Err(ConfigError::new(
                "IPv6 upstream target hosts must close the `]` bracket",
            ));
        };
        let host = &rest[..close_index];
        let suffix = &rest[close_index + 1..];
        let port = if suffix.is_empty() {
            None
        } else if let Some(raw_port) = suffix.strip_prefix(':') {
            Some(parse_port(raw_port, "upstream target port")?)
        } else {
            return Err(ConfigError::new(
                "upstream target must put the port after the IPv6 host bracket",
            ));
        };

        if host.is_empty() {
            return Err(ConfigError::new("upstream target host cannot be empty"));
        }

        return Ok((host, port));
    }

    if authority.matches(':').count() > 1 {
        return Err(ConfigError::new(
            "IPv6 upstream target hosts must be bracketed, for example http://[::1]:9001",
        ));
    }

    if let Some((host, raw_port)) = authority.rsplit_once(':') {
        if host.is_empty() {
            return Err(ConfigError::new("upstream target host cannot be empty"));
        }

        return Ok((host, Some(parse_port(raw_port, "upstream target port")?)));
    }

    Ok((authority, None))
}

fn parse_port(raw: &str, label: &str) -> Result<u16, ConfigError> {
    if raw.is_empty() {
        return Err(ConfigError::new(format!("{label} cannot be empty")));
    }

    raw.parse::<u16>()
        .map_err(|error| ConfigError::new(format!("{label} must be a valid TCP port: {error}")))
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

fn configure_stream_timeouts(
    stream: &TcpStream,
    read_timeout: Duration,
    write_timeout: Duration,
) -> io::Result<()> {
    stream.set_read_timeout(Some(read_timeout))?;
    stream.set_write_timeout(Some(write_timeout))?;
    Ok(())
}

fn configure_client_stream(stream: &TcpStream) -> io::Result<()> {
    configure_stream_timeouts(stream, CLIENT_IO_TIMEOUT, CLIENT_IO_TIMEOUT)
}

fn configure_upstream_stream(stream: &TcpStream) -> io::Result<()> {
    configure_stream_timeouts(stream, UPSTREAM_IO_TIMEOUT, UPSTREAM_IO_TIMEOUT)
}

fn connect_upstream(upstream: &UpstreamTarget) -> io::Result<TcpStream> {
    let mut last_error = None;

    for addr in upstream.connect_addr.to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, UPSTREAM_CONNECT_TIMEOUT) {
            Ok(stream) => {
                configure_upstream_stream(&stream)?;
                return Ok(stream);
            }
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| {
        invalid_data(format!(
            "upstream target `{}` resolved to no socket addresses",
            upstream.connect_addr
        ))
    }))
}

#[derive(Clone)]
struct ConnectionLimiter {
    active: Arc<AtomicUsize>,
    limit: usize,
}

impl ConnectionLimiter {
    fn new(limit: usize) -> Self {
        assert!(limit > 0, "connection limit must be positive");

        Self {
            active: Arc::new(AtomicUsize::new(0)),
            limit,
        }
    }

    fn try_acquire(&self) -> Option<ConnectionPermit> {
        let mut active = self.active.load(Ordering::Acquire);
        loop {
            if active >= self.limit {
                return None;
            }

            match self.active.compare_exchange_weak(
                active,
                active + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(ConnectionPermit {
                        active: Arc::clone(&self.active),
                    });
                }
                Err(current) => active = current,
            }
        }
    }

    #[cfg(test)]
    fn active_for_test(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }
}

struct ConnectionPermit {
    active: Arc<AtomicUsize>,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        let previous = self.active.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "connection permit underflow");
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
    let bait_exposures = BaitExposureStore::from_event_log(&config.event_log_path)?;
    let restored_bait_exposure_count = bait_exposures.len();
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
            "ingress_identity_rule_count": runtime.ingress_identity_resolver.len(),
            "ingress_transport_auth_enabled": runtime.ingress_transport_auth_secret.is_some(),
            "trusted_bait_soften_path_prefixes": runtime.trusted_bait_soften_path_prefixes,
            "restored_bait_exposure_count": restored_bait_exposure_count,
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

#[derive(Clone)]
struct ProxyRuntime {
    upstream: UpstreamTarget,
    event_log: Arc<Mutex<FileEventLogWriter>>,
    debug_log: Option<Arc<Mutex<FileDebugLogWriter>>>,
    intervention_control_path: PathBuf,
    policy_store: Arc<Mutex<PolicyStateStore>>,
    controlled_reality_config: ControlledRealityConfig,
    controlled_reality: Arc<ControlledRealityResponder>,
    surface_controller: Arc<dyn SurfaceController + Send + Sync>,
    ingress_identity_resolver: Arc<IngressIdentityResolver>,
    ingress_transport_auth_secret: Option<Arc<str>>,
    bait_signing_secret: Option<Arc<str>>,
    trusted_bait_soften_path_prefixes: Vec<String>,
    bait_registry: Arc<BaitRegistry>,
    bait_content: BaitContentOverrides,
    bait_exposures: Arc<Mutex<BaitExposureStore>>,
}

#[derive(Debug, Default)]
struct BaitExposureStore {
    exposures: HashMap<(SessionId, BaitId), ExposureId>,
    exposure_order: VecDeque<(SessionId, BaitId)>,
}

impl BaitExposureStore {
    fn from_event_log(path: &Path) -> io::Result<Self> {
        let file = match fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => return Err(error),
        };

        Self::from_event_log_reader(BufReader::new(file))
    }

    fn from_event_log_reader(reader: impl BufRead) -> io::Result<Self> {
        let mut store = Self::default();

        for (line_index, line) in reader.lines().enumerate() {
            let line_number = line_index + 1;
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }

            let value: Value = serde_json::from_str(&line).map_err(|error| {
                invalid_data(format!(
                    "could not rebuild bait exposure store from event log line {line_number}: {error}"
                ))
            })?;
            let schema_version = value
                .get("schema_version")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    invalid_data(format!(
                        "could not rebuild bait exposure store from event log line {line_number}: missing schema_version"
                    ))
                })?;
            if schema_version != u64::from(EVENT_SCHEMA_VERSION) {
                return Err(invalid_data(format!(
                    "could not rebuild bait exposure store from event log line {line_number}: unsupported schema_version {schema_version}; expected {EVENT_SCHEMA_VERSION}"
                )));
            }

            let event: Event = serde_json::from_value(value).map_err(|error| {
                invalid_data(format!(
                    "could not rebuild bait exposure store from event log line {line_number}: {error}"
                ))
            })?;

            if let EventKind::BaitExposed {
                bait_id,
                exposure_id,
                ..
            } = event.kind
            {
                store.record_exposure(event.session_id, bait_id, exposure_id);
            }
        }

        Ok(store)
    }

    fn len(&self) -> usize {
        self.exposures.len()
    }

    fn record_exposure(&mut self, session_id: SessionId, bait_id: BaitId, exposure_id: ExposureId) {
        let key = (session_id, bait_id);
        if self.exposures.insert(key.clone(), exposure_id).is_some() {
            self.exposure_order.retain(|existing| existing != &key);
        }
        self.exposure_order.push_back(key);

        while self.exposures.len() > MAX_BAIT_EXPOSURES {
            if let Some(oldest) = self.exposure_order.pop_front() {
                self.exposures.remove(&oldest);
            }
        }
    }

    fn exposure_for_action(&self, session_id: SessionId, bait_id: &BaitId) -> Option<ExposureId> {
        self.exposures.get(&(session_id, bait_id.clone())).cloned()
    }
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

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct BaitContentOverrides {
    docs_discovery_heading: Option<String>,
    openapi: OpenApiOperationOverride,
    surfaces: HashMap<String, SurfaceContentOverride>,
}

impl BaitContentOverrides {
    fn surface_for(&self, bait: &Bait) -> Option<&SurfaceContentOverride> {
        self.surfaces.get(&bait.id.0)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        validate_optional_non_empty(
            "content.docs_discovery_heading",
            self.docs_discovery_heading.as_deref(),
        )?;
        self.openapi.validate()?;

        for (bait_id, surface) in &self.surfaces {
            validate_non_empty("content.surfaces bait id", bait_id)?;
            surface.validate(bait_id)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct OpenApiOperationOverride {
    summary: Option<String>,
    description: Option<String>,
    operation_id: Option<String>,
    tags: Vec<String>,
    response_status: Option<String>,
    response_description: Option<String>,
    request_body: Option<Value>,
    path_item: Option<Value>,
}

impl OpenApiOperationOverride {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_optional_non_empty("content.openapi.summary", self.summary.as_deref())?;
        validate_optional_non_empty("content.openapi.description", self.description.as_deref())?;
        validate_optional_non_empty("content.openapi.operation_id", self.operation_id.as_deref())?;
        validate_optional_non_empty(
            "content.openapi.response_status",
            self.response_status.as_deref(),
        )?;
        validate_optional_non_empty(
            "content.openapi.response_description",
            self.response_description.as_deref(),
        )?;

        for tag in &self.tags {
            validate_non_empty("content.openapi.tags", tag)?;
        }

        if let Some(path_item) = &self.path_item {
            if !path_item.is_object() {
                return Err(ConfigError::new(
                    "content.openapi.path_item must be a JSON object",
                ));
            }
        }

        if let Some(request_body) = &self.request_body {
            if !request_body.is_object() {
                return Err(ConfigError::new(
                    "content.openapi.request_body must be a JSON object",
                ));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct SurfaceContentOverride {
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    content_type: Option<String>,
    body: String,
}

impl SurfaceContentOverride {
    fn validate(&self, bait_id: &str) -> Result<(), ConfigError> {
        if matches!(self.status, Some(status) if !(100..600).contains(&status)) {
            return Err(ConfigError::new(format!(
                "content.surfaces.{bait_id}.status must be an HTTP status code"
            )));
        }
        validate_optional_non_empty(
            &format!("content.surfaces.{bait_id}.content_type"),
            self.content_type.as_deref(),
        )?;
        validate_non_empty(&format!("content.surfaces.{bait_id}.body"), &self.body)
    }
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
        self.content.validate()?;

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
    validate_non_empty(&format!("{label}.prefix"), &mint.prefix)
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

struct M1DemoSurfaceController {
    bait_registry: Arc<BaitRegistry>,
    content: BaitContentOverrides,
    bait_signing_secret: Option<Arc<str>>,
}

impl M1DemoSurfaceController {
    fn with_content_overrides(
        bait_registry: Arc<BaitRegistry>,
        content: BaitContentOverrides,
        bait_signing_secret: Option<Arc<str>>,
    ) -> Self {
        Self {
            bait_registry,
            content,
            bait_signing_secret,
        }
    }

    fn bait_for_class(&self, bait_class: BaitClass) -> Option<&Bait> {
        self.bait_registry.bait_for_class(bait_class)
    }
}

impl SurfaceController for M1DemoSurfaceController {
    fn decide(
        &self,
        request: &SurfaceRequestMeta,
        session_id: SessionId,
    ) -> io::Result<SurfaceAction> {
        if request.method == "GET" {
            if let Some(bait) = self.bait_registry.bait_for_surface(&request.path) {
                if bait.bait_class != BaitClass::OpenApi {
                    let bait = render_bait_for_session(
                        bait,
                        session_id,
                        self.bait_signing_secret.as_deref(),
                    )
                    .map_err(|error| invalid_data(error.to_string()))?;
                    return Ok(SurfaceAction::EidolonOwned {
                        response: bait_surface_response(&bait, &self.content),
                    });
                }
            }
        }

        if request.method == "GET" && request.path == DOCS_DISCOVERY_TARGET {
            return Ok(SurfaceAction::RewrittenUpstream {
                plan: RewritePlan::html(HtmlInsertion::new(m3_docs_discovery_html(
                    &self.bait_registry,
                    &self.content,
                ))),
            });
        }

        if let Some(bait) = self.bait_for_class(BaitClass::OpenApi) {
            if !is_openapi_discovery_request(request, bait) {
                return Ok(SurfaceAction::ProtectedUpstream);
            }
            let bait =
                render_bait_for_session(bait, session_id, self.bait_signing_secret.as_deref())
                    .map_err(|error| invalid_data(error.to_string()))?;

            return Ok(SurfaceAction::RewrittenUpstream {
                plan: RewritePlan::openapi_paths(vec![openapi_path_insertion_for_bait(
                    &bait,
                    &self.content.openapi,
                )]),
            });
        }

        Ok(SurfaceAction::ProtectedUpstream)
    }
}

fn is_openapi_discovery_request(request: &SurfaceRequestMeta, bait: &Bait) -> bool {
    request.method == "GET"
        && request.path == bait.surface
        && matches!(
            request.query.as_deref(),
            None | Some(LEGACY_IMPORT_OPENAPI_QUERY)
        )
}

fn is_legacy_openapi_discovery_query(request: &SurfaceRequestMeta) -> bool {
    request.method == "GET"
        && request.path == OPENAPI_DISCOVERY_TARGET
        && request.query.as_deref() == Some(LEGACY_IMPORT_OPENAPI_QUERY)
}

fn linked_bait_surface_kind(
    runtime: &ProxyRuntime,
    request: &SurfaceRequestMeta,
) -> Option<policy::LinkedBaitSurfaceKind> {
    if request.method != "GET" {
        return None;
    }

    runtime
        .bait_registry
        .baits()
        .iter()
        .find(|bait| bait.bait_class != BaitClass::OpenApi && bait.surface == request.path)
        .map(|_| {
            if request.path.starts_with("/docs/") {
                policy::LinkedBaitSurfaceKind::Docs
            } else if request.path.starts_with("/assets/") {
                policy::LinkedBaitSurfaceKind::Assets
            } else {
                policy::LinkedBaitSurfaceKind::Other
            }
        })
}

fn is_blind_decoy_write_probe(
    runtime: &ProxyRuntime,
    session_id: SessionId,
    request: &SurfaceRequestMeta,
) -> bool {
    blind_decoy_write_probe_path_kind(runtime, session_id, request).is_some()
}

fn blind_decoy_write_probe_path_kind(
    runtime: &ProxyRuntime,
    session_id: SessionId,
    request: &SurfaceRequestMeta,
) -> Option<policy::DecoyWriteProbePathKind> {
    if !matches!(request.method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE") {
        return None;
    }

    let headers: Vec<(&str, &str)> = surface_header_pairs(&request.headers).collect();
    if runtime
        .bait_registry
        .match_action_for_session(
            &request.method,
            &request.path,
            headers.iter().copied(),
            session_id,
            runtime.bait_signing_secret.as_deref(),
        )
        .ok()
        .flatten()
        .is_some()
        || runtime
            .bait_registry
            .match_action_shape(&request.method, &request.path, headers.iter().copied())
            .is_some()
    {
        return None;
    }

    runtime.bait_registry.baits().iter().find(|bait| {
        bait.expected_action
            .method
            .eq_ignore_ascii_case(&request.method)
            && bait.expected_action.path == request.path
            && bait.expected_action.header_name.is_some()
    })?;

    Some(if request.path == DECOY_RECONCILE_PATH {
        policy::DecoyWriteProbePathKind::Reconcile
    } else {
        policy::DecoyWriteProbePathKind::Other
    })
}

fn is_aggregated_discovery_recon_candidate_request(
    runtime: &ProxyRuntime,
    session_id: SessionId,
    request: &SurfaceRequestMeta,
) -> bool {
    discovery_surface_kind(runtime, request).is_some()
        || linked_bait_surface_kind(runtime, request).is_some()
        || is_blind_decoy_write_probe(runtime, session_id, request)
}

fn discovery_surface_kind(
    runtime: &ProxyRuntime,
    request: &SurfaceRequestMeta,
) -> Option<policy::DiscoverySurfaceKind> {
    if request.method != "GET" {
        return None;
    }
    if request.path == DOCS_DISCOVERY_TARGET {
        return Some(policy::DiscoverySurfaceKind::Docs);
    }

    runtime
        .bait_registry
        .bait_for_class(BaitClass::OpenApi)
        .filter(|bait| is_openapi_discovery_request(request, bait))
        .map(|_| policy::DiscoverySurfaceKind::OpenApi)
}

fn m3_docs_discovery_html(bait_registry: &BaitRegistry, content: &BaitContentOverrides) -> String {
    let heading = content
        .docs_discovery_heading
        .as_deref()
        .unwrap_or("Customer import recovery controls");
    let mut html = format!(
        r#"
    <section data-eidolon-discovery="m3-legacy-import">
      <h2>{}</h2>
"#,
        html_escape(heading)
    );

    for bait in bait_registry
        .baits()
        .iter()
        .filter(|bait| bait.bait_class != BaitClass::OpenApi)
    {
        html.push_str(&format!(
            "      <p><a href=\"{}\">{}</a></p>\n",
            html_escape(&bait.surface),
            html_escape(discovery_label(bait.bait_class)),
        ));
    }

    html.push_str("    </section>\n    ");
    html
}

fn discovery_label(bait_class: BaitClass) -> &'static str {
    match bait_class {
        BaitClass::Docs => "Customer import notes",
        BaitClass::HiddenRoute => "Customer import recovery checklist",
        BaitClass::FakeCredentialToken => "Import reconciliation token note",
        BaitClass::JsDiscoveredRoute => "Customer import helper manifest",
        BaitClass::OpenApi => "Customer import API hook",
    }
}

fn html_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '"' => escaped.push_str("&quot;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

fn bait_surface_response(bait: &Bait, content: &BaitContentOverrides) -> SurfaceResponse {
    if let Some(override_content) = content.surface_for(bait) {
        return SurfaceResponse::new(
            override_content.status.unwrap_or(200),
            vec![SurfaceHeader::new(
                "Content-Type",
                override_content
                    .content_type
                    .as_deref()
                    .unwrap_or_else(|| default_surface_content_type(bait.bait_class)),
            )],
            override_content.body.clone(),
        );
    }

    match bait.bait_class {
        BaitClass::Docs => SurfaceResponse::new(
            200,
            vec![SurfaceHeader::new(
                "Content-Type",
                "text/markdown; charset=utf-8",
            )],
            docs_for_bait(bait),
        ),
        BaitClass::HiddenRoute => SurfaceResponse::new(
            200,
            vec![SurfaceHeader::new(
                "Content-Type",
                "text/markdown; charset=utf-8",
            )],
            action_markdown(
                "Customer Import Recovery Checklist",
                "Client-reachable recovery notes for customer upload retries. The trace header gates queueing only; it does not prove tenant ownership of the submitted import source.",
                bait,
            ),
        ),
        BaitClass::FakeCredentialToken => SurfaceResponse::new(
            200,
            vec![SurfaceHeader::new(
                "Content-Type",
                "text/markdown; charset=utf-8",
            )],
            action_markdown(
                "Import Reconciliation Token Notes",
                "Compatibility token accepted by the import API from external client requests. Possession of the header value is sufficient to queue tenant reconciliation.",
                bait,
            ),
        ),
        BaitClass::JsDiscoveredRoute => SurfaceResponse::new(
            200,
            vec![SurfaceHeader::new(
                "Content-Type",
                "application/javascript; charset=utf-8",
            )],
            javascript_for_bait(bait),
        ),
        BaitClass::OpenApi => surface_text_response(404, "openapi bait is exposed by rewrite\n"),
    }
}

fn default_surface_content_type(bait_class: BaitClass) -> &'static str {
    match bait_class {
        BaitClass::JsDiscoveredRoute => "application/javascript; charset=utf-8",
        _ => "text/markdown; charset=utf-8",
    }
}

fn action_markdown(title: &str, description: &str, bait: &Bait) -> String {
    let action = &bait.expected_action;
    let header_name = action.header_name.as_deref().unwrap_or("X-Migration-Trace");
    let header_value = action.header_value.as_deref().unwrap_or(&bait.id.0);

    format!(
        "# {title}\n\n{description}\n\nUse `{header_name}: {header_value}` with:\n\n```http\n{} {}\n```\n",
        action.method, action.path
    )
}

fn javascript_for_bait(bait: &Bait) -> String {
    let action = &bait.expected_action;
    let header_name = action.header_name.as_deref().unwrap_or("X-Migration-Trace");
    let header_value = action.header_value.as_deref().unwrap_or(&bait.id.0);
    let payload = json!({
        "resumeEndpoint": action.path,
        "method": action.method,
        "headerName": header_name,
        "headerValue": header_value,
        "inputOrigin": "external_customer_request",
        "trustBoundary": "browser_upload_to_import_reconcile_api",
        "authorizationModel": "legacy_header_only",
        "effect": "queues tenant import reconciliation",
    });

    format!("window.__eidolonImportWorker = {payload};\n")
}

fn openapi_path_insertion_for_bait(
    bait: &Bait,
    openapi: &OpenApiOperationOverride,
) -> OpenApiPathInsertion {
    if let Some(path_item) = &openapi.path_item {
        return OpenApiPathInsertion::new(bait.expected_action.path.clone(), path_item.clone());
    }

    let action = &bait.expected_action;
    let header_name = action.header_name.as_deref().unwrap_or("X-Migration-Trace");
    let header_value = action.header_value.as_deref().unwrap_or(&bait.id.0);
    let summary = openapi
        .summary
        .as_deref()
        .unwrap_or("Customer import reconciliation endpoint");
    let response_status = openapi.response_status.as_deref().unwrap_or("202");
    let response_description = openapi
        .response_description
        .as_deref()
        .unwrap_or("Customer import reconciliation request accepted");
    let mut operation = Map::new();

    operation.insert("summary".to_string(), json!(summary));
    operation.insert(
        "description".to_string(),
        json!(openapi.description.as_deref().unwrap_or(
            "Accepts customer-controlled import manifests and source URLs from the public import workflow. The legacy trace header is a compatibility gate only; possession of the header value from an external client request is sufficient to enqueue tenant reconciliation."
        )),
    );
    if let Some(operation_id) = &openapi.operation_id {
        operation.insert("operationId".to_string(), json!(operation_id));
    }
    let tags = if openapi.tags.is_empty() {
        vec![
            "customer-imports".to_string(),
            "legacy-reconciliation".to_string(),
        ]
    } else {
        openapi.tags.clone()
    };
    operation.insert("tags".to_string(), json!(tags));
    operation.insert(
        "parameters".to_string(),
        json!([
            {
                "name": header_name,
                "in": "header",
                "required": true,
                "description": "Legacy compatibility gate accepted from external client requests; this value alone authorizes queueing reconciliation.",
                "schema": { "type": "string", "example": header_value }
            }
        ]),
    );
    operation.insert(
        "requestBody".to_string(),
        openapi
            .request_body
            .clone()
            .unwrap_or_else(default_openapi_reconcile_request_body),
    );

    let mut responses = Map::new();
    responses.insert(
        response_status.to_string(),
        json!({ "description": response_description }),
    );
    operation.insert("responses".to_string(), Value::Object(responses));

    OpenApiPathInsertion::new(
        action.path.clone(),
        Value::Object(Map::from_iter([(
            action.method.to_ascii_lowercase(),
            Value::Object(operation),
        )])),
    )
}

fn owned_openapi_discovery_response(
    bait: &Bait,
    openapi: &OpenApiOperationOverride,
) -> SurfaceResponse {
    let insertion = openapi_path_insertion_for_bait(bait, openapi);
    let mut paths = Map::new();
    paths.insert(insertion.path, insertion.path_item);
    let document = json!({
        "openapi": "3.0.3",
        "info": {
            "title": "Customer import recovery schema",
            "version": "0.0.0-eidolon"
        },
        "paths": Value::Object(paths),
    });

    match serde_json::to_vec(&document) {
        Ok(body) => SurfaceResponse::new(
            200,
            vec![SurfaceHeader::new(
                "Content-Type",
                "application/json; charset=utf-8",
            )],
            body,
        ),
        Err(_) => surface_text_response(500, "failed to render owned openapi discovery response\n"),
    }
}

fn default_openapi_reconcile_request_body() -> Value {
    json!({
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
                        "source": {
                            "type": "string",
                            "description": "Customer-controlled import manifest label or inline source selector."
                        },
                        "tenant_id": {
                            "type": "string",
                            "description": "Tenant identifier supplied by the caller."
                        },
                        "reconcile_mode": {
                            "type": "string",
                            "enum": ["merge", "overwrite", "preview"],
                            "description": "Caller-selected reconciliation behavior."
                        },
                        "dry_run": {
                            "type": "boolean",
                            "description": "Preview flag; legacy clients can omit it when queueing repair jobs."
                        }
                    }
                }
            }
        }
    })
}

fn is_success_status(status: u16) -> bool {
    (200..300).contains(&status)
}

fn handle_connection(mut client_stream: TcpStream, runtime: &ProxyRuntime) -> io::Result<()> {
    configure_client_stream(&client_stream)?;

    let client_peer_addr = client_stream.peer_addr().ok();
    let client_peer = client_peer_addr.as_ref().map(ToString::to_string);
    let client_peer_ip = client_peer_addr.map(|addr| addr.ip());
    let Some(request) = read_http_request(&mut client_stream)? else {
        write_debug(
            runtime,
            "connection_closed_without_request",
            None,
            json!({
                "client_peer": client_peer,
            }),
        )?;
        return Ok(());
    };

    let intervention_mode = intervention_mode_from_control_file(&runtime.intervention_control_path);
    let path = normalized_event_path(&request)?;
    let surface_request = surface_request_meta(&request, &path);
    let session = effective_session_context(runtime, &request, &surface_request, client_peer_ip);
    let mut policy_state = policy_state_for_session(runtime, session.session_id)?;
    let starting_policy_state = policy_state;
    let mut policy_reason_override = None;
    let discovery_recon_state =
        update_discovery_recon_state_for_request(runtime, session.session_id, &surface_request)?;
    let discovery_recon_score =
        policy::aggregated_discovery_recon_score(&session.ingress_signals, discovery_recon_state);
    let mut discovery_recon_threshold = policy::discovery_recon_aggregation_score_threshold();
    if intervention_mode.interventions_enabled() {
        if let Some(transition) = policy::transition_to_suspicious_from_ingress_signals(
            policy_state,
            &surface_request.path,
            &runtime.trusted_bait_soften_path_prefixes,
            &session.ingress_identity,
            &session.ingress_signals,
        ) {
            write_debug(
                runtime,
                "policy_transition_selected",
                Some(session.session_id),
                json!({
                    "from": transition.from,
                    "to": transition.to,
                    "reason": transition.reason.as_str(),
                }),
            )?;
            set_policy_state_for_session(runtime, session.session_id, transition.to)?;
            write_event(
                &runtime.event_log,
                &policy::policy_changed_event(session.session_id, &transition),
            )?;
            policy_state = transition.to;
        } else if let Some(transition) = policy::transition_to_suspicious_from_discovery_fanout(
            policy_state,
            &surface_request.path,
            &session.ingress_identity,
            discovery_recon_state.fanout,
        ) {
            write_debug(
                runtime,
                "policy_transition_selected",
                Some(session.session_id),
                json!({
                    "from": transition.from,
                    "to": transition.to,
                    "reason": transition.reason.as_str(),
                }),
            )?;
            set_policy_state_for_session(runtime, session.session_id, transition.to)?;
            write_event(
                &runtime.event_log,
                &policy::policy_changed_event(session.session_id, &transition),
            )?;
            policy_state = transition.to;
        } else if let Some(transition) =
            policy::transition_to_suspicious_from_aggregated_discovery_recon(
                policy_state,
                &surface_request.path,
                is_aggregated_discovery_recon_candidate_request(
                    runtime,
                    session.session_id,
                    &surface_request,
                ),
                &session.ingress_identity,
                &session.ingress_signals,
                discovery_recon_state,
            )
        {
            write_debug(
                runtime,
                "policy_transition_selected",
                Some(session.session_id),
                json!({
                    "from": transition.from,
                    "to": transition.to,
                    "reason": transition.reason.as_str(),
                }),
            )?;
            set_policy_state_for_session(runtime, session.session_id, transition.to)?;
            write_event(
                &runtime.event_log,
                &policy::policy_changed_event(session.session_id, &transition),
            )?;
            policy_state = transition.to;
        }
        if starting_policy_state == PolicyState::Suspicious {
            if let Some(transition) =
                policy::transition_to_rate_limited_from_suspicious_discovery_recon(
                    policy_state,
                    &surface_request.path,
                    discovery_surface_kind(runtime, &surface_request).is_some(),
                    blind_decoy_write_probe_path_kind(
                        runtime,
                        session.session_id,
                        &surface_request,
                    )
                    .is_some(),
                    &session.ingress_identity,
                    &session.ingress_signals,
                    discovery_recon_state,
                )
            {
                write_debug(
                    runtime,
                    "policy_transition_selected",
                    Some(session.session_id),
                    json!({
                        "from": transition.from,
                        "to": transition.to,
                        "reason": transition.reason.as_str(),
                    }),
                )?;
                set_policy_state_for_session(runtime, session.session_id, transition.to)?;
                write_event(
                    &runtime.event_log,
                    &policy::policy_changed_event(session.session_id, &transition),
                )?;
                discovery_recon_threshold = policy::discovery_recon_rate_limit_score_threshold();
                policy_state = transition.to;
            }
        } else if starting_policy_state == PolicyState::RateLimited {
            if let Some(transition) = policy::transition_to_blocked_from_repeated_discovery_recon(
                policy_state,
                &surface_request.path,
                discovery_surface_kind(runtime, &surface_request).is_some(),
                blind_decoy_write_probe_path_kind(runtime, session.session_id, &surface_request)
                    .is_some(),
                &session.ingress_identity,
                &session.ingress_signals,
                discovery_recon_state,
            ) {
                write_debug(
                    runtime,
                    "policy_transition_selected",
                    Some(session.session_id),
                    json!({
                        "from": transition.from,
                        "to": transition.to,
                        "reason": transition.reason.as_str(),
                    }),
                )?;
                set_policy_state_for_session(runtime, session.session_id, transition.to)?;
                write_event(
                    &runtime.event_log,
                    &policy::policy_changed_event(session.session_id, &transition),
                )?;
                discovery_recon_threshold = policy::discovery_recon_rate_limit_score_threshold();
                policy_reason_override = Some(transition.reason);
                policy_state = transition.to;
            }
        }
    }
    write_debug(
        runtime,
        "request_received",
        Some(session.session_id),
        json!({
            "client_peer": client_peer,
            "method": request.method.as_str(),
            "target_form": debug_target_form(&request.target),
            "request_host": effective_request_host(&request),
            "path": debug_path(&path),
            "query_present": debug_query_present(&path),
            "http_version": request.version.as_str(),
            "body_len": request.body.len(),
            "header_count": request.headers.len(),
            "safe_headers": safe_header_observations(&request.headers),
            "session_source": debug_session_source(session.source),
            "ingress_identity": &session.ingress_identity,
            "local_ingress_trust_scope_rejection":
                &session.local_ingress_trust_scope_rejection,
            "ingress_signals": &session.ingress_signals,
            "trusted_ingress_local_soften_path_prefixes":
                &session.trusted_bait_soften_path_prefixes,
            "discovery_surface_fanout":
                debug_discovery_surface_fanout(discovery_recon_state.fanout),
            "discovery_request_count": discovery_recon_state.request_count,
            "discovery_query_seen": discovery_recon_state.query_seen,
            "discovery_legacy_openapi_query_seen":
                discovery_recon_state.legacy_openapi_query_seen,
            "discovery_linked_bait_surface_seen":
                discovery_recon_state.linked_bait_surface_seen,
            "discovery_linked_bait_surface_classes":
                discovery_recon_state.linked_bait_surface_classes,
            "discovery_decoy_write_probe_seen":
                discovery_recon_state.decoy_write_probe_seen,
            "discovery_decoy_write_probe_count":
                discovery_recon_state.decoy_write_probe_count,
            "discovery_decoy_write_probe_path_classes":
                discovery_recon_state.decoy_write_probe_path_classes,
            "discovery_recon_score": {
                "repeated_discovery_score": discovery_recon_score.repeated_discovery_score,
                "query_score": discovery_recon_score.query_score,
                "legacy_openapi_query_score":
                    discovery_recon_score.legacy_openapi_query_score,
                "linked_bait_surface_score":
                    discovery_recon_score.linked_bait_surface_score,
                "linked_bait_class_fanout_bonus":
                    discovery_recon_score.linked_bait_class_fanout_bonus,
                "decoy_write_probe_score":
                    discovery_recon_score.decoy_write_probe_score,
                "decoy_write_probe_path_fanout_bonus":
                    discovery_recon_score.decoy_write_probe_path_fanout_bonus,
                "detection_score": discovery_recon_score.detection_score,
                "total": discovery_recon_score.total,
                "threshold": discovery_recon_threshold,
            },
            "policy_state": policy_state,
            "intervention_mode": debug_intervention_mode(intervention_mode),
        }),
    )?;

    if !intervention_mode.interventions_enabled() {
        if let Some(response) = runtime
            .controlled_reality
            .fail_closed_response(&surface_request)
        {
            write_debug(
                runtime,
                "interventions_disabled_fail_closed",
                Some(session.session_id),
                json!({
                    "method": request.method.as_str(),
                    "path": debug_path(&surface_request.path),
                    "query_present": surface_request.query.is_some(),
                    "response_status": response.status,
                    "response_body_len": response.body.len(),
                }),
            )?;
            let decision = policy::PolicyDecision::new(
                policy_state,
                RoutingDecision::EidolonOwned,
                "interventions disabled; known controlled-reality write path failed closed",
            );

            return write_direct_response(DirectResponseContext {
                client_stream,
                runtime,
                session: &session,
                request: &request,
                path: &path,
                decision: &decision,
                discovery_recon_score,
                discovery_recon_threshold,
                response,
                intervention_mode,
                surface_requested_intervention: true,
            });
        }
    }

    let mut decision = policy::decide_for_state(policy_state, intervention_mode);
    if let Some(reason) = policy_reason_override {
        decision =
            policy::PolicyDecision::new(decision.policy_state, decision.routing_decision, reason);
    }
    let controller_surface_action = if intervention_mode.interventions_enabled() {
        match decision.routing_decision {
            RoutingDecision::ProtectedUpstream => runtime
                .surface_controller
                .decide(&surface_request, session.session_id)?,
            RoutingDecision::ControlledReality => {
                let (action, transition) = controlled_reality_action(
                    runtime,
                    session.session_id,
                    &surface_request,
                    decision.reason.clone(),
                )?;
                if let Some(transition) = transition {
                    write_debug(
                        runtime,
                        "policy_transition_selected",
                        Some(session.session_id),
                        json!({
                            "from": transition.from,
                            "to": transition.to,
                            "reason": transition.reason.as_str(),
                        }),
                    )?;
                    set_policy_state_for_session(runtime, session.session_id, transition.to)?;
                    write_event(
                        &runtime.event_log,
                        &policy::policy_changed_event(session.session_id, &transition),
                    )?;
                    let blocked_decision = policy::PolicyDecision::new(
                        transition.to,
                        action.routing_decision(),
                        transition.reason.clone(),
                    );
                    write_debug(
                        runtime,
                        "surface_action_selected",
                        Some(session.session_id),
                        json!({
                            "policy_state": blocked_decision.policy_state,
                            "policy_routing_decision": blocked_decision.routing_decision,
                            "policy_reason": blocked_decision.reason.as_str(),
                            "controller_surface_action": debug_surface_action(&action),
                            "candidate_surface_action": debug_surface_action(&action),
                            "surface_action": debug_surface_action(&action),
                            "surface_requested_intervention": true,
                            "trusted_ingress_softened_surface": false,
                            "trusted_ingress_softening_reason": Value::Null,
                            "trusted_bait_soften_path_prefixes": &runtime.trusted_bait_soften_path_prefixes,
                            "trusted_ingress_local_soften_path_prefixes":
                                &session.trusted_bait_soften_path_prefixes,
                        }),
                    )?;
                    let SurfaceAction::EidolonOwned { response } = action else {
                        panic!("blocked controlled-reality action should be eidolon owned");
                    };
                    return write_direct_response(DirectResponseContext {
                        client_stream,
                        runtime,
                        session: &session,
                        request: &request,
                        path: &path,
                        decision: &blocked_decision,
                        discovery_recon_score,
                        discovery_recon_threshold,
                        response,
                        intervention_mode,
                        surface_requested_intervention: true,
                    });
                }
                action
            }
            RoutingDecision::RateLimited => SurfaceAction::RateLimited {
                reason: decision.reason.clone(),
                response: rate_limited_response(
                    runtime.controlled_reality_config.retry_after_seconds,
                ),
            },
            RoutingDecision::EidolonOwned => SurfaceAction::EidolonOwned {
                response: surface_text_response(403, "blocked by eidolon policy\n"),
            },
            RoutingDecision::RewrittenUpstream => {
                return Err(invalid_data(
                    "policy requested rewritten upstream without a surface rewrite plan",
                ));
            }
        }
    } else {
        SurfaceAction::ProtectedUpstream
    };
    let candidate_surface_action = strengthen_surface_action_for_suspicious_discovery(
        runtime,
        session.session_id,
        decision.policy_state,
        &surface_request,
        controller_surface_action.clone(),
    )?;
    let (surface_action, trusted_ingress_softening_reason) =
        maybe_soften_surface_action_for_trusted_ingress(
            &runtime.trusted_bait_soften_path_prefixes,
            &session,
            decision.policy_state,
            &surface_request,
            candidate_surface_action.clone(),
        );
    let mut effective_decision = policy::PolicyDecision::new(
        decision.policy_state,
        surface_action.routing_decision(),
        trusted_ingress_softening_reason
            .clone()
            .unwrap_or_else(|| decision.reason.clone()),
    );
    let surface_requested_intervention =
        !matches!(&candidate_surface_action, SurfaceAction::ProtectedUpstream);
    write_debug(
        runtime,
        "surface_action_selected",
        Some(session.session_id),
        json!({
            "policy_state": decision.policy_state,
            "policy_routing_decision": decision.routing_decision,
            "policy_reason": decision.reason.as_str(),
            "controller_surface_action": debug_surface_action(&controller_surface_action),
            "candidate_surface_action": debug_surface_action(&candidate_surface_action),
            "surface_action": debug_surface_action(&surface_action),
            "surface_requested_intervention": surface_requested_intervention,
            "trusted_ingress_softened_surface": trusted_ingress_softening_reason.is_some(),
            "trusted_ingress_softening_reason": trusted_ingress_softening_reason,
            "trusted_bait_soften_path_prefixes": &runtime.trusted_bait_soften_path_prefixes,
            "trusted_ingress_local_soften_path_prefixes":
                &session.trusted_bait_soften_path_prefixes,
        }),
    )?;
    if let Some(transition) = maybe_transition_to_blocked_from_reality_escape_attempt(
        runtime,
        &session,
        &request,
        &surface_request,
        &effective_decision,
    )? {
        write_debug(
            runtime,
            "policy_transition_selected",
            Some(session.session_id),
            json!({
                "from": transition.from,
                "to": transition.to,
                "reason": transition.reason.as_str(),
            }),
        )?;
        set_policy_state_for_session(runtime, session.session_id, transition.to)?;
        write_event(
            &runtime.event_log,
            &policy::policy_changed_event(session.session_id, &transition),
        )?;
        let blocked_decision = policy::PolicyDecision::new(
            transition.to,
            RoutingDecision::EidolonOwned,
            transition.reason.clone(),
        );
        let blocked_response = surface_text_response(403, "blocked by eidolon policy\n");
        let blocked_surface_action = SurfaceAction::EidolonOwned {
            response: blocked_response.clone(),
        };
        write_debug(
            runtime,
            "surface_action_selected",
            Some(session.session_id),
            json!({
                "policy_state": blocked_decision.policy_state,
                "policy_routing_decision": blocked_decision.routing_decision,
                "policy_reason": blocked_decision.reason.as_str(),
                "controller_surface_action": debug_surface_action(&controller_surface_action),
                "candidate_surface_action": debug_surface_action(&candidate_surface_action),
                "surface_action": debug_surface_action(&blocked_surface_action),
                "surface_requested_intervention": true,
                "trusted_ingress_softened_surface": false,
                "trusted_ingress_softening_reason": Value::Null,
                "trusted_bait_soften_path_prefixes": &runtime.trusted_bait_soften_path_prefixes,
                "trusted_ingress_local_soften_path_prefixes":
                    &session.trusted_bait_soften_path_prefixes,
            }),
        )?;
        return write_direct_response(DirectResponseContext {
            client_stream,
            runtime,
            session: &session,
            request: &request,
            path: &path,
            decision: &blocked_decision,
            discovery_recon_score,
            discovery_recon_threshold,
            response: blocked_response,
            intervention_mode,
            surface_requested_intervention: true,
        });
    }

    if intervention_mode.interventions_enabled()
        && (matches!(&surface_action, SurfaceAction::ProtectedUpstream)
            || (decision.policy_state == PolicyState::RateLimited
                && matches!(&surface_action, SurfaceAction::RateLimited { .. })))
    {
        if let Some(action_match) = runtime
            .bait_registry
            .match_action_for_session(
                &request.method,
                &surface_request.path,
                header_pairs(&request.headers),
                session.session_id,
                runtime.bait_signing_secret.as_deref(),
            )
            .map_err(|error| invalid_data(error.to_string()))?
        {
            effective_decision = policy::PolicyDecision::new(
                decision.policy_state,
                RoutingDecision::EidolonOwned,
                "bait-derived decoy action intercepted before protected upstream",
            );
            write_event(
                &runtime.event_log,
                &request_seen_event(
                    &request,
                    &path,
                    &session,
                    &effective_decision,
                    discovery_recon_score,
                    discovery_recon_threshold,
                ),
            )?;
            let action_exposure_id = write_bait_action_observed_event(
                runtime,
                &session,
                decision.policy_state,
                &action_match.bait,
                &request.method,
                &surface_request.path,
            )?;
            write_debug(
                runtime,
                "bait_action_match",
                Some(session.session_id),
                json!({
                    "bait_id": &action_match.bait.id,
                    "method": request.method.as_str(),
                    "path": debug_path(&surface_request.path),
                    "query_present": surface_request.query.is_some(),
                    "matched_prior_exposure": action_exposure_id.is_some(),
                    "exposure_id": &action_exposure_id,
                }),
            )?;

            let mut response = if let Some(transition) =
                policy::transition_after_correlated_bait_action(decision.policy_state)
                    .filter(|_| action_exposure_id.is_some())
            {
                write_debug(
                    runtime,
                    "policy_transition_selected",
                    Some(session.session_id),
                    json!({
                        "from": transition.from,
                        "to": transition.to,
                        "reason": transition.reason.as_str(),
                    }),
                )?;
                set_policy_state_for_session(runtime, session.session_id, transition.to)?;
                write_event(
                    &runtime.event_log,
                    &policy::policy_changed_event(session.session_id, &transition),
                )?;
                let (action, controlled_transition) = controlled_reality_action(
                    runtime,
                    session.session_id,
                    &surface_request,
                    transition.reason.clone(),
                )?;
                effective_decision = if let Some(controlled_transition) = controlled_transition {
                    write_debug(
                        runtime,
                        "policy_transition_selected",
                        Some(session.session_id),
                        json!({
                            "from": controlled_transition.from,
                            "to": controlled_transition.to,
                            "reason": controlled_transition.reason.as_str(),
                        }),
                    )?;
                    set_policy_state_for_session(
                        runtime,
                        session.session_id,
                        controlled_transition.to,
                    )?;
                    write_event(
                        &runtime.event_log,
                        &policy::policy_changed_event(session.session_id, &controlled_transition),
                    )?;
                    policy::PolicyDecision::new(
                        controlled_transition.to,
                        action.routing_decision(),
                        controlled_transition.reason.clone(),
                    )
                } else {
                    direct_surface_decision(transition.to, &action, transition.reason)
                };
                write_event(
                    &runtime.event_log,
                    &policy::policy_intervention_event(session.session_id, &effective_decision),
                )?;
                direct_surface_response(action)
                    .expect("controlled reality action should produce direct response")
            } else {
                write_event(
                    &runtime.event_log,
                    &policy::policy_intervention_event(session.session_id, &effective_decision),
                )?;
                bait_action_synthetic_response()
            };
            apply_response_headers(&mut response, &session);
            write_event(
                &runtime.event_log,
                &policy::response_audit_event(
                    session.session_id,
                    &effective_decision,
                    response.status,
                ),
            )?;
            write_debug(
                runtime,
                "response_served",
                Some(session.session_id),
                json!({
                    "route": "bait_action_direct",
                    "decision": {
                        "policy_state": effective_decision.policy_state,
                        "routing_decision": effective_decision.routing_decision,
                        "reason": effective_decision.reason.as_str(),
                    },
                    "response": debug_response_fields(&response),
                }),
            )?;

            client_stream.write_all(&response.to_http_bytes())?;
            return client_stream.flush();
        }
    }

    if intervention_mode.interventions_enabled()
        && matches!(&surface_action, SurfaceAction::ProtectedUpstream)
    {
        if let Some(action_shape_match) = runtime.bait_registry.match_action_shape(
            &request.method,
            &surface_request.path,
            header_pairs(&request.headers),
        ) {
            let prior_same_bait_exposure = write_bait_action_near_miss_event(
                runtime,
                &session,
                decision.policy_state,
                &action_shape_match.bait,
                &request.method,
                &surface_request.path,
            )?;
            write_debug(
                runtime,
                "bait_action_near_miss",
                Some(session.session_id),
                json!({
                    "bait_id": &action_shape_match.bait.id,
                    "method": request.method.as_str(),
                    "path": debug_path(&surface_request.path),
                    "query_present": surface_request.query.is_some(),
                    "prior_same_bait_exposure": prior_same_bait_exposure,
                }),
            )?;

            if let Some(transition) = policy::transition_to_rate_limited_from_same_bait_near_miss(
                decision.policy_state,
                &surface_request.path,
                &action_shape_match.bait.id,
                prior_same_bait_exposure,
            ) {
                write_debug(
                    runtime,
                    "policy_transition_selected",
                    Some(session.session_id),
                    json!({
                        "from": transition.from,
                        "to": transition.to,
                        "reason": transition.reason.as_str(),
                    }),
                )?;
                set_policy_state_for_session(runtime, session.session_id, transition.to)?;
                write_event(
                    &runtime.event_log,
                    &policy::policy_changed_event(session.session_id, &transition),
                )?;
                let response =
                    rate_limited_response(runtime.controlled_reality_config.retry_after_seconds);
                let action = SurfaceAction::RateLimited {
                    reason: transition.reason.clone(),
                    response: response.clone(),
                };
                effective_decision =
                    direct_surface_decision(transition.to, &action, transition.reason);
                return write_direct_response(DirectResponseContext {
                    client_stream,
                    runtime,
                    session: &session,
                    request: &request,
                    path: &path,
                    decision: &effective_decision,
                    discovery_recon_score,
                    discovery_recon_threshold,
                    response,
                    intervention_mode,
                    surface_requested_intervention: true,
                });
            }
        }
    }

    if intervention_mode.interventions_enabled()
        && decision.policy_state == PolicyState::RateLimited
        && matches!(&surface_action, SurfaceAction::RateLimited { .. })
        && runtime
            .bait_registry
            .match_action_for_session(
                &request.method,
                &surface_request.path,
                header_pairs(&request.headers),
                session.session_id,
                runtime.bait_signing_secret.as_deref(),
            )
            .map_err(|error| invalid_data(error.to_string()))?
            .is_none()
    {
        if let Some(action_shape_match) = runtime.bait_registry.match_action_shape(
            &request.method,
            &surface_request.path,
            header_pairs(&request.headers),
        ) {
            let prior_same_bait_exposure = write_bait_action_near_miss_event(
                runtime,
                &session,
                decision.policy_state,
                &action_shape_match.bait,
                &request.method,
                &surface_request.path,
            )?;
            write_debug(
                runtime,
                "bait_action_near_miss",
                Some(session.session_id),
                json!({
                    "bait_id": &action_shape_match.bait.id,
                    "method": request.method.as_str(),
                    "path": debug_path(&surface_request.path),
                    "query_present": surface_request.query.is_some(),
                    "prior_same_bait_exposure": prior_same_bait_exposure,
                }),
            )?;

            if let Some(transition) =
                policy::transition_to_blocked_from_repeated_same_bait_near_miss(
                    decision.policy_state,
                    &surface_request.path,
                    &action_shape_match.bait.id,
                    prior_same_bait_exposure,
                )
            {
                write_debug(
                    runtime,
                    "policy_transition_selected",
                    Some(session.session_id),
                    json!({
                        "from": transition.from,
                        "to": transition.to,
                        "reason": transition.reason.as_str(),
                    }),
                )?;
                set_policy_state_for_session(runtime, session.session_id, transition.to)?;
                write_event(
                    &runtime.event_log,
                    &policy::policy_changed_event(session.session_id, &transition),
                )?;
                effective_decision = policy::PolicyDecision::new(
                    transition.to,
                    RoutingDecision::EidolonOwned,
                    transition.reason.clone(),
                );
                return write_direct_response(DirectResponseContext {
                    client_stream,
                    runtime,
                    session: &session,
                    request: &request,
                    path: &path,
                    decision: &effective_decision,
                    discovery_recon_score,
                    discovery_recon_threshold,
                    response: surface_text_response(403, "blocked by eidolon policy\n"),
                    intervention_mode,
                    surface_requested_intervention: true,
                });
            }
        }
    }

    if let Some(mut response) = direct_surface_response(surface_action.clone()) {
        effective_decision = direct_surface_decision(
            decision.policy_state,
            &surface_action,
            decision.reason.clone(),
        );
        write_request_and_policy_events(
            runtime,
            &request_seen_event(
                &request,
                &path,
                &session,
                &effective_decision,
                discovery_recon_score,
                discovery_recon_threshold,
            ),
            &effective_decision,
            intervention_mode,
            surface_requested_intervention,
        )?;
        apply_response_headers(&mut response, &session);
        if let Some(bait) = bait_exposure_for_direct_surface(
            &decision,
            &surface_action,
            &surface_request,
            &runtime.bait_registry,
        ) {
            write_bait_exposed_event(
                runtime,
                &session,
                decision.policy_state,
                bait,
                surface_request.path.clone(),
            )?;
        }
        write_event(
            &runtime.event_log,
            &policy::response_audit_event(session.session_id, &effective_decision, response.status),
        )?;
        write_debug(
            runtime,
            "response_served",
            Some(session.session_id),
            json!({
                "route": "direct_surface",
                "decision": {
                    "policy_state": effective_decision.policy_state,
                    "routing_decision": effective_decision.routing_decision,
                    "reason": effective_decision.reason.as_str(),
                },
                "response": debug_response_fields(&response),
            }),
        )?;

        client_stream.write_all(&response.to_http_bytes())?;
        return client_stream.flush();
    }

    let upstream_request_decision = upstream_request_decision(
        decision.policy_state,
        &surface_action,
        effective_decision.reason.clone(),
    );
    write_event(
        &runtime.event_log,
        &request_seen_event(
            &request,
            &path,
            &session,
            &upstream_request_decision,
            discovery_recon_score,
            discovery_recon_threshold,
        ),
    )?;
    if intervention_mode == InterventionMode::Disabled {
        write_event(
            &runtime.event_log,
            &policy::policy_intervention_event(session.session_id, &upstream_request_decision),
        )?;
    }

    let upstream_request = request.to_upstream_bytes(&runtime.upstream)?;
    write_debug(
        runtime,
        "upstream_request_forwarding",
        Some(session.session_id),
        json!({
            "method": request.method.as_str(),
            "path": debug_path(&path),
            "query_present": debug_query_present(&path),
            "connect_addr": runtime.upstream.connect_addr.as_str(),
            "request_bytes": upstream_request.len(),
        }),
    )?;
    let mut upstream_stream = connect_upstream(&runtime.upstream)?;
    upstream_stream.write_all(&upstream_request)?;
    upstream_stream.flush()?;

    let mut response = read_http_response(&mut upstream_stream)?;
    write_debug(
        runtime,
        "upstream_response_received",
        Some(session.session_id),
        json!({
            "status": response.status,
            "body_len": response.body.len(),
            "header_count": response.headers.len(),
            "surface_requested_intervention": surface_requested_intervention,
        }),
    )?;
    let mut pending_bait_exposure = None;
    if let SurfaceAction::RewrittenUpstream { plan } = surface_action {
        let meta = surface_response_meta(&response, &path);
        if is_success_status(response.status) {
            let outcome = rewrite_response_body(&meta, &response.body, &plan);
            write_debug(
                runtime,
                "surface_rewrite_evaluated",
                Some(session.session_id),
                json!({
                    "plan": debug_rewrite_plan(&plan),
                    "disposition": debug_rewrite_disposition(outcome.disposition()),
                    "refusal": outcome.refusal().map(ToString::to_string),
                    "original_body_len": response.body.len(),
                    "output_body_len": outcome.body().len(),
                    "surface_path": debug_path(&path),
                    "query_present": debug_query_present(&path),
                }),
            )?;
            if outcome.is_rewritten() {
                effective_decision = policy::PolicyDecision::new(
                    decision.policy_state,
                    RoutingDecision::RewrittenUpstream,
                    "surface controller rewrote upstream response",
                );
                if let Some(bait) = runtime.bait_registry.bait_for_class(BaitClass::OpenApi) {
                    if is_openapi_discovery_request(&surface_request, bait) {
                        pending_bait_exposure =
                            Some((bait.clone(), surface_request.target.clone()));
                    }
                }
            } else if let Some(refusal) = outcome.refusal() {
                effective_decision = policy::PolicyDecision::new(
                    decision.policy_state,
                    RoutingDecision::ProtectedUpstream,
                    format!("surface controller rewrite refused; forwarded original upstream response: {refusal}"),
                );
            } else {
                effective_decision = policy::PolicyDecision::new(
                    decision.policy_state,
                    RoutingDecision::ProtectedUpstream,
                    "surface controller rewrite made no changes; forwarded original upstream response",
                );
            }
            response.body = outcome.into_body();
        } else {
            write_debug(
                runtime,
                "surface_rewrite_skipped",
                Some(session.session_id),
                json!({
                    "reason": "non_success_upstream_response",
                    "status": response.status,
                    "plan": debug_rewrite_plan(&plan),
                }),
            )?;
            effective_decision = policy::PolicyDecision::new(
                decision.policy_state,
                RoutingDecision::ProtectedUpstream,
                "surface controller skipped rewrite for non-success upstream response",
            );
        }
    }
    apply_response_headers(&mut response, &session);

    if surface_requested_intervention {
        write_event(
            &runtime.event_log,
            &policy::policy_intervention_event(session.session_id, &effective_decision),
        )?;
    }
    if let Some((bait, surface)) = pending_bait_exposure {
        write_bait_exposed_event(runtime, &session, decision.policy_state, &bait, surface)?;
    }
    write_event(
        &runtime.event_log,
        &policy::response_audit_event(session.session_id, &effective_decision, response.status),
    )?;
    write_debug(
        runtime,
        "response_served",
        Some(session.session_id),
        json!({
            "route": "upstream",
            "decision": {
                "policy_state": effective_decision.policy_state,
                "routing_decision": effective_decision.routing_decision,
                "reason": effective_decision.reason.as_str(),
            },
            "response": debug_response_fields(&response),
        }),
    )?;

    client_stream.write_all(&response.to_http_bytes())?;
    client_stream.flush()
}

fn maybe_transition_to_blocked_from_reality_escape_attempt(
    runtime: &ProxyRuntime,
    session: &SessionContext,
    request: &HttpRequest,
    surface_request: &SurfaceRequestMeta,
    decision: &policy::PolicyDecision,
) -> io::Result<Option<policy::PolicyTransition>> {
    if decision.policy_state != PolicyState::ControlledReality {
        return Ok(None);
    }
    if runtime
        .controlled_reality
        .is_controlled_branch(surface_request)
    {
        clear_reality_escape_attempts_for_session(runtime, session.session_id)?;
        return Ok(None);
    }
    if decision.policy_state != PolicyState::ControlledReality
        || !matches!(
            decision.routing_decision,
            RoutingDecision::ControlledReality | RoutingDecision::RateLimited
        )
    {
        return Ok(None);
    }
    let attempt_count = note_reality_escape_attempt_for_session(runtime, session.session_id)?;

    write_debug(
        runtime,
        "reality_escape_attempt",
        Some(session.session_id),
        json!({
            "method": request.method.as_str(),
            "path": debug_path(&surface_request.path),
            "query_present": surface_request.query.is_some(),
            "policy_state": decision.policy_state,
            "routing_decision": decision.routing_decision,
            "attempt_count": attempt_count,
        }),
    )?;

    write_event(
        &runtime.event_log,
        &policy::reality_escape_attempt_event(
            session.session_id,
            decision.policy_state,
            request.method.clone(),
            redacted_event_target(&surface_request.path),
            decision.routing_decision,
            "controlled session requested a path outside the configured controlled-reality branch",
        ),
    )?;

    Ok(
        policy::transition_to_blocked_from_repeated_reality_escape_attempt(
            decision.policy_state,
            &surface_request.path,
            attempt_count,
        ),
    )
}

struct DirectResponseContext<'a> {
    client_stream: TcpStream,
    runtime: &'a ProxyRuntime,
    session: &'a SessionContext,
    request: &'a HttpRequest,
    path: &'a str,
    decision: &'a policy::PolicyDecision,
    discovery_recon_score: policy::DiscoveryReconAggregationScore,
    discovery_recon_threshold: u8,
    response: SurfaceResponse,
    intervention_mode: InterventionMode,
    surface_requested_intervention: bool,
}

fn write_direct_response(context: DirectResponseContext<'_>) -> io::Result<()> {
    let DirectResponseContext {
        mut client_stream,
        runtime,
        session,
        request,
        path,
        decision,
        discovery_recon_score,
        discovery_recon_threshold,
        response,
        intervention_mode,
        surface_requested_intervention,
    } = context;

    write_request_and_policy_events(
        runtime,
        &request_seen_event(
            request,
            path,
            session,
            decision,
            discovery_recon_score,
            discovery_recon_threshold,
        ),
        decision,
        intervention_mode,
        surface_requested_intervention,
    )?;

    let mut response = surface_response_to_http(response);
    apply_response_headers(&mut response, session);
    write_event(
        &runtime.event_log,
        &policy::response_audit_event(session.session_id, decision, response.status),
    )?;
    write_debug(
        runtime,
        "response_served",
        Some(session.session_id),
        json!({
            "route": "direct_response",
            "decision": {
                "policy_state": decision.policy_state,
                "routing_decision": decision.routing_decision,
                "reason": decision.reason.as_str(),
            },
            "response": debug_response_fields(&response),
        }),
    )?;

    client_stream.write_all(&response.to_http_bytes())?;
    client_stream.flush()
}

fn policy_state_for_session(
    runtime: &ProxyRuntime,
    session_id: SessionId,
) -> io::Result<PolicyState> {
    let store = runtime
        .policy_store
        .lock()
        .map_err(|_| io::Error::other("policy state store lock poisoned"))?;

    Ok(store.policy_state(session_id))
}

fn set_policy_state_for_session(
    runtime: &ProxyRuntime,
    session_id: SessionId,
    policy_state: PolicyState,
) -> io::Result<()> {
    let mut store = runtime
        .policy_store
        .lock()
        .map_err(|_| io::Error::other("policy state store lock poisoned"))?;

    store.set_policy_state(session_id, policy_state)
}

fn note_reality_escape_attempt_for_session(
    runtime: &ProxyRuntime,
    session_id: SessionId,
) -> io::Result<u32> {
    let mut store = runtime
        .policy_store
        .lock()
        .map_err(|_| io::Error::other("policy state store lock poisoned"))?;

    store.note_reality_escape_attempt(session_id)
}

fn clear_reality_escape_attempts_for_session(
    runtime: &ProxyRuntime,
    session_id: SessionId,
) -> io::Result<()> {
    let mut store = runtime
        .policy_store
        .lock()
        .map_err(|_| io::Error::other("policy state store lock poisoned"))?;

    store.clear_reality_escape_attempts(session_id)
}

fn update_discovery_recon_state_for_request(
    runtime: &ProxyRuntime,
    session_id: SessionId,
    request: &SurfaceRequestMeta,
) -> io::Result<policy::DiscoveryReconState> {
    let mut store = runtime
        .policy_store
        .lock()
        .map_err(|_| io::Error::other("policy state store lock poisoned"))?;

    if let Some(kind) = discovery_surface_kind(runtime, request) {
        return store.note_discovery_surface_request(
            session_id,
            kind,
            request.query.is_some(),
            is_legacy_openapi_discovery_query(request),
        );
    }

    if let Some(kind) = linked_bait_surface_kind(runtime, request) {
        return store.note_linked_bait_surface_request(session_id, kind);
    }

    if let Some(kind) = blind_decoy_write_probe_path_kind(runtime, session_id, request) {
        return store.note_decoy_write_probe(session_id, kind);
    }

    let record = store.record(session_id);
    Ok(policy::DiscoveryReconState {
        fanout: record.discovery_surface_fanout,
        request_count: record.discovery_request_count,
        query_seen: record.discovery_query_seen,
        legacy_openapi_query_seen: record.discovery_legacy_openapi_query_seen,
        linked_bait_surface_seen: record.discovery_linked_bait_surface_fanout.any_seen(),
        linked_bait_surface_classes: record
            .discovery_linked_bait_surface_fanout
            .distinct_surface_count(),
        decoy_write_probe_seen: record.discovery_decoy_write_probe_count > 0,
        decoy_write_probe_count: record.discovery_decoy_write_probe_count,
        decoy_write_probe_path_classes: record
            .discovery_decoy_write_probe_fanout
            .distinct_path_count(),
    })
}

fn controlled_reality_action(
    runtime: &ProxyRuntime,
    session_id: SessionId,
    request: &SurfaceRequestMeta,
    default_reason: String,
) -> io::Result<(SurfaceAction, Option<policy::PolicyTransition>)> {
    let depth = {
        let mut store = runtime
            .policy_store
            .lock()
            .map_err(|_| io::Error::other("policy state store lock poisoned"))?;
        store.increment_controlled_reality_depth(session_id)?
    };

    let depth_limit = runtime.controlled_reality_config.max_action_depth;
    if depth > depth_limit {
        let tarpit_delay = runtime.controlled_reality_config.tarpit_delay;
        if !tarpit_delay.is_zero() {
            thread::sleep(tarpit_delay);
        }
        let transition = policy::transition_to_blocked_from_repeated_controlled_reality_depth_limit(
            PolicyState::ControlledReality,
            &request.path,
            depth,
            depth_limit,
        );
        let action = if transition.is_some() {
            SurfaceAction::EidolonOwned {
                response: surface_text_response(403, "blocked by eidolon policy\n"),
            }
        } else {
            SurfaceAction::RateLimited {
                reason: format!(
                    "controlled reality action depth {depth} exceeded limit {depth_limit}; tarpit delay {}ms",
                    tarpit_delay.as_millis()
                ),
                response: rate_limited_response(
                    runtime.controlled_reality_config.retry_after_seconds,
                ),
            }
        };
        write_debug(
            runtime,
            "controlled_reality_action_selected",
            Some(session_id),
            json!({
                "depth": depth,
                "depth_limit": depth_limit,
                "tarpit_ms": tarpit_delay.as_millis(),
                "transition": transition.as_ref().map(|selected| json!({
                    "from": selected.from,
                    "to": selected.to,
                    "reason": selected.reason.as_str(),
                })),
                "action": debug_surface_action(&action),
            }),
        )?;
        return Ok((action, transition));
    }

    let mut action = runtime.controlled_reality.decide(request, depth);
    if let SurfaceAction::ControlledReality { reason, .. } = &mut action {
        if depth == 1 {
            *reason = default_reason;
        }
    }
    write_debug(
        runtime,
        "controlled_reality_action_selected",
        Some(session_id),
        json!({
            "depth": depth,
            "depth_limit": depth_limit,
            "action": debug_surface_action(&action),
        }),
    )?;

    Ok((action, None))
}

fn bait_exposure_for_direct_surface<'a>(
    policy_decision: &policy::PolicyDecision,
    surface_action: &SurfaceAction,
    surface_request: &SurfaceRequestMeta,
    bait_registry: &'a BaitRegistry,
) -> Option<&'a Bait> {
    if policy_decision.routing_decision != RoutingDecision::ProtectedUpstream
        || !matches!(surface_action, SurfaceAction::EidolonOwned { .. })
        || surface_request.method != "GET"
    {
        return None;
    }

    bait_registry
        .bait_for_surface(&surface_request.path)
        .or_else(|| {
            (policy_decision.policy_state == PolicyState::Suspicious
                && surface_request.path == DOCS_DISCOVERY_TARGET)
                .then(|| bait_registry.bait_for_class(BaitClass::Docs))
                .flatten()
        })
}

fn strengthen_surface_action_for_suspicious_discovery(
    runtime: &ProxyRuntime,
    session_id: SessionId,
    policy_state: PolicyState,
    surface_request: &SurfaceRequestMeta,
    controller_surface_action: SurfaceAction,
) -> io::Result<SurfaceAction> {
    if policy_state != PolicyState::Suspicious
        || surface_request.method != "GET"
        || !matches!(
            &controller_surface_action,
            SurfaceAction::RewrittenUpstream { .. }
        )
    {
        return Ok(controller_surface_action);
    }

    if surface_request.path == DOCS_DISCOVERY_TARGET {
        let Some(bait) = runtime.bait_registry.bait_for_class(BaitClass::Docs) else {
            return Ok(controller_surface_action);
        };
        let bait =
            render_bait_for_session(bait, session_id, runtime.bait_signing_secret.as_deref())
                .map_err(|error| invalid_data(error.to_string()))?;

        return Ok(SurfaceAction::EidolonOwned {
            response: bait_surface_response(&bait, &runtime.bait_content),
        });
    }

    let Some(bait) = runtime.bait_registry.bait_for_class(BaitClass::OpenApi) else {
        return Ok(controller_surface_action);
    };
    if surface_request.path != OPENAPI_DISCOVERY_TARGET
        || !is_openapi_discovery_request(surface_request, bait)
    {
        return Ok(controller_surface_action);
    }
    let bait = render_bait_for_session(bait, session_id, runtime.bait_signing_secret.as_deref())
        .map_err(|error| invalid_data(error.to_string()))?;

    Ok(SurfaceAction::EidolonOwned {
        response: owned_openapi_discovery_response(&bait, &runtime.bait_content.openapi),
    })
}

fn upstream_request_decision(
    policy_state: PolicyState,
    surface_action: &SurfaceAction,
    default_reason: String,
) -> policy::PolicyDecision {
    match surface_action {
        SurfaceAction::RewrittenUpstream { .. } => policy::PolicyDecision::new(
            policy_state,
            RoutingDecision::ProtectedUpstream,
            "surface controller requested upstream response rewrite; request forwarded to protected upstream before rewrite outcome",
        ),
        _ => policy::PolicyDecision::protected_upstream(policy_state, default_reason),
    }
}

fn write_bait_exposed_event(
    runtime: &ProxyRuntime,
    session: &SessionContext,
    policy_state: PolicyState,
    bait: &Bait,
    surface: impl Into<String>,
) -> io::Result<ExposureId> {
    let exposure_id = ExposureId(format!("exp-{}", SessionId::new().0));
    let surface = surface.into();
    let mut exposures = runtime
        .bait_exposures
        .lock()
        .map_err(|_| io::Error::other("bait exposure store lock poisoned"))?;

    write_event(
        &runtime.event_log,
        &Event::new(
            session.session_id,
            EventSource::SurfaceController,
            policy_state,
            EventKind::BaitExposed {
                bait_id: bait.id.clone(),
                exposure_id: exposure_id.clone(),
                surface: redacted_event_target(&surface),
                header_value_mint: bait.header_value_mint_audit(),
            },
        ),
    )?;

    exposures.record_exposure(session.session_id, bait.id.clone(), exposure_id.clone());
    write_debug(
        runtime,
        "bait_exposed",
        Some(session.session_id),
        json!({
            "bait_id": &bait.id,
            "bait_class": bait.bait_class,
            "surface": debug_path(&bait.surface),
            "requested_surface": debug_path(&surface),
            "exposure_id": &exposure_id,
            "stored_exposure_count": exposures.exposures.len(),
        }),
    )?;
    Ok(exposure_id)
}

fn bait_action_exposure_id(
    runtime: &ProxyRuntime,
    session: &SessionContext,
    bait_id: &BaitId,
) -> io::Result<Option<ExposureId>> {
    let exposures = runtime
        .bait_exposures
        .lock()
        .map_err(|_| io::Error::other("bait exposure store lock poisoned"))?;

    Ok(exposures.exposure_for_action(session.session_id, bait_id))
}

struct BaitActionObservation<'a> {
    bait: &'a Bait,
    method: &'a str,
    path: &'a str,
    exposure_id: Option<ExposureId>,
    prior_same_bait_exposure: bool,
    header_value_mint_status: Option<BaitHeaderValueMintStatus>,
}

fn write_bait_action_observed_event_with_exposure(
    runtime: &ProxyRuntime,
    session: &SessionContext,
    policy_state: PolicyState,
    observation: BaitActionObservation<'_>,
) -> io::Result<()> {
    let BaitActionObservation {
        bait,
        method,
        path,
        exposure_id,
        prior_same_bait_exposure,
        header_value_mint_status,
    } = observation;
    let matched_prior_exposure = exposure_id.is_some();
    write_event(
        &runtime.event_log,
        &Event::new(
            session.session_id,
            EventSource::BaitEngine,
            policy_state,
            EventKind::BaitActionObserved {
                bait_id: bait.id.clone(),
                exposure_id: exposure_id.clone(),
                method: method.to_string(),
                path: redacted_event_target(path),
                header_value_mint: bait.header_value_mint_audit(),
                header_value_mint_status,
            },
        ),
    )?;

    write_debug(
        runtime,
        "bait_action_observed",
        Some(session.session_id),
        json!({
            "bait_id": &bait.id,
            "method": method,
            "path": debug_path(path),
            "query_present": debug_query_present(path),
            "matched_prior_exposure": matched_prior_exposure,
            "prior_same_bait_exposure": prior_same_bait_exposure,
            "exposure_id": &exposure_id,
        }),
    )
}

fn write_bait_action_observed_event(
    runtime: &ProxyRuntime,
    session: &SessionContext,
    policy_state: PolicyState,
    bait: &Bait,
    method: &str,
    path: &str,
) -> io::Result<Option<ExposureId>> {
    let exposure_id = bait_action_exposure_id(runtime, session, &bait.id)?;
    write_bait_action_observed_event_with_exposure(
        runtime,
        session,
        policy_state,
        BaitActionObservation {
            bait,
            method,
            path,
            exposure_id: exposure_id.clone(),
            prior_same_bait_exposure: exposure_id.is_some(),
            header_value_mint_status: bait
                .header_value_mint_audit()
                .map(|_| BaitHeaderValueMintStatus::MatchedSessionValue),
        },
    )?;

    Ok(exposure_id)
}

fn write_bait_action_near_miss_event(
    runtime: &ProxyRuntime,
    session: &SessionContext,
    policy_state: PolicyState,
    bait: &Bait,
    method: &str,
    path: &str,
) -> io::Result<bool> {
    let prior_same_bait_exposure = bait_action_exposure_id(runtime, session, &bait.id)?.is_some();
    write_bait_action_observed_event_with_exposure(
        runtime,
        session,
        policy_state,
        BaitActionObservation {
            bait,
            method,
            path,
            exposure_id: None,
            prior_same_bait_exposure,
            header_value_mint_status: bait
                .header_value_mint_audit()
                .map(|_| BaitHeaderValueMintStatus::SessionValueMismatch),
        },
    )?;

    Ok(prior_same_bait_exposure)
}

fn bait_action_synthetic_response() -> HttpResponse {
    surface_response_to_http(surface_text_response(202, "accepted\n"))
}

fn surface_header_pairs(headers: &[SurfaceHeader]) -> impl Iterator<Item = (&str, &str)> {
    headers
        .iter()
        .map(|header| (header.name.as_str(), header.value.as_str()))
}

fn header_pairs(headers: &[HttpHeader]) -> impl Iterator<Item = (&str, &str)> {
    headers
        .iter()
        .map(|header| (header.name.as_str(), header.value.as_str()))
}

fn surface_request_meta(request: &HttpRequest, path: &str) -> SurfaceRequestMeta {
    SurfaceRequestMeta::new(
        request.method.clone(),
        path.to_string(),
        surface_headers(&request.headers),
        request.body.len(),
    )
}

fn surface_response_meta(response: &HttpResponse, path: &str) -> SurfaceResponseMeta {
    SurfaceResponseMeta::for_surface(
        response.status,
        path.to_string(),
        surface_headers(&response.headers),
        response.body.len(),
    )
}

fn surface_headers(headers: &[HttpHeader]) -> Vec<SurfaceHeader> {
    headers
        .iter()
        .map(|header| SurfaceHeader::new(header.name.clone(), header.value.clone()))
        .collect()
}

fn direct_surface_response(action: SurfaceAction) -> Option<HttpResponse> {
    match action {
        SurfaceAction::EidolonOwned { response }
        | SurfaceAction::ControlledReality { response, .. }
        | SurfaceAction::RateLimited { response, .. } => Some(surface_response_to_http(response)),
        SurfaceAction::ProtectedUpstream | SurfaceAction::RewrittenUpstream { .. } => None,
    }
}

fn direct_surface_decision(
    policy_state: PolicyState,
    action: &SurfaceAction,
    default_reason: String,
) -> policy::PolicyDecision {
    match action {
        SurfaceAction::ProtectedUpstream => {
            policy::PolicyDecision::protected_upstream(policy_state, default_reason)
        }
        SurfaceAction::EidolonOwned { .. } => {
            let reason = if policy_state == PolicyState::Blocked {
                default_reason
            } else {
                "surface controller served eidolon-owned response".to_string()
            };
            policy::PolicyDecision::new(policy_state, RoutingDecision::EidolonOwned, reason)
        }
        SurfaceAction::ControlledReality { reason, .. } => policy::PolicyDecision::new(
            policy_state,
            RoutingDecision::ControlledReality,
            reason.clone(),
        ),
        SurfaceAction::RateLimited { reason, .. } => {
            policy::PolicyDecision::new(policy_state, RoutingDecision::RateLimited, reason.clone())
        }
        SurfaceAction::RewrittenUpstream { .. } => policy::PolicyDecision::new(
            policy_state,
            RoutingDecision::RewrittenUpstream,
            "surface controller requested upstream response rewrite",
        ),
    }
}

fn surface_text_response(status: u16, body: impl Into<Vec<u8>>) -> SurfaceResponse {
    SurfaceResponse::new(
        status,
        vec![SurfaceHeader::new(
            "Content-Type",
            "text/plain; charset=utf-8",
        )],
        body,
    )
}

fn surface_response_to_http(response: SurfaceResponse) -> HttpResponse {
    HttpResponse {
        version: "HTTP/1.1".to_string(),
        status: response.status,
        reason: reason_phrase(response.status).to_string(),
        headers: response
            .headers
            .into_iter()
            .map(|header| HttpHeader {
                name: header.name,
                value: header.value,
            })
            .collect(),
        body: response.body,
    }
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        202 => "Accepted",
        203 => "Non-Authoritative Information",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "Unknown Status",
    }
}

fn normalized_event_path(request: &HttpRequest) -> io::Result<String> {
    Ok(normalize_request_target(&request.target)?.to_string())
}

fn event_discovery_recon_score(
    score: policy::DiscoveryReconAggregationScore,
    threshold: u8,
) -> DiscoveryReconScore {
    if score.total == 0 {
        return DiscoveryReconScore::default();
    }

    DiscoveryReconScore {
        repeated_discovery_score: score.repeated_discovery_score,
        query_score: score.query_score,
        legacy_openapi_query_score: score.legacy_openapi_query_score,
        linked_bait_surface_score: score.linked_bait_surface_score,
        linked_bait_class_fanout_bonus: score.linked_bait_class_fanout_bonus,
        decoy_write_probe_score: score.decoy_write_probe_score,
        decoy_write_probe_path_fanout_bonus: score.decoy_write_probe_path_fanout_bonus,
        detection_score: score.detection_score,
        total: score.total,
        threshold,
    }
}

fn request_seen_event(
    request: &HttpRequest,
    path: &str,
    session: &SessionContext,
    decision: &policy::PolicyDecision,
    discovery_recon_score: policy::DiscoveryReconAggregationScore,
    discovery_recon_threshold: u8,
) -> Event {
    Event::new(
        session.session_id,
        EventSource::Proxy,
        decision.policy_state,
        EventKind::RequestSeen {
            method: request.method.clone(),
            path: redacted_event_target(path),
            safe_headers: safe_header_observations(&request.headers),
            ingress_identity: session.ingress_identity.clone(),
            local_ingress_trust_scope_rejection: session
                .local_ingress_trust_scope_rejection
                .clone(),
            trusted_ingress_soften_match: session.trusted_ingress_soften_match.clone(),
            ingress_signals: session.ingress_signals.clone(),
            discovery_recon_score: event_discovery_recon_score(
                discovery_recon_score,
                discovery_recon_threshold,
            ),
            routing_decision: decision.routing_decision,
        },
    )
}

fn write_request_and_policy_events(
    runtime: &ProxyRuntime,
    request_event: &Event,
    decision: &policy::PolicyDecision,
    intervention_mode: InterventionMode,
    surface_requested_intervention: bool,
) -> io::Result<()> {
    write_event(&runtime.event_log, request_event)?;

    if intervention_mode == InterventionMode::Disabled
        || surface_requested_intervention
        || decision.routing_decision != RoutingDecision::ProtectedUpstream
    {
        write_event(
            &runtime.event_log,
            &policy::policy_intervention_event(request_event.session_id, decision),
        )?;
    }

    Ok(())
}

fn safe_header_observations(headers: &[HttpHeader]) -> Vec<SafeHeaderObservation> {
    SAFE_HEADER_NAMES
        .iter()
        .map(|name| SafeHeaderObservation {
            name: (*name).to_string(),
            present: headers
                .iter()
                .any(|header| header.name.eq_ignore_ascii_case(name)),
        })
        .collect()
}

fn apply_response_headers(response: &mut HttpResponse, session: &SessionContext) {
    let connection_nominated_headers: Vec<String> = response
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("connection"))
        .flat_map(|header| header.value.split(','))
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect();

    for name in connection_nominated_headers {
        response.remove_header(&name);
    }

    for name in [
        "Connection",
        "Keep-Alive",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "TE",
        "Trailer",
        "Transfer-Encoding",
        "Upgrade",
    ] {
        response.remove_header(name);
    }

    response.set_header("Connection", "close");
    response.set_header("Content-Length", response.body.len().to_string());

    if let Some(set_cookie) = session.set_cookie_value() {
        response.append_header(session::SET_COOKIE_HEADER_NAME, set_cookie);
    }
}

fn write_event(log: &Arc<Mutex<FileEventLogWriter>>, event: &Event) -> io::Result<()> {
    let mut log = log
        .lock()
        .map_err(|_| io::Error::other("event log lock poisoned"))?;
    log.write_event(event)
}

fn effective_session_context(
    runtime: &ProxyRuntime,
    request: &HttpRequest,
    surface_request: &SurfaceRequestMeta,
    client_peer_ip: Option<IpAddr>,
) -> SessionContext {
    let headers: Vec<(&str, &str)> = header_pairs(&request.headers).collect();
    let request_host = effective_request_host(request);
    let mut session = session::derive_session_from_headers(headers.iter().copied());
    session.ingress_identity = session::authenticated_ingress_identity_from_headers(
        headers.iter().copied(),
        runtime.ingress_transport_auth_secret.as_deref(),
    );
    session.ingress_signals = session::authenticated_ingress_advisory_signals_from_headers(
        headers.iter().copied(),
        runtime.ingress_transport_auth_secret.as_deref(),
    );
    let local_trust_evaluation = runtime.ingress_identity_resolver.evaluate(
        &request.method,
        &surface_request.path,
        request_host.as_deref(),
        client_peer_ip,
        headers.iter().copied(),
    );
    session.local_ingress_trust_scope_rejection = local_trust_evaluation.scope_rejection;
    let local_trust = local_trust_evaluation.resolved;
    let merged_identity = ingress_identity::merge_ingress_identity(
        session.ingress_identity.clone(),
        local_trust.as_ref().map(|trust| trust.identity.clone()),
    );
    session.trusted_ingress_soften_match = local_trust.as_ref().and_then(|trust| {
        if merged_identity != trust.identity {
            return None;
        }

        let bait_soften_path_prefixes = trust.bait_soften_path_prefixes.clone()?;
        Some(eidolon_core::TrustedIngressSoftenMatch {
            label: trust.identity.label.clone(),
            source: trust.identity.source,
            trust_tier: trust.identity.trust_tier,
            methods: trust.methods.clone(),
            path_prefixes: trust.path_prefixes.clone(),
            request_path_softened: bait_soften_path_prefixes
                .iter()
                .any(|prefix| surface_request.path.starts_with(prefix)),
            bait_soften_path_prefixes,
            user_agent_substrings: trust.user_agent_substrings.clone().unwrap_or_default(),
            hosts: trust.hosts.clone().unwrap_or_default(),
            source_cidrs: trust.source_cidrs.clone().unwrap_or_default(),
            required_header_names: trust.required_header_names.clone(),
        })
    });
    session.trusted_bait_soften_path_prefixes = session
        .trusted_ingress_soften_match
        .as_ref()
        .map(|scope| scope.bait_soften_path_prefixes.clone());
    session.ingress_identity = merged_identity;

    session
}

fn maybe_soften_surface_action_for_trusted_ingress(
    trusted_bait_soften_path_prefixes: &[String],
    session: &SessionContext,
    policy_state: PolicyState,
    surface_request: &SurfaceRequestMeta,
    surface_action: SurfaceAction,
) -> (SurfaceAction, Option<String>) {
    if !matches!(policy_state, PolicyState::Normal | PolicyState::Observe) {
        return (surface_action, None);
    }
    if surface_request.method != "GET" {
        return (surface_action, None);
    }
    if !ingress_identity::softens_bait_surface_exposure(&session.ingress_identity) {
        return (surface_action, None);
    }
    if !trusted_bait_soften_path_prefixes
        .iter()
        .any(|prefix| surface_request.path.starts_with(prefix))
    {
        return (surface_action, None);
    }
    if let Some(local_soften_path_prefixes) = &session.trusted_bait_soften_path_prefixes {
        if !local_soften_path_prefixes
            .iter()
            .any(|prefix| surface_request.path.starts_with(prefix))
        {
            return (surface_action, None);
        }
    }
    if !matches!(
        &surface_action,
        SurfaceAction::EidolonOwned { .. } | SurfaceAction::RewrittenUpstream { .. }
    ) {
        return (surface_action, None);
    }

    (
        SurfaceAction::ProtectedUpstream,
        Some(
            "trusted ingress identity suppressed bait surface intervention before runtime suspicion was established"
                .to_string(),
        ),
    )
}

fn write_debug(
    runtime: &ProxyRuntime,
    event: &str,
    session_id: Option<SessionId>,
    fields: Value,
) -> io::Result<()> {
    let Some(log) = &runtime.debug_log else {
        return Ok(());
    };

    let observed_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default();
    let record = json!({
        "schema_version": 1,
        "run_kind": "eidolon_proxy_debug",
        "observed_at_unix_ms": observed_at_unix_ms,
        "event": event,
        "session_id": session_id,
        "fields": fields,
    });

    let mut log = log
        .lock()
        .map_err(|_| io::Error::other("debug log lock poisoned"))?;
    log.write_record(&record)
}

fn debug_path(target: &str) -> String {
    let query_index = target.find('?');
    let fragment_index = target.find('#');
    let end = match (query_index, fragment_index) {
        (Some(query), Some(fragment)) => query.min(fragment),
        (Some(query), None) => query,
        (None, Some(fragment)) => fragment,
        (None, None) => target.len(),
    };

    target[..end].to_string()
}

fn redacted_event_target(target: &str) -> String {
    let (target_without_fragment, fragment_present) = target
        .split_once('#')
        .map_or((target, false), |(target, _)| (target, true));
    let (path, query) = target_without_fragment
        .split_once('?')
        .map_or((target_without_fragment, None), |(path, query)| {
            (path, Some(query))
        });

    let mut redacted = path.to_string();
    if let Some(query) = query {
        redacted.push('?');
        redacted.push_str(&redacted_event_query(query));
    }
    if fragment_present {
        redacted.push_str("#<redacted>");
    }

    redacted
}

fn redacted_event_query(query: &str) -> String {
    let redacted_pairs: Vec<String> = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let key = pair.split_once('=').map_or(pair, |(key, _)| key);
            if key.is_empty() {
                "<redacted>".to_string()
            } else {
                format!("{key}=<redacted>")
            }
        })
        .collect();

    if redacted_pairs.is_empty() {
        "<redacted>".to_string()
    } else {
        redacted_pairs.join("&")
    }
}

fn debug_query_present(target: &str) -> bool {
    target.contains('?')
}

fn debug_target_form(target: &str) -> &'static str {
    if target.starts_with('/') {
        "origin_form"
    } else if target.starts_with("http://") {
        "absolute_http_form"
    } else if target == "*" {
        "asterisk_form"
    } else {
        "unknown"
    }
}

fn debug_session_source(source: session::SessionSource) -> &'static str {
    match source {
        session::SessionSource::Cookie => "cookie",
        session::SessionSource::Generated => "generated",
    }
}

fn debug_intervention_mode(mode: InterventionMode) -> &'static str {
    match mode {
        InterventionMode::Enabled => "enabled",
        InterventionMode::Disabled => "disabled",
    }
}

fn debug_discovery_surface_fanout(fanout: policy::DiscoverySurfaceFanout) -> Value {
    json!({
        "docs_seen": fanout.docs_seen,
        "openapi_seen": fanout.openapi_seen,
        "distinct_surfaces": fanout.distinct_surface_count(),
    })
}

fn debug_response_fields(response: &HttpResponse) -> Value {
    json!({
        "status": response.status,
        "body_len": response.body.len(),
        "header_count": response.headers.len(),
        "set_cookie": response
            .headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case(session::SET_COOKIE_HEADER_NAME)),
    })
}

fn debug_surface_action(action: &SurfaceAction) -> Value {
    match action {
        SurfaceAction::ProtectedUpstream => json!({
            "type": "protected_upstream",
        }),
        SurfaceAction::RewrittenUpstream { plan } => json!({
            "type": "rewritten_upstream",
            "plan": debug_rewrite_plan(plan),
        }),
        SurfaceAction::EidolonOwned { response } => json!({
            "type": "eidolon_owned",
            "response_status": response.status,
            "response_body_len": response.body.len(),
            "response_header_count": response.headers.len(),
        }),
        SurfaceAction::ControlledReality { reason, response } => json!({
            "type": "controlled_reality",
            "reason": reason,
            "response_status": response.status,
            "response_body_len": response.body.len(),
            "response_header_count": response.headers.len(),
        }),
        SurfaceAction::RateLimited { reason, response } => json!({
            "type": "rate_limited",
            "reason": reason,
            "response_status": response.status,
            "response_body_len": response.body.len(),
            "response_header_count": response.headers.len(),
        }),
    }
}

fn debug_rewrite_plan(plan: &RewritePlan) -> &'static str {
    match &plan.operation {
        Some(operation) if operation.is_empty() => "empty",
        Some(eidolon_proxy::surface::RewriteOperation::Html(_)) => "html",
        Some(eidolon_proxy::surface::RewriteOperation::RobotsTxt(_)) => "robots_txt",
        Some(eidolon_proxy::surface::RewriteOperation::OpenApiPaths(_)) => "openapi_paths",
        Some(eidolon_proxy::surface::RewriteOperation::JsonFields(_)) => "json_fields",
        None => "none",
    }
}

fn debug_rewrite_disposition(
    disposition: eidolon_proxy::surface::RewriteDisposition,
) -> &'static str {
    match disposition {
        eidolon_proxy::surface::RewriteDisposition::Unchanged => "unchanged",
        eidolon_proxy::surface::RewriteDisposition::Rewritten => "rewritten",
        eidolon_proxy::surface::RewriteDisposition::Refused => "refused",
    }
}

fn intervention_mode_from_control_file(path: &Path) -> InterventionMode {
    match fs::read_to_string(path) {
        Ok(value) if intervention_control_disables(&value) => InterventionMode::Disabled,
        Ok(_) => InterventionMode::Enabled,
        Err(error) if error.kind() == io::ErrorKind::NotFound => InterventionMode::Enabled,
        Err(error) => {
            eprintln!(
                "intervention control file `{}` could not be read; disabling interventions: {error}",
                path.display()
            );
            InterventionMode::Disabled
        }
    }
}

fn intervention_control_disables(value: &str) -> bool {
    let value = value.trim();
    value.eq_ignore_ascii_case("disabled")
        || value.eq_ignore_ascii_case("disable")
        || value.eq_ignore_ascii_case("off")
        || value == "0"
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpRequest {
    method: String,
    target: String,
    version: String,
    headers: Vec<HttpHeader>,
    body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpHeader {
    name: String,
    value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpResponse {
    version: String,
    status: u16,
    reason: String,
    headers: Vec<HttpHeader>,
    body: Vec<u8>,
}

impl HttpRequest {
    fn to_upstream_bytes(&self, upstream: &UpstreamTarget) -> io::Result<Vec<u8>> {
        let target = normalize_request_target(&self.target)?;
        let connection_nominated_headers = connection_nominated_headers(&self.headers);
        let should_emit_content_length = !self.body.is_empty()
            || self
                .headers
                .iter()
                .any(|header| header.name.eq_ignore_ascii_case("content-length"));
        let mut bytes = Vec::new();

        write!(
            bytes,
            "{} {} {}\r\nHost: {}\r\nConnection: close\r\n",
            self.method, target, self.version, upstream.authority
        )?;

        if should_emit_content_length {
            write!(bytes, "Content-Length: {}\r\n", self.body.len())?;
        }

        for header in &self.headers {
            if should_skip_forwarded_header(&header.name, &connection_nominated_headers) {
                continue;
            }

            write!(bytes, "{}: {}\r\n", header.name, header.value)?;
        }

        bytes.extend_from_slice(b"\r\n");
        bytes.extend_from_slice(&self.body);
        Ok(bytes)
    }
}

impl HttpResponse {
    fn to_http_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        write!(
            bytes,
            "{} {} {}\r\n",
            self.version, self.status, self.reason
        )
        .expect("writing to Vec should not fail");

        for header in &self.headers {
            write!(bytes, "{}: {}\r\n", header.name, header.value)
                .expect("writing to Vec should not fail");
        }

        bytes.extend_from_slice(b"\r\n");
        bytes.extend_from_slice(&self.body);
        bytes
    }

    fn set_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = name.into();
        let value = value.into();
        self.remove_header(&name);
        self.headers.push(HttpHeader { name, value });
    }

    fn remove_header(&mut self, name: &str) {
        self.headers
            .retain(|header| !header.name.eq_ignore_ascii_case(name));
    }

    fn append_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.headers.push(HttpHeader {
            name: name.into(),
            value: value.into(),
        });
    }
}

fn read_http_request<R>(reader: &mut R) -> io::Result<Option<HttpRequest>>
where
    R: Read,
{
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    let header_end = loop {
        let bytes_read = reader.read(&mut chunk)?;
        if bytes_read == 0 {
            if buffer.is_empty() {
                return Ok(None);
            }

            return Err(invalid_data(
                "connection closed before HTTP headers completed",
            ));
        }

        buffer.extend_from_slice(&chunk[..bytes_read]);
        if buffer.len() > MAX_HEADER_BYTES {
            return Err(invalid_data("HTTP request headers exceed size limit"));
        }

        if let Some(header_end) = find_header_end(&buffer) {
            break header_end;
        }
    };

    let head = &buffer[..header_end - 4];
    let mut request = parse_http_request_head(head)?;
    let content_length = request_content_length(&request)?;
    if content_length > MAX_BODY_BYTES {
        return Err(invalid_data("HTTP request body exceeds size limit"));
    }

    let body_start = header_end;
    request
        .body
        .extend_from_slice(&buffer[body_start..buffer.len().min(body_start + content_length)]);

    while request.body.len() < content_length {
        let remaining = content_length - request.body.len();
        let read_len = remaining.min(chunk.len());
        let bytes_read = reader.read(&mut chunk[..read_len])?;
        if bytes_read == 0 {
            return Err(invalid_data("connection closed before HTTP body completed"));
        }

        request.body.extend_from_slice(&chunk[..bytes_read]);
    }

    Ok(Some(request))
}

fn read_http_response<R>(reader: &mut R) -> io::Result<HttpResponse>
where
    R: Read,
{
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    let header_end = loop {
        let bytes_read = reader.read(&mut chunk)?;
        if bytes_read == 0 {
            return Err(invalid_data(
                "connection closed before HTTP response headers completed",
            ));
        }

        buffer.extend_from_slice(&chunk[..bytes_read]);
        if buffer.len() > MAX_HEADER_BYTES {
            return Err(invalid_data("HTTP response headers exceed size limit"));
        }

        if let Some(header_end) = find_header_end(&buffer) {
            break header_end;
        }
    };

    let head = &buffer[..header_end - 4];
    let mut response = parse_http_response_head(head)?;
    let body_start = header_end;
    response.body.extend_from_slice(&buffer[body_start..]);

    match response_transfer_coding(&response)? {
        ResponseTransferCoding::Identity => {
            if let Some(content_length) = response_content_length(&response)? {
                if content_length > MAX_BODY_BYTES {
                    return Err(invalid_data("HTTP response body exceeds size limit"));
                }

                if response.body.len() > content_length {
                    response.body.truncate(content_length);
                }

                while response.body.len() < content_length {
                    let remaining = content_length - response.body.len();
                    let read_len = remaining.min(chunk.len());
                    let bytes_read = reader.read(&mut chunk[..read_len])?;
                    if bytes_read == 0 {
                        return Err(invalid_data(
                            "connection closed before HTTP response body completed",
                        ));
                    }

                    response.body.extend_from_slice(&chunk[..bytes_read]);
                }
            } else {
                while response.body.len() <= MAX_BODY_BYTES {
                    let bytes_read = reader.read(&mut chunk)?;
                    if bytes_read == 0 {
                        return Ok(response);
                    }

                    response.body.extend_from_slice(&chunk[..bytes_read]);
                }

                return Err(invalid_data("HTTP response body exceeds size limit"));
            }
        }
        ResponseTransferCoding::Chunked => {
            response.body = read_chunked_response_body(reader, response.body)?;
        }
    }

    Ok(response)
}

fn parse_http_request_head(head: &[u8]) -> io::Result<HttpRequest> {
    let head = std::str::from_utf8(head).map_err(|_| invalid_data("HTTP headers are not UTF-8"))?;
    let mut lines = head.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| invalid_data("missing HTTP request line"))?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| invalid_data("missing HTTP method"))?;
    let target = request_parts
        .next()
        .ok_or_else(|| invalid_data("missing HTTP request target"))?;
    let version = request_parts
        .next()
        .ok_or_else(|| invalid_data("missing HTTP version"))?;

    if request_parts.next().is_some() {
        return Err(invalid_data("HTTP request line has too many fields"));
    }

    if !version.starts_with("HTTP/") {
        return Err(invalid_data("HTTP version must start with HTTP/"));
    }

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }

        let Some((name, value)) = line.split_once(':') else {
            return Err(invalid_data("HTTP header is missing `:`"));
        };

        let name = name.trim();
        if name.is_empty() {
            return Err(invalid_data("HTTP header name cannot be empty"));
        }

        headers.push(HttpHeader {
            name: name.to_string(),
            value: value.trim().to_string(),
        });
    }

    Ok(HttpRequest {
        method: method.to_string(),
        target: target.to_string(),
        version: version.to_string(),
        headers,
        body: Vec::new(),
    })
}

fn parse_http_response_head(head: &[u8]) -> io::Result<HttpResponse> {
    let head = std::str::from_utf8(head)
        .map_err(|_| invalid_data("HTTP response headers are not UTF-8"))?;
    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| invalid_data("missing HTTP response status line"))?;
    let mut status_parts = status_line.splitn(3, ' ');
    let version = status_parts
        .next()
        .ok_or_else(|| invalid_data("missing HTTP response version"))?;
    let status = status_parts
        .next()
        .ok_or_else(|| invalid_data("missing HTTP response status"))?;
    let reason = status_parts.next().unwrap_or_default();

    if !version.starts_with("HTTP/") {
        return Err(invalid_data("HTTP response version must start with HTTP/"));
    }

    let status = status
        .parse::<u16>()
        .map_err(|error| invalid_data(format!("invalid HTTP response status: {error}")))?;

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }

        let Some((name, value)) = line.split_once(':') else {
            return Err(invalid_data("HTTP response header is missing `:`"));
        };

        let name = name.trim();
        if name.is_empty() {
            return Err(invalid_data("HTTP response header name cannot be empty"));
        }

        headers.push(HttpHeader {
            name: name.to_string(),
            value: value.trim().to_string(),
        });
    }

    Ok(HttpResponse {
        version: version.to_string(),
        status,
        reason: reason.to_string(),
        headers,
        body: Vec::new(),
    })
}

fn request_content_length(request: &HttpRequest) -> io::Result<usize> {
    if request.headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("transfer-encoding")
            && header.value.to_ascii_lowercase().contains("chunked")
    }) {
        return Err(invalid_data(
            "chunked request bodies are not supported by the v0 proxy",
        ));
    }

    let mut content_length = None;
    for header in &request.headers {
        if header.name.eq_ignore_ascii_case("content-length") {
            let parsed = header
                .value
                .parse::<usize>()
                .map_err(|error| invalid_data(format!("invalid Content-Length: {error}")))?;
            if content_length.is_some_and(|existing| existing != parsed) {
                return Err(invalid_data("conflicting request Content-Length headers"));
            }
            content_length = Some(parsed);
        }
    }

    Ok(content_length.unwrap_or(0))
}

fn response_content_length(response: &HttpResponse) -> io::Result<Option<usize>> {
    let mut content_length = None;
    for header in &response.headers {
        if header.name.eq_ignore_ascii_case("content-length") {
            let parsed = header
                .value
                .parse::<usize>()
                .map_err(|error| invalid_data(format!("invalid Content-Length: {error}")))?;
            if content_length.is_some_and(|existing| existing != parsed) {
                return Err(invalid_data("conflicting upstream Content-Length headers"));
            }
            content_length = Some(parsed);
        }
    }

    Ok(content_length)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseTransferCoding {
    Identity,
    Chunked,
}

fn response_transfer_coding(response: &HttpResponse) -> io::Result<ResponseTransferCoding> {
    let codings: Vec<String> = response
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("transfer-encoding"))
        .flat_map(|header| header.value.split(','))
        .map(|coding| coding.trim().to_ascii_lowercase())
        .filter(|coding| !coding.is_empty())
        .collect();

    match codings.as_slice() {
        [] => Ok(ResponseTransferCoding::Identity),
        [coding] if coding == "chunked" => Ok(ResponseTransferCoding::Chunked),
        _ => Err(invalid_data(format!(
            "unsupported upstream Transfer-Encoding: {}",
            codings.join(", ")
        ))),
    }
}

fn read_chunked_response_body<R>(reader: &mut R, mut buffer: Vec<u8>) -> io::Result<Vec<u8>>
where
    R: Read,
{
    let mut body = Vec::new();

    loop {
        let size_line = read_crlf_line(reader, &mut buffer)?;
        let chunk_size = parse_chunk_size(&size_line)?;

        if chunk_size == 0 {
            loop {
                let trailer_line = read_crlf_line(reader, &mut buffer)?;
                if trailer_line.is_empty() {
                    return Ok(body);
                }
            }
        }

        let body_len = body
            .len()
            .checked_add(chunk_size)
            .ok_or_else(|| invalid_data("HTTP response body exceeds size limit"))?;
        if body_len > MAX_BODY_BYTES {
            return Err(invalid_data("HTTP response body exceeds size limit"));
        }

        let chunk_with_crlf = chunk_size
            .checked_add(2)
            .ok_or_else(|| invalid_data("HTTP response chunk exceeds size limit"))?;
        ensure_buffer_len(reader, &mut buffer, chunk_with_crlf)?;
        body.extend(buffer.drain(..chunk_size));
        if buffer.drain(..2).ne(b"\r\n".iter().copied()) {
            return Err(invalid_data("invalid chunked response body"));
        }
    }
}

fn read_crlf_line<R>(reader: &mut R, buffer: &mut Vec<u8>) -> io::Result<Vec<u8>>
where
    R: Read,
{
    loop {
        if let Some(line_end) = find_crlf(buffer) {
            let line = buffer[..line_end].to_vec();
            buffer.drain(..line_end + 2);
            return Ok(line);
        }

        if buffer.len() > MAX_HEADER_BYTES {
            return Err(invalid_data("chunked response metadata exceeds size limit"));
        }

        read_more(reader, buffer)?;
    }
}

fn ensure_buffer_len<R>(reader: &mut R, buffer: &mut Vec<u8>, len: usize) -> io::Result<()>
where
    R: Read,
{
    while buffer.len() < len {
        read_more(reader, buffer)?;
    }

    Ok(())
}

fn read_more<R>(reader: &mut R, buffer: &mut Vec<u8>) -> io::Result<()>
where
    R: Read,
{
    let mut chunk = [0_u8; 1024];
    let bytes_read = reader.read(&mut chunk)?;
    if bytes_read == 0 {
        return Err(invalid_data(
            "connection closed before chunked HTTP response body completed",
        ));
    }

    buffer.extend_from_slice(&chunk[..bytes_read]);
    Ok(())
}

fn parse_chunk_size(line: &[u8]) -> io::Result<usize> {
    let line = std::str::from_utf8(line)
        .map_err(|_| invalid_data("chunked response size line is not UTF-8"))?;
    let size = line
        .split_once(';')
        .map_or(line, |(size, _extension)| size)
        .trim();

    if size.is_empty() {
        return Err(invalid_data("missing chunked response size"));
    }

    usize::from_str_radix(size, 16)
        .map_err(|error| invalid_data(format!("invalid chunked response size: {error}")))
}

fn find_crlf(buffer: &[u8]) -> Option<usize> {
    buffer.windows(2).position(|window| window == b"\r\n")
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

fn normalize_request_target(target: &str) -> io::Result<&str> {
    if target.is_empty() {
        return Err(invalid_data("HTTP request target cannot be empty"));
    }

    if target.starts_with('/') {
        return Ok(target);
    }

    if let Some(rest) = target.strip_prefix("http://") {
        return Ok(match rest.find('/') {
            Some(index) => &rest[index..],
            None => "/",
        });
    }

    if target == "*" {
        return Ok(target);
    }

    Err(invalid_data(
        "HTTP request target must be origin-form or http absolute-form",
    ))
}

fn effective_request_host(request: &HttpRequest) -> Option<String> {
    request_host_from_target(&request.target)
        .or_else(|| {
            request
                .headers
                .iter()
                .find(|header| header.name.eq_ignore_ascii_case("host"))
                .map(|header| header.value.as_str())
        })
        .and_then(normalize_request_host)
}

fn request_host_from_target(target: &str) -> Option<&str> {
    let rest = target.strip_prefix("http://")?;
    Some(match rest.split_once('/') {
        Some((authority, _)) => authority,
        None => rest,
    })
}

fn normalize_request_host(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    let bracketless = value
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(value);
    if bracketless.parse::<IpAddr>().is_ok() {
        return Some(bracketless.to_ascii_lowercase());
    }

    parse_authority(value)
        .ok()
        .map(|(host, _)| host.to_ascii_lowercase())
}

fn connection_nominated_headers(headers: &[HttpHeader]) -> Vec<String> {
    headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("connection"))
        .flat_map(|header| header.value.split(','))
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect()
}

fn should_skip_forwarded_header(name: &str, connection_nominated_headers: &[String]) -> bool {
    name.eq_ignore_ascii_case("host")
        || name.eq_ignore_ascii_case("content-length")
        || name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("proxy-connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("proxy-authenticate")
        || name.eq_ignore_ascii_case("proxy-authorization")
        || name.eq_ignore_ascii_case("te")
        || name.eq_ignore_ascii_case("trailer")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("upgrade")
        || name.to_ascii_lowercase().starts_with("x-eidolon-")
        || connection_nominated_headers
            .iter()
            .any(|header| name.eq_ignore_ascii_case(header))
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
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
    use std::{
        io::{Cursor, Read, Write},
        net::{Shutdown, TcpListener},
        thread::JoinHandle,
        time::{SystemTime, UNIX_EPOCH},
    };

    use eidolon_core::{ExpectedAction, SessionId, SurfaceKind};
    use eidolon_proxy::surface::{HtmlInsertion, RewritePlan};
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

    fn set_runtime_policy_state(runtime: &ProxyRuntime, cookie: &str, policy_state: PolicyState) {
        let session_id =
            session::session_id_from_cookie_header(cookie).expect("cookie should contain session");
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
        format!("eidolon_session={}", SessionId::new().0)
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
        let cookie_a = format!("eidolon_session={}", session_a.0);
        let session_b = SessionId::new();
        let cookie_b = format!("eidolon_session={}", session_b.0);
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
        let (upstream, upstream_handle) = spawn_upstream(json_response(r#"{"mode":"upstream"}"#));
        let runtime = test_runtime_with_bait_profile(
            upstream,
            &event_log_path,
            unique_temp_path("session-minted-bait-replay-control.txt"),
            loaded,
            Some(Arc::clone(&signing_secret)),
        );
        let session_a = SessionId::new();
        let cookie_a = format!("eidolon_session={}", session_a.0);
        let session_b = SessionId::new();
        let cookie_b = format!("eidolon_session={}", session_b.0);
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
        let upstream_request = must_join(upstream_handle.join(), "upstream thread should join");

        assert_eq!(exposure_a.status, 200);
        assert_eq!(exposure_b.status, 200);
        assert_eq!(replay_response.body, br#"{"mode":"upstream"}"#);
        assert!(must_ok(
            String::from_utf8(upstream_request),
            "request should be utf8"
        )
        .starts_with("POST /api/v2/import/reconcile HTTP/1.1\r\n"));

        let replay_action = events_of_type(&event_log_path, "bait_action_observed")
            .into_iter()
            .find(|event| event["session_id"] == session_b.0.to_string())
            .expect("replayed minted bait action should be logged");
        assert_eq!(replay_action["policy_state"], "observe");
        assert_eq!(replay_action["kind"]["bait_id"], "minted_trace");
        assert!(replay_action["kind"]["exposure_id"].is_null());
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
        assert_eq!(
            replay_request["kind"]["routing_decision"],
            "protected_upstream"
        );

        assert!(!events_of_type(&event_log_path, "policy_changed")
            .into_iter()
            .any(|event| {
                event["session_id"] == session_b.0.to_string()
                    && event["kind"]["to"] == "controlled_reality"
            }));
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
        let session = session::derive_session_from_headers([("Cookie", cookie_header())]);
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
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("persistence_class=discovery_recon")));

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
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("persistence_class=discovery_recon")));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("persistence_kind=discovery_recon_retry")));

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
        assert!(surface_debugs[2]["fields"]["policy_reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("persistence_class=discovery_recon")));
        assert!(surface_debugs[2]["fields"]["policy_reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("persistence_kind=discovery_recon_retry")));
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
        assert_eq!(second_response.status, 200);

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
            "protected_upstream"
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
        assert_eq!(second_response.status, 200);

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
            "protected_upstream"
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
        assert_eq!(second_response.status, 200);
        assert_eq!(third_response.status, 200);
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
            "protected_upstream"
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
            "protected_upstream"
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
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("persistence_class=discovery_recon")));

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
        assert_eq!(second_response.status, 200);
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
            "protected_upstream"
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
        assert!(policy_changes[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("persistence_class=discovery_recon")));

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
        assert_eq!(second_response.status, 200);
        assert_eq!(third_response.status, 429);
        assert_eq!(header_values(&third_response, "retry-after"), vec!["30"]);

        let request_events = events_of_type(&event_log_path, "request_seen");
        assert_eq!(request_events.len(), 3);
        assert_eq!(request_events[1]["policy_state"], "suspicious");
        assert_eq!(
            request_events[1]["kind"]["routing_decision"],
            "protected_upstream"
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
        assert_eq!(second_response.status, 200);
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
            "protected_upstream"
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
        assert_eq!(policy_decisions.len(), 2);
        assert!(policy_decisions[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| {
                reason.contains("rate-limited discovery recon retry moved session to blocked")
            }));
        assert!(policy_decisions[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("decoy_write_probe_seen=true")));
        assert!(policy_decisions[1]["kind"]["reason"]
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
        assert_eq!(second_response.status, 200);
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
        assert_eq!(policy_decisions.len(), 2);
        assert!(policy_decisions[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| {
                reason.contains("rate-limited discovery recon retry moved session to blocked")
            }));
        assert!(policy_decisions[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("decoy_write_probe_count=2")));
        assert!(policy_decisions[1]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("decoy_write_probe_path_classes=2")));
        assert!(policy_decisions[1]["kind"]["reason"]
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
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("persistence_kind=write_recon_retry")));
        assert!(policy_changes[2]["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("persistence_class=write_recon")));

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
            "rate-limited discovery recon retry moved session to blocked: path=/docs actor_kind=agentic_browser vendor_score=35 discovery_requests=3 distinct_surfaces=2 query_seen=true legacy_openapi_query_seen=true linked_bait_surface_seen=false linked_bait_surface_classes=0 decoy_write_probe_seen=false decoy_write_probe_count=0 decoy_write_probe_path_classes=0 detection_count=0 repeated_discovery_score=2 query_score=1 legacy_openapi_query_score=2 linked_bait_surface_score=0 linked_bait_class_fanout_bonus=0 decoy_write_probe_score=0 decoy_write_probe_path_fanout_bonus=0 detection_score=0 recon_score=5 recon_block_threshold=5 persistence_class=discovery_recon persistence_kind=discovery_recon_retry"
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
        let (upstream, upstream_handle) = spawn_upstream(html_response(original));
        let mut runtime = test_runtime_with_m1_controller_and_debug_log(
            upstream,
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
        let cookie = format!("eidolon_session={}", session_id.0);
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
    fn runtime_wrong_bait_header_value_logs_unmatched_bait_action_and_forwards_upstream() {
        let event_log_path = unique_temp_path("near-miss-events.jsonl");
        let (upstream, upstream_handle) = spawn_upstream(json_response(r#"{"mode":"upstream"}"#));
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
        let upstream_request = must_join(upstream_handle.join(), "upstream thread should join");

        assert_eq!(response.body, br#"{"mode":"upstream"}"#);
        assert!(must_ok(
            String::from_utf8(upstream_request),
            "request should be utf8"
        )
        .starts_with("POST /api/v2/import/reconcile HTTP/1.1\r\n"));
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
    fn runtime_missing_bait_header_on_shared_path_does_not_log_bait_action() {
        let event_log_path = unique_temp_path("missing-bait-header-events.jsonl");
        let (upstream, upstream_handle) = spawn_upstream(json_response(r#"{"mode":"upstream"}"#));
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
        let upstream_request = must_join(upstream_handle.join(), "upstream thread should join");

        assert_eq!(response.body, br#"{"mode":"upstream"}"#);
        assert!(must_ok(
            String::from_utf8(upstream_request),
            "request should be utf8"
        )
        .starts_with("POST /api/v2/import/reconcile HTTP/1.1\r\n"));
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
        assert!(policy_changed["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("persistence_class=same_bait_near_miss")));
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
        assert!(blocked_change["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason
                .contains("post_containment_persistence_kind=controlled_reality_depth_limit")));

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
        assert!(blocked_change["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason
                .contains("post_containment_persistence_kind=controlled_reality_branch_escape")));

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
