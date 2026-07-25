use std::{
    collections::{HashMap, HashSet, VecDeque},
    env, fmt, fs,
    io::{self, BufRead, BufReader, Read, Write},
    net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    path::{Component, Path, PathBuf},
    process::ExitCode,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use eidolon_bait::{docs_for_bait, render_bait_for_session, BaitRegistry};
use eidolon_core::{
    Bait, BaitClass, BaitHeaderValueMintStatus, BaitId, ControlledRealityInteraction,
    DiscoveryReconScore, Event, EventKind, EventSource, ExposureId, HeaderValueMint, PolicyState,
    RequestId, RoutingDecision, SafeHeaderObservation, SessionId, EVENT_SCHEMA_VERSION,
};
use eidolon_proxy::{
    controlled_reality::{
        is_controlled_follow_up_path, rate_limited_response, ControlledRealityConfig,
        ControlledRealityRenderedResponse, ControlledRealityResourceDescriptor,
        ControlledRealityResponder, DEFAULT_RETRY_AFTER_SECONDS, DEFAULT_TARPIT_DELAY,
        MAX_CONTROLLED_REALITY_ACTION_DEPTH, MAX_TARPIT_DELAY,
    },
    controlled_reality_backend::{
        ControlledRealityBackendAuthSecret, ControlledRealityBackendClient,
        ControlledRealityBackendError,
    },
    debug_log::FileDebugLogWriter,
    event_log::{
        read_jsonl_reconstruction, DurableResponseMatch, FileEventLogWriter, JsonlTailRepairOutcome,
    },
    http_request::{
        canonical_request_target, normalized_request_host, HttpHeader, HttpRequest, HttpVersion,
        RequestTargetMode, MAX_HTTP_BODY_BYTES as MAX_BODY_BYTES,
        MAX_HTTP_HEADER_BYTES as MAX_HEADER_BYTES,
    },
    ingress_identity::{self, IngressIdentityResolver},
    policy::{self, InterventionMode},
    policy_store::{
        ControlledRealityPendingInteractionKind, ControlledRealityPendingResponse,
        ControlledRealityProgress, PolicyStateStore,
    },
    request_evaluation::{self, RequestEvaluationInput, RequestPolicyFacts},
    session::{self, SessionContext},
    session_auth::{enforcement_rank, SessionAuthority},
    state_lease::DurableStateLease,
    surface::{
        rewrite_response_body, HtmlInsertion, OpenApiPathInsertion, ResponseCachePolicy,
        RewritePlan, SurfaceAction, SurfaceController, SurfaceHeader, SurfaceRequestMeta,
        SurfaceResponse, SurfaceResponseMeta,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

#[cfg(test)]
use eidolon_proxy::http_request::canonicalize_request_target;

const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:8080";
const DEFAULT_UPSTREAM: &str = "http://127.0.0.1:9001";
const DEFAULT_EVENT_LOG: &str = "/tmp/eidolon-events.jsonl";
const DEFAULT_INTERVENTION_CONTROL: &str = "/tmp/eidolon-interventions.txt";
const DEFAULT_POLICY_STATE: &str = "/tmp/eidolon-policy-state.json";
const DEFAULT_TRUSTED_BAIT_SOFTEN_PREFIXES: &[&str] = &["/docs", "/openapi.json"];
const SESSION_PROOF_CACHE_CONTROL: &str = "private, no-store";
const DOCS_DISCOVERY_TARGET: &str = "/docs";
const OPENAPI_DISCOVERY_TARGET: &str = "/openapi.json";
const REJECTED_REQUEST_TARGET: &str = "/__eidolon_rejected_target__";
const LEGACY_IMPORT_OPENAPI_QUERY: &str = "eidolon_surface=legacy-import";
const DEFAULT_HTTP_PORT: u16 = 80;
const MAX_INFORMATIONAL_RESPONSES: usize = 16;
const MAX_BAIT_EXPOSURES: usize = 4096;
const BAIT_EXPOSURE_TTL_SECS: u64 = 24 * 60 * 60;
const MAX_CONSUMED_BAIT_PROOFS: usize = 4096;
const MAX_BAIT_PROOF_TTL_SECS: u64 = 24 * 60 * 60;
const BAIT_EXPOSURE_STATE_SCHEMA_VERSION: u16 = 1;
const CONSUMED_PROOF_STATE_SCHEMA_VERSION: u16 = 1;
const MAX_CONCURRENT_CONNECTIONS: usize = 64;
const CONTROLLED_REALITY_WORKFLOW_LOCK_SHARDS: usize = 64;
const CONTROLLED_REALITY_BACKEND_ENCODED_SECRET_BYTES: usize = 64;
const CONTROLLED_REALITY_BACKEND_MAX_SECRET_FILE_BYTES: usize =
    CONTROLLED_REALITY_BACKEND_ENCODED_SECRET_BYTES + 1;
const CLIENT_IO_TIMEOUT: Duration = Duration::from_secs(30);
const CLIENT_REQUEST_DEADLINE: Duration = Duration::from_secs(30);
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
                "authenticated_ingress_continuity: {}",
                if config.require_authenticated_ingress_continuity {
                    "required"
                } else {
                    "optional"
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
            match &config.controlled_reality_backend {
                Some(backend) => {
                    println!("controlled_reality_renderer: remote ({})", backend.address)
                }
                None => println!("controlled_reality_renderer: in_process"),
            }
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
    require_authenticated_ingress_continuity: bool,
    trusted_bait_soften_path_prefixes: Vec<String>,
    intervention_control_path: PathBuf,
    policy_state_path: PathBuf,
    controlled_reality_config: ControlledRealityConfig,
    controlled_reality_backend: Option<ControlledRealityBackendConfig>,
    owned_cluster_lab: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ControlledRealityBackendConfig {
    address: String,
    auth_secret_path: PathBuf,
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
                "--require-authenticated-ingress-continuity" => {
                    if builder.require_authenticated_ingress_continuity {
                        return Err(ConfigError::new(format!("duplicate option `{flag}`")));
                    }
                    builder.require_authenticated_ingress_continuity = true;
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
                "--controlled-reality-backend-addr" => {
                    let value = option_value(flag, inline_value, &mut args)?;
                    set_once(&mut builder.controlled_reality_backend_addr, flag, value)?;
                }
                "--controlled-reality-backend-auth-secret-file" => {
                    let value = option_value(flag, inline_value, &mut args)?;
                    set_once(
                        &mut builder.controlled_reality_backend_auth_secret_path,
                        flag,
                        parse_controlled_reality_backend_auth_secret_path(&value)?,
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
    require_authenticated_ingress_continuity: bool,
    trusted_bait_soften_path_prefixes: Vec<String>,
    intervention_control_path: Option<PathBuf>,
    policy_state_path: Option<PathBuf>,
    controlled_reality_max_depth: Option<u32>,
    controlled_reality_tarpit_delay: Option<Duration>,
    controlled_reality_retry_after_seconds: Option<u64>,
    controlled_reality_backend_addr: Option<String>,
    controlled_reality_backend_auth_secret_path: Option<PathBuf>,
    owned_cluster_lab: bool,
}

impl ConfigBuilder {
    fn build(self) -> Result<ProxyConfig, ConfigError> {
        if self.require_authenticated_ingress_continuity
            && self.ingress_transport_auth_secret_path.is_none()
        {
            return Err(ConfigError::new(
                "`--require-authenticated-ingress-continuity` requires \
                 `--ingress-transport-auth-secret-file`",
            ));
        }
        let controlled_reality_backend = match (
            self.controlled_reality_backend_addr,
            self.controlled_reality_backend_auth_secret_path,
        ) {
            (Some(address), Some(auth_secret_path)) => Some(ControlledRealityBackendConfig {
                address: parse_controlled_reality_backend_addr(&address, self.owned_cluster_lab)?,
                auth_secret_path,
            }),
            (None, None) => None,
            _ => {
                return Err(ConfigError::new(
                    "controlled-reality backend address and auth secret file must be configured together",
                ));
            }
        };
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
            require_authenticated_ingress_continuity: self.require_authenticated_ingress_continuity,
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
            controlled_reality_backend,
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

fn parse_controlled_reality_backend_addr(
    raw: &str,
    owned_cluster_lab: bool,
) -> Result<String, ConfigError> {
    if let Ok(address) = raw.parse::<SocketAddr>() {
        if address.port() == 0 {
            return Err(ConfigError::new(
                "controlled reality backend port must not be 0",
            ));
        }
        if address.ip().is_unspecified() || (!address.ip().is_loopback() && !owned_cluster_lab) {
            return Err(ConfigError::new(
                "controlled reality backend must be loopback unless `--owned-cluster-lab` is set",
            ));
        }
        return Ok(address.to_string());
    }

    if !owned_cluster_lab {
        return Err(ConfigError::new(
            "controlled reality backend DNS names require `--owned-cluster-lab`",
        ));
    }
    if raw.contains(['/', '?', '#', '@']) || raw.chars().any(char::is_whitespace) {
        return Err(ConfigError::new(
            "controlled reality backend must be a host and explicit TCP port",
        ));
    }
    let Some((host, raw_port)) = raw.rsplit_once(':') else {
        return Err(ConfigError::new(
            "controlled reality backend DNS name requires an explicit TCP port",
        ));
    };
    if host.is_empty()
        || host.starts_with('.')
        || host.ends_with('.')
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
    {
        return Err(ConfigError::new(
            "controlled reality backend DNS name is invalid",
        ));
    }
    let port = parse_port(raw_port, "controlled reality backend port")?;
    if port == 0 {
        return Err(ConfigError::new(
            "controlled reality backend port must not be 0",
        ));
    }
    Ok(raw.to_string())
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

fn parse_controlled_reality_backend_auth_secret_path(raw: &str) -> Result<PathBuf, ConfigError> {
    let path = parse_file_path(raw, "controlled reality backend auth secret")?;
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(ConfigError::new(
            "controlled reality backend auth secret path must be absolute and contain no `..` components",
        ));
    }
    if !path.is_file() {
        return Err(ConfigError::new(format!(
            "controlled reality backend auth secret path must be an existing file: `{}`",
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

fn load_controlled_reality_backend_auth_secret(
    path: &Path,
) -> io::Result<ControlledRealityBackendAuthSecret> {
    let file = fs::File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid_data(
            "controlled reality backend auth secret must be a regular file",
        ));
    }
    let mut encoded = Vec::with_capacity(CONTROLLED_REALITY_BACKEND_MAX_SECRET_FILE_BYTES + 1);
    file.take((CONTROLLED_REALITY_BACKEND_MAX_SECRET_FILE_BYTES + 1) as u64)
        .read_to_end(&mut encoded)?;
    let decoded = decode_controlled_reality_backend_auth_secret(&encoded);
    encoded.fill(0);
    ControlledRealityBackendAuthSecret::new(decoded?).map_err(|_| {
        invalid_data("controlled reality backend auth secret must decode to 32 nontrivial bytes")
    })
}

fn decode_controlled_reality_backend_auth_secret(encoded: &[u8]) -> io::Result<Vec<u8>> {
    let encoded = match encoded {
        bytes if bytes.len() == CONTROLLED_REALITY_BACKEND_ENCODED_SECRET_BYTES => bytes,
        bytes
            if bytes.len() == CONTROLLED_REALITY_BACKEND_MAX_SECRET_FILE_BYTES
                && bytes.last().is_some_and(|byte| *byte == b'\n') =>
        {
            &bytes[..CONTROLLED_REALITY_BACKEND_ENCODED_SECRET_BYTES]
        }
        _ => {
            return Err(invalid_data(
                "controlled reality backend auth secret must contain exactly 64 hexadecimal characters and an optional newline",
            ));
        }
    };
    let mut decoded = Vec::with_capacity(CONTROLLED_REALITY_BACKEND_ENCODED_SECRET_BYTES / 2);
    for pair in encoded.chunks_exact(2) {
        let high = decode_controlled_reality_backend_hex_nibble(pair[0])
            .ok_or_else(|| invalid_data("controlled reality backend auth secret is not hex"))?;
        let low = decode_controlled_reality_backend_hex_nibble(pair[1])
            .ok_or_else(|| invalid_data("controlled reality backend auth secret is not hex"))?;
        decoded.push((high << 4) | low);
    }
    Ok(decoded)
}

fn decode_controlled_reality_backend_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
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

struct DeadlineTcpReader<'a> {
    stream: &'a mut TcpStream,
    deadline: Instant,
}

impl<'a> DeadlineTcpReader<'a> {
    fn new(stream: &'a mut TcpStream, timeout: Duration) -> Self {
        Self {
            stream,
            deadline: Instant::now() + timeout,
        }
    }

    fn timeout_error() -> io::Error {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "HTTP request read deadline exceeded",
        )
    }
}

impl Read for DeadlineTcpReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(Self::timeout_error)?;
        if remaining.is_zero() {
            return Err(Self::timeout_error());
        }

        self.stream.set_read_timeout(Some(remaining))?;
        let result = self.stream.read(buffer);
        if Instant::now() >= self.deadline {
            return Err(Self::timeout_error());
        }
        result
    }
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
    let state_lease = DurableStateLease::acquire_for_policy_state(&config.policy_state_path)?;
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
    let (debug_log, debug_log_tail_repair) = match &config.debug_log_path {
        Some(path) => {
            let writer = FileDebugLogWriter::open(path)?;
            let repair = writer.startup_tail_repair();
            (Some(Arc::new(Mutex::new(writer))), Some(repair))
        }
        None => (None, None),
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
    let now = current_unix_secs();
    let bait_exposures = BaitExposureStore::open_or_rebuild(&config.event_log_path, now)?;
    let restored_bait_exposure_count = bait_exposures.len();
    let restored_bait_exposure_ttl_evicted = bait_exposures.ttl_evicted;
    let restored_bait_exposure_torn_tail_line = bait_exposures.torn_tail_line;
    let bait_exposure_state_path = bait_exposures.path.clone();
    let consumed_bait_proofs = ConsumedBaitProofStore::open_or_rebuild(
        &config.event_log_path,
        &bait_registry,
        bait_signing_secret.as_deref(),
        now,
    )?;
    let restored_consumed_bait_proof_count = consumed_bait_proofs.consumed.len();
    let restored_consumed_bait_proof_torn_tail_line = consumed_bait_proofs.torn_tail_line;
    let consumed_proof_state_path = consumed_bait_proofs.path.clone();
    let consumed_proof_migration_quarantine_until = consumed_bait_proofs.migration_quarantine_until;
    let policy_store = PolicyStateStore::open(&config.policy_state_path)?;
    let policy_store_eviction = policy_store.last_eviction_stats();
    let policy_store_session_count = policy_store.len();
    let policy_store_fail_closed_for_unknown_sessions =
        policy_store.fail_closed_for_unknown_sessions();
    let event_log_writer = FileEventLogWriter::open(&config.event_log_path)?;
    let event_log_tail_repair = event_log_writer.startup_tail_repair();
    let controlled_reality_backend = match &config.controlled_reality_backend {
        Some(backend) => Some(Arc::new(
            ControlledRealityBackendClient::from_target(
                &backend.address,
                load_controlled_reality_backend_auth_secret(&backend.auth_secret_path)?,
            )
            .map_err(|error| {
                invalid_data(format!(
                    "could not resolve controlled reality backend: {}",
                    error.audit_code()
                ))
            })?,
        )),
        None => None,
    };
    let runtime = ProxyRuntime {
        upstream: config.upstream,
        client_request_deadline: CLIENT_REQUEST_DEADLINE,
        event_log: Arc::new(Mutex::new(event_log_writer)),
        debug_log,
        intervention_control_path: config.intervention_control_path,
        policy_store: Arc::new(Mutex::new(policy_store)),
        session_authority: Arc::new(Mutex::new(session_authority)),
        controlled_reality_config: config.controlled_reality_config,
        controlled_reality: Arc::new(ControlledRealityResponder),
        controlled_reality_backend,
        controlled_reality_workflow_locks: Arc::new(ControlledRealityWorkflowLocks::new()),
        surface_controller: Arc::new(M1DemoSurfaceController::with_content_overrides(
            Arc::clone(&bait_registry),
            bait_content.clone(),
            bait_signing_secret.clone(),
        )),
        ingress_identity_resolver: Arc::new(ingress_identity_resolver),
        ingress_transport_auth_secret,
        require_authenticated_ingress_continuity: config.require_authenticated_ingress_continuity,
        bait_signing_secret: bait_signing_secret.clone(),
        trusted_bait_soften_path_prefixes: config.trusted_bait_soften_path_prefixes,
        bait_registry,
        bait_content,
        bait_exposures: Arc::new(Mutex::new(bait_exposures)),
        consumed_bait_proofs: Arc::new(Mutex::new(consumed_bait_proofs)),
    };
    reconcile_all_pending_controlled_reality_interactions(&runtime)?;
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
                "renderer": if runtime.controlled_reality_backend.is_some() {
                    "remote"
                } else {
                    "in_process"
                },
            },
            "bait_profile": bait_profile_debug,
            "bait_signing_enabled": bait_signing_secret.is_some(),
            "session_signing": session_signing_debug,
            "restored_consumed_bait_proof_count": restored_consumed_bait_proof_count,
            "restored_consumed_bait_proof_torn_tail_line": restored_consumed_bait_proof_torn_tail_line,
            "consumed_proof_state_path": consumed_proof_state_path,
            "consumed_proof_migration_quarantine_until": consumed_proof_migration_quarantine_until,
            "event_log_tail_repair": jsonl_tail_repair_debug(event_log_tail_repair),
            "debug_log_tail_repair": debug_log_tail_repair.map(jsonl_tail_repair_debug),
            "event_log_bytes": std::fs::metadata(&config.event_log_path)
                .map(|metadata| metadata.len())
                .unwrap_or(0),
            "policy_state_bytes": std::fs::metadata(&config.policy_state_path)
                .map(|metadata| metadata.len())
                .unwrap_or(0),
            "ingress_identity_rule_count": runtime.ingress_identity_resolver.len(),
            "ingress_transport_auth_enabled": runtime.ingress_transport_auth_secret.is_some(),
            "continuity_mode": if runtime.require_authenticated_ingress_continuity {
                "authenticated_ingress_required"
            } else {
                "lab_direct_peer_with_optional_authenticated_ingress"
            },
            "trusted_bait_soften_path_prefixes": runtime.trusted_bait_soften_path_prefixes,
            "restored_bait_exposure_count": restored_bait_exposure_count,
            "restored_bait_exposure_ttl_evicted": restored_bait_exposure_ttl_evicted,
            "restored_bait_exposure_torn_tail_line": restored_bait_exposure_torn_tail_line,
            "bait_exposure_store": {
                "state_path": bait_exposure_state_path,
                "max_records": MAX_BAIT_EXPOSURES,
                "ttl_secs": BAIT_EXPOSURE_TTL_SECS,
            },
            "policy_store": {
                "session_count": policy_store_session_count,
                "ttl_evicted": policy_store_eviction.ttl_evicted,
                "lru_evicted": policy_store_eviction.lru_evicted,
                "protected_fail_closed_evicted": policy_store_eviction.protected_fail_closed_evicted,
                "fail_closed_activated": policy_store_eviction.fail_closed_activated,
                "fail_closed_for_unknown_sessions": policy_store_fail_closed_for_unknown_sessions,
                "max_sessions": eidolon_proxy::policy_store::MAX_POLICY_SESSIONS,
                "session_ttl_secs": eidolon_proxy::policy_store::POLICY_SESSION_TTL_SECS,
            },
            "durable_state_writer": {
                "mode": "single_writer",
                "lease_path": state_lease.path(),
            },
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
                        if let Err(error) = handle_connection(stream, &runtime, permit) {
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

fn jsonl_tail_repair_debug(outcome: JsonlTailRepairOutcome) -> Value {
    match outcome {
        JsonlTailRepairOutcome::NotNeeded => json!({
            "outcome": "not_needed",
        }),
        JsonlTailRepairOutcome::AppendedNewline { previous_len } => json!({
            "outcome": "appended_newline",
            "previous_len": previous_len,
        }),
        JsonlTailRepairOutcome::Truncated {
            original_len,
            repaired_len,
        } => json!({
            "outcome": "truncated",
            "original_len": original_len,
            "repaired_len": repaired_len,
        }),
    }
}

#[derive(Clone)]
struct ProxyRuntime {
    upstream: UpstreamTarget,
    client_request_deadline: Duration,
    event_log: Arc<Mutex<FileEventLogWriter>>,
    debug_log: Option<Arc<Mutex<FileDebugLogWriter>>>,
    intervention_control_path: PathBuf,
    policy_store: Arc<Mutex<PolicyStateStore>>,
    session_authority: Arc<Mutex<SessionAuthority>>,
    controlled_reality_config: ControlledRealityConfig,
    controlled_reality: Arc<ControlledRealityResponder>,
    controlled_reality_backend: Option<Arc<ControlledRealityBackendClient>>,
    controlled_reality_workflow_locks: Arc<ControlledRealityWorkflowLocks>,
    surface_controller: Arc<dyn SurfaceController + Send + Sync>,
    ingress_identity_resolver: Arc<IngressIdentityResolver>,
    ingress_transport_auth_secret: Option<Arc<str>>,
    require_authenticated_ingress_continuity: bool,
    bait_signing_secret: Option<Arc<str>>,
    trusted_bait_soften_path_prefixes: Vec<String>,
    bait_registry: Arc<BaitRegistry>,
    bait_content: BaitContentOverrides,
    bait_exposures: Arc<Mutex<BaitExposureStore>>,
    consumed_bait_proofs: Arc<Mutex<ConsumedBaitProofStore>>,
}

struct ControlledRealityWorkflowLocks {
    shards: [Mutex<()>; CONTROLLED_REALITY_WORKFLOW_LOCK_SHARDS],
}

impl ControlledRealityWorkflowLocks {
    fn new() -> Self {
        Self {
            shards: std::array::from_fn(|_| Mutex::new(())),
        }
    }

    fn lock(&self, session_id: SessionId) -> io::Result<std::sync::MutexGuard<'_, ()>> {
        let index =
            (session_id.0.as_u128() % CONTROLLED_REALITY_WORKFLOW_LOCK_SHARDS as u128) as usize;
        self.shards[index]
            .lock()
            .map_err(|_| io::Error::other("controlled-reality workflow lock poisoned"))
    }
}

#[derive(Debug, Default)]
struct BaitExposureStore {
    path: Option<PathBuf>,
    exposures: HashMap<(SessionId, BaitId), BaitExposureRecord>,
    exposure_order: VecDeque<(SessionId, BaitId)>,
    ttl_evicted: usize,
    torn_tail_line: Option<usize>,
}

#[derive(Debug, Clone)]
struct BaitExposureRecord {
    exposure_id: ExposureId,
    observed_at_unix_secs: u64,
}

#[derive(Debug, Default)]
struct ConsumedBaitProofStore {
    path: Option<PathBuf>,
    consumed: HashMap<(SessionId, BaitId, [u8; 32]), u64>,
    migration_quarantine_until: Option<u64>,
    torn_tail_line: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConsumeProofOutcome {
    Fresh,
    Replay,
    CapacityExceeded,
    Unavailable,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredBaitExposureState {
    schema_version: u16,
    exposures: Vec<StoredBaitExposure>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredBaitExposure {
    session_id: SessionId,
    bait_id: BaitId,
    exposure_id: ExposureId,
    observed_at_unix_secs: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredConsumedProofState {
    schema_version: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    migration_quarantine_until: Option<u64>,
    consumed: Vec<StoredConsumedProof>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredConsumedProof {
    session_id: SessionId,
    bait_id: BaitId,
    proof_digest_hex: String,
    expires_at_unix_secs: u64,
}

fn state_path_for_event_log(event_log_path: &Path, suffix: &str) -> PathBuf {
    let mut path = event_log_path.as_os_str().to_os_string();
    path.push(suffix);
    PathBuf::from(path)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AtomicStateWriteOutcome {
    Durable,
    CommittedDurabilityUncertain,
}

fn atomic_state_write(path: &Path, value: &impl Serialize) -> io::Result<AtomicStateWriteOutcome> {
    atomic_state_write_with_parent_sync(path, value, sync_state_parent_directory)
}

fn atomic_state_write_with_parent_sync(
    path: &Path,
    value: &impl Serialize,
    sync_parent: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<AtomicStateWriteOutcome> {
    let serialized = serde_json::to_vec_pretty(value)
        .map_err(|error| invalid_data(format!("failed to serialize state: {error}")))?;
    let mut temp = path.as_os_str().to_os_string();
    temp.push(".tmp");
    let temp = PathBuf::from(temp);
    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temp)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(&serialized)?;
    file.flush()?;
    file.sync_all()?;
    fs::rename(temp, path)?;
    match sync_parent(path) {
        Ok(()) => Ok(AtomicStateWriteOutcome::Durable),
        Err(error) => {
            eprintln!(
                "eidolon persistence failure: state rename committed but parent directory sync failed for `{}`: {error}",
                path.display()
            );
            Ok(AtomicStateWriteOutcome::CommittedDurabilityUncertain)
        }
    }
}

fn sync_state_parent_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn proof_digest(proof_value: &str) -> [u8; 32] {
    Sha256::digest(proof_value.as_bytes()).into()
}

fn digest_hex(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn parse_digest_hex(value: &str) -> io::Result<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid_data(
            "consumed proof digest must contain exactly 64 hexadecimal characters",
        ));
    }
    let mut digest = [0_u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&value[start..start + 2], 16)
            .map_err(|_| invalid_data("consumed proof digest is invalid hexadecimal"))?;
    }
    Ok(digest)
}

fn event_log_history_exists(path: &Path) -> io::Result<bool> {
    if fs::metadata(path)
        .map(|metadata| metadata.len() > 0)
        .unwrap_or(false)
    {
        return Ok(true);
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let Some(base_name) = path.file_name().and_then(|name| name.to_str()) else {
        return Ok(false);
    };
    match fs::read_dir(parent) {
        Ok(entries) => Ok(entries
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter_map(|name| name.strip_prefix(base_name).map(str::to_string))
            .filter_map(|suffix| suffix.strip_prefix('.').map(str::to_string))
            .any(|suffix| !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit()))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

impl ConsumedBaitProofStore {
    fn open_or_rebuild(
        event_log_path: &Path,
        registry: &BaitRegistry,
        signing_secret: Option<&str>,
        now: u64,
    ) -> io::Result<Self> {
        let state_path = state_path_for_event_log(event_log_path, ".consumed-proofs.json");
        match fs::read(&state_path) {
            Ok(bytes) => Self::from_state_bytes(state_path, &bytes, now),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let history_exists = event_log_history_exists(event_log_path)?;
                let mut store =
                    Self::from_event_log(event_log_path, registry, signing_secret, now)?;
                store.path = Some(state_path);
                if history_exists {
                    store.migration_quarantine_until =
                        Some(now.saturating_add(MAX_BAIT_PROOF_TTL_SECS));
                }
                store.persist()?;
                Ok(store)
            }
            Err(error) => Err(error),
        }
    }

    fn from_state_bytes(path: PathBuf, bytes: &[u8], now: u64) -> io::Result<Self> {
        let stored: StoredConsumedProofState = serde_json::from_slice(bytes).map_err(|error| {
            invalid_data(format!(
                "failed to parse consumed proof state `{}`: {error}",
                path.display()
            ))
        })?;
        if stored.schema_version != CONSUMED_PROOF_STATE_SCHEMA_VERSION {
            return Err(invalid_data(format!(
                "unsupported consumed proof state schema version {}",
                stored.schema_version
            )));
        }
        let mut consumed = HashMap::new();
        for record in stored.consumed {
            if record.expires_at_unix_secs <= now {
                continue;
            }
            if record.expires_at_unix_secs.saturating_sub(now) > MAX_BAIT_PROOF_TTL_SECS {
                return Err(invalid_data(
                    "consumed proof state contains an expiry beyond the maximum proof lifetime",
                ));
            }
            let key = (
                record.session_id,
                record.bait_id,
                parse_digest_hex(&record.proof_digest_hex)?,
            );
            consumed
                .entry(key)
                .and_modify(|expiry: &mut u64| {
                    *expiry = (*expiry).max(record.expires_at_unix_secs);
                })
                .or_insert(record.expires_at_unix_secs);
            if consumed.len() > MAX_CONSUMED_BAIT_PROOFS {
                return Err(invalid_data(
                    "active consumed bait proof state exceeds configured capacity",
                ));
            }
        }
        let migration_quarantine_until = stored
            .migration_quarantine_until
            .filter(|until| *until > now);
        let store = Self {
            path: Some(path),
            consumed,
            migration_quarantine_until,
            torn_tail_line: None,
        };
        store.persist()?;
        Ok(store)
    }

    fn from_event_log(
        path: &Path,
        registry: &BaitRegistry,
        signing_secret: Option<&str>,
        now: u64,
    ) -> io::Result<Self> {
        let file = match fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => return Err(error),
        };
        let mut store = Self::default();
        let source = read_jsonl_reconstruction(BufReader::new(file))?;
        for (line_index, line) in source.lines.iter().enumerate() {
            let line_number = line_index + 1;
            if line.trim().is_empty() {
                continue;
            }
            let event: Event = match serde_json::from_str(line) {
                Ok(event) => event,
                Err(_error) if source.is_torn_tail(line_index) => {
                    store.torn_tail_line = Some(line_number);
                    eprintln!(
                        "eidolon startup: ignoring crash-torn event log tail at line {line_number}; reconstructed up to the tear"
                    );
                    break;
                }
                Err(error) => {
                    return Err(invalid_data(format!(
                        "could not rebuild consumed bait proof store from event log line {line_number}: {error}"
                    )))
                }
            };
            if event.schema_version != EVENT_SCHEMA_VERSION {
                return Err(invalid_data(format!(
                    "could not rebuild consumed bait proof store from event log line {}: unsupported schema version {}",
                    line_index + 1,
                    event.schema_version
                )));
            }
            let EventKind::BaitActionObserved {
                bait_id,
                header_value_mint_status,
                ..
            } = event.kind
            else {
                continue;
            };
            if !matches!(
                header_value_mint_status,
                Some(BaitHeaderValueMintStatus::MatchedSessionValue)
                    | Some(BaitHeaderValueMintStatus::ReplaySeen)
            ) {
                continue;
            }
            let Some(bait) = registry.baits().iter().find(|bait| bait.id == bait_id) else {
                continue;
            };
            let issued_at = u64::try_from(event.observed_at.timestamp()).unwrap_or_default();
            let rendered = eidolon_bait::render_bait_for_session_at(
                bait,
                event.session_id,
                signing_secret,
                issued_at,
            )
            .map_err(|error| invalid_data(error.to_string()))?;
            let Some(proof_value) = rendered.expected_action.header_value.clone() else {
                continue;
            };
            let expires_at = proof_expiry_epoch_seconds(bait, &proof_value)?;
            if expires_at <= now {
                continue;
            }
            let key = (event.session_id, bait_id, proof_digest(&proof_value));
            if let Some(existing_expiry) = store.consumed.get_mut(&key) {
                *existing_expiry = expires_at;
                continue;
            }
            if store.consumed.len() >= MAX_CONSUMED_BAIT_PROOFS {
                return Err(invalid_data(
                    "active consumed bait proof state exceeds configured capacity",
                ));
            }
            store.consumed.insert(key, expires_at);
        }
        Ok(store)
    }

    fn check_and_mark(
        &mut self,
        session_id: SessionId,
        bait_id: BaitId,
        proof_value: String,
        expires_at: u64,
        now: u64,
    ) -> ConsumeProofOutcome {
        self.check_and_mark_with_persist(
            session_id,
            bait_id,
            proof_value,
            expires_at,
            now,
            Self::persist,
        )
    }

    fn check_and_mark_with_persist(
        &mut self,
        session_id: SessionId,
        bait_id: BaitId,
        proof_value: String,
        expires_at: u64,
        now: u64,
        persist: impl FnOnce(&Self) -> io::Result<AtomicStateWriteOutcome>,
    ) -> ConsumeProofOutcome {
        if expires_at <= now || expires_at.saturating_sub(now) > MAX_BAIT_PROOF_TTL_SECS {
            return ConsumeProofOutcome::Unavailable;
        }
        let key = (session_id, bait_id, proof_digest(&proof_value));
        let mut next = self.consumed.clone();
        next.retain(|_, expiry| *expiry > now);
        if next.contains_key(&key) {
            self.consumed = next;
            return ConsumeProofOutcome::Replay;
        }
        if self
            .migration_quarantine_until
            .is_some_and(|until| until > now)
        {
            self.consumed = next;
            return ConsumeProofOutcome::Unavailable;
        }
        if next.len() >= MAX_CONSUMED_BAIT_PROOFS {
            self.consumed = next;
            return ConsumeProofOutcome::CapacityExceeded;
        }
        next.insert(key, expires_at);
        let previous = std::mem::replace(&mut self.consumed, next);
        let previous_quarantine = self.migration_quarantine_until.take();
        match persist(self) {
            Ok(AtomicStateWriteOutcome::Durable) => ConsumeProofOutcome::Fresh,
            Ok(AtomicStateWriteOutcome::CommittedDurabilityUncertain) => {
                ConsumeProofOutcome::Unavailable
            }
            Err(error) => {
                self.consumed = previous;
                self.migration_quarantine_until = previous_quarantine;
                eprintln!("eidolon persistence failure: consumed proof state: {error}");
                ConsumeProofOutcome::Unavailable
            }
        }
    }

    fn persist(&self) -> io::Result<AtomicStateWriteOutcome> {
        let Some(path) = &self.path else {
            return Ok(AtomicStateWriteOutcome::Durable);
        };
        let mut consumed: Vec<_> = self
            .consumed
            .iter()
            .map(
                |((session_id, bait_id, proof_digest), expires_at_unix_secs)| StoredConsumedProof {
                    session_id: *session_id,
                    bait_id: bait_id.clone(),
                    proof_digest_hex: digest_hex(proof_digest),
                    expires_at_unix_secs: *expires_at_unix_secs,
                },
            )
            .collect();
        consumed.sort_by(|left, right| {
            (
                left.expires_at_unix_secs,
                left.session_id.0,
                left.bait_id.0.as_str(),
                left.proof_digest_hex.as_str(),
            )
                .cmp(&(
                    right.expires_at_unix_secs,
                    right.session_id.0,
                    right.bait_id.0.as_str(),
                    right.proof_digest_hex.as_str(),
                ))
        });
        atomic_state_write(
            path,
            &StoredConsumedProofState {
                schema_version: CONSUMED_PROOF_STATE_SCHEMA_VERSION,
                migration_quarantine_until: self.migration_quarantine_until,
                consumed,
            },
        )
    }
}

fn proof_expiry_epoch_seconds(bait: &Bait, proof_value: &str) -> io::Result<u64> {
    let Some(mint) = bait.expected_action.header_value_mint.as_ref() else {
        return Err(invalid_data("proof expiry requested for static bait"));
    };
    let Some(window) = mint.proof_window_seconds else {
        return Err(invalid_data("minted proof has no configured lifetime"));
    };
    let prefix = format!("{}_w", mint.prefix);
    let bucket_hex = proof_value
        .strip_prefix(&prefix)
        .and_then(|value| value.split_once('_'))
        .map(|(bucket, _)| bucket)
        .ok_or_else(|| invalid_data("matched proof has malformed window"))?;
    let bucket = u64::from_str_radix(bucket_hex, 16)
        .map_err(|_| invalid_data("matched proof has invalid window"))?;
    bucket
        .checked_add(1)
        .and_then(|next| next.checked_mul(window))
        .ok_or_else(|| invalid_data("matched proof expiry overflowed"))
}

impl BaitExposureStore {
    fn open_or_rebuild(event_log_path: &Path, now: u64) -> io::Result<Self> {
        let state_path = state_path_for_event_log(event_log_path, ".exposures.json");
        match fs::read(&state_path) {
            Ok(bytes) => {
                let store = Self::from_state_bytes(state_path, &bytes, now)?;
                store.persist()?;
                Ok(store)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let mut store = Self::from_event_log_at(event_log_path, now)?;
                store.path = Some(state_path);
                store.persist()?;
                Ok(store)
            }
            Err(error) => Err(error),
        }
    }

    fn from_state_bytes(path: PathBuf, bytes: &[u8], now: u64) -> io::Result<Self> {
        let stored: StoredBaitExposureState = serde_json::from_slice(bytes).map_err(|error| {
            invalid_data(format!(
                "failed to parse bait exposure state `{}`: {error}",
                path.display()
            ))
        })?;
        if stored.schema_version != BAIT_EXPOSURE_STATE_SCHEMA_VERSION {
            return Err(invalid_data(format!(
                "unsupported bait exposure state schema version {}",
                stored.schema_version
            )));
        }
        let mut store = Self {
            path: None,
            ..Self::default()
        };
        let mut records = stored.exposures;
        records.sort_by_key(|record| (record.observed_at_unix_secs, record.session_id.0));
        for record in records {
            store.apply_record_exposure_at(
                record.session_id,
                record.bait_id,
                record.exposure_id,
                record.observed_at_unix_secs,
                now,
            );
        }
        store.path = Some(path);
        Ok(store)
    }

    #[cfg(test)]
    fn from_event_log(path: &Path) -> io::Result<Self> {
        Self::from_event_log_at(path, current_unix_secs())
    }

    fn from_event_log_at(path: &Path, now: u64) -> io::Result<Self> {
        let file = match fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => return Err(error),
        };

        Self::from_event_log_reader_at(BufReader::new(file), now)
    }

    #[cfg(test)]
    fn from_event_log_reader(reader: impl BufRead) -> io::Result<Self> {
        Self::from_event_log_reader_at(reader, current_unix_secs())
    }

    fn from_event_log_reader_at(reader: impl BufRead, now: u64) -> io::Result<Self> {
        let source = read_jsonl_reconstruction(reader)?;
        let mut store = Self::default();
        let mut torn_tail_line = None;

        for (line_index, line) in source.lines.iter().enumerate() {
            let line_number = line_index + 1;
            if line.trim().is_empty() {
                continue;
            }

            let value: Value = match serde_json::from_str(line) {
                Ok(value) => value,
                Err(_error) if source.is_torn_tail(line_index) => {
                    torn_tail_line = Some(line_number);
                    eprintln!(
                        "eidolon startup: ignoring crash-torn event log tail at line {line_number}; reconstructed up to the tear"
                    );
                    break;
                }
                Err(error) => {
                    return Err(invalid_data(format!(
                        "could not rebuild bait exposure store from event log line {line_number}: {error}"
                    )))
                }
            };
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
                let observed_at_unix_secs =
                    u64::try_from(event.observed_at.timestamp()).unwrap_or_default();
                store.apply_record_exposure_at(
                    event.session_id,
                    bait_id,
                    exposure_id,
                    observed_at_unix_secs,
                    now,
                );
            }
        }

        store.torn_tail_line = torn_tail_line;
        Ok(store)
    }

    fn len(&self) -> usize {
        self.exposures.len()
    }

    #[cfg(test)]
    fn record_exposure(
        &mut self,
        session_id: SessionId,
        bait_id: BaitId,
        exposure_id: ExposureId,
    ) -> io::Result<()> {
        let now = current_unix_secs();
        self.record_exposure_at(session_id, bait_id, exposure_id, now, now)
    }

    fn record_exposure_at(
        &mut self,
        session_id: SessionId,
        bait_id: BaitId,
        exposure_id: ExposureId,
        observed_at_unix_secs: u64,
        now: u64,
    ) -> io::Result<()> {
        self.record_exposure_at_with_persist(
            session_id,
            bait_id,
            exposure_id,
            observed_at_unix_secs,
            now,
            Self::persist,
        )
    }

    fn record_exposure_at_with_persist(
        &mut self,
        session_id: SessionId,
        bait_id: BaitId,
        exposure_id: ExposureId,
        observed_at_unix_secs: u64,
        now: u64,
        persist: impl FnOnce(&Self) -> io::Result<AtomicStateWriteOutcome>,
    ) -> io::Result<()> {
        let previous_exposures = self.exposures.clone();
        let previous_order = self.exposure_order.clone();
        let previous_ttl_evicted = self.ttl_evicted;
        self.apply_record_exposure_at(session_id, bait_id, exposure_id, observed_at_unix_secs, now);
        match persist(self) {
            Ok(
                AtomicStateWriteOutcome::Durable
                | AtomicStateWriteOutcome::CommittedDurabilityUncertain,
            ) => Ok(()),
            Err(error) => {
                self.exposures = previous_exposures;
                self.exposure_order = previous_order;
                self.ttl_evicted = previous_ttl_evicted;
                eprintln!("eidolon persistence failure: bait exposure state: {error}");
                Err(error)
            }
        }
    }

    fn apply_record_exposure_at(
        &mut self,
        session_id: SessionId,
        bait_id: BaitId,
        exposure_id: ExposureId,
        observed_at_unix_secs: u64,
        now: u64,
    ) {
        self.prune_expired(now);
        if observed_at_unix_secs.saturating_add(BAIT_EXPOSURE_TTL_SECS) <= now {
            self.ttl_evicted += 1;
            return;
        }

        let key = (session_id, bait_id);
        if self
            .exposures
            .get(&key)
            .is_some_and(|existing| existing.observed_at_unix_secs > observed_at_unix_secs)
        {
            return;
        }
        if self
            .exposures
            .insert(
                key.clone(),
                BaitExposureRecord {
                    exposure_id,
                    observed_at_unix_secs,
                },
            )
            .is_some()
        {
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
        self.exposure_for_action_at(session_id, bait_id, current_unix_secs())
    }

    fn exposure_for_action_at(
        &self,
        session_id: SessionId,
        bait_id: &BaitId,
        now: u64,
    ) -> Option<ExposureId> {
        self.exposures
            .get(&(session_id, bait_id.clone()))
            .filter(|record| {
                record
                    .observed_at_unix_secs
                    .saturating_add(BAIT_EXPOSURE_TTL_SECS)
                    > now
            })
            .map(|record| record.exposure_id.clone())
    }

    fn prune_expired(&mut self, now: u64) {
        let before = self.exposures.len();
        self.exposures.retain(|_, record| {
            record
                .observed_at_unix_secs
                .saturating_add(BAIT_EXPOSURE_TTL_SECS)
                > now
        });
        self.ttl_evicted += before - self.exposures.len();
        self.exposure_order
            .retain(|key| self.exposures.contains_key(key));
    }

    fn persist(&self) -> io::Result<AtomicStateWriteOutcome> {
        let Some(path) = &self.path else {
            return Ok(AtomicStateWriteOutcome::Durable);
        };
        let mut exposures: Vec<_> = self
            .exposures
            .iter()
            .map(|((session_id, bait_id), record)| StoredBaitExposure {
                session_id: *session_id,
                bait_id: bait_id.clone(),
                exposure_id: record.exposure_id.clone(),
                observed_at_unix_secs: record.observed_at_unix_secs,
            })
            .collect();
        exposures.sort_by(|left, right| {
            (
                left.observed_at_unix_secs,
                left.session_id.0,
                left.bait_id.0.as_str(),
            )
                .cmp(&(
                    right.observed_at_unix_secs,
                    right.session_id.0,
                    right.bait_id.0.as_str(),
                ))
        });
        atomic_state_write(
            path,
            &StoredBaitExposureState {
                schema_version: BAIT_EXPOSURE_STATE_SCHEMA_VERSION,
                exposures,
            },
        )
    }
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
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
        if matches!(self.status, Some(status) if !(200..600).contains(&status)) {
            return Err(ConfigError::new(format!(
                "content.surfaces.{bait_id}.status must be a final HTTP status code (200-599)"
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
    validate_action_path("bait.expected_action.path", &bait.expected_action.path)?;
    validate_optional_non_empty(
        "bait.expected_action.header_name",
        bait.expected_action.header_name.as_deref(),
    )?;
    validate_optional_non_empty(
        "bait.expected_action.header_value",
        bait.expected_action.header_value.as_deref(),
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
    validate_optional_header_value_mint(
        "bait.expected_action.header_value_mint",
        bait.expected_action.header_value_mint.as_ref(),
    )?;

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
    if mint.proof_window_seconds.is_none() {
        return Err(ConfigError::new(format!(
            "{label}.proof_window_seconds is required"
        )));
    }
    if mint.proof_window_seconds == Some(0) {
        return Err(ConfigError::new(format!(
            "{label}.proof_window_seconds must be greater than zero"
        )));
    }
    if mint
        .proof_window_seconds
        .is_some_and(|window| window > MAX_BAIT_PROOF_TTL_SECS)
    {
        return Err(ConfigError::new(format!(
            "{label}.proof_window_seconds must not exceed {MAX_BAIT_PROOF_TTL_SECS}"
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

fn validate_action_path(label: &str, value: &str) -> Result<(), ConfigError> {
    validate_path(label, value)?;
    if value.contains('?') || value.contains('#') {
        return Err(ConfigError::new(format!(
            "{label} must be a canonical path-only value without a query string or fragment"
        )));
    }
    let canonical = request_evaluation::canonical_action_route_path(value).map_err(|reason| {
        ConfigError::new(format!(
            "{label} must be a canonical path-only value: {reason}"
        ))
    })?;
    if canonical != value {
        return Err(ConfigError::new(format!(
            "{label} must be a canonical path-only value without percent-encoded bytes"
        )));
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

            let cache_policy = generated_openapi_cache_policy(&bait, &self.content.openapi);
            return Ok(SurfaceAction::RewrittenUpstream {
                plan: RewritePlan::openapi_paths(vec![openapi_path_insertion_for_bait(
                    &bait,
                    &self.content.openapi,
                )])
                .with_cache_policy(cache_policy),
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

    let response = match bait.bait_class {
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
    };

    if bait.bait_class != BaitClass::OpenApi && bait.header_value_mint_audit().is_some() {
        response.with_cache_policy(ResponseCachePolicy::PrivateNoStore)
    } else {
        response
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
    let cache_policy = generated_openapi_cache_policy(bait, openapi);
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
        )
        .with_cache_policy(cache_policy),
        Err(_) => surface_text_response(500, "failed to render owned openapi discovery response\n"),
    }
}

fn generated_openapi_cache_policy(
    bait: &Bait,
    openapi: &OpenApiOperationOverride,
) -> ResponseCachePolicy {
    if openapi.path_item.is_none() && bait.header_value_mint_audit().is_some() {
        ResponseCachePolicy::PrivateNoStore
    } else {
        ResponseCachePolicy::Preserve
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

fn is_rewriteable_response_status(status: u16) -> bool {
    status == 200
}

fn handle_connection(
    mut client_stream: TcpStream,
    runtime: &ProxyRuntime,
    _permit: ConnectionPermit,
) -> io::Result<()> {
    configure_client_stream(&client_stream)?;

    let client_peer_addr = client_stream.peer_addr().ok();
    let client_peer = client_peer_addr.as_ref().map(ToString::to_string);
    let client_peer_ip = client_peer_addr.map(|addr| addr.ip());
    let request = {
        let mut reader =
            DeadlineTcpReader::new(&mut client_stream, runtime.client_request_deadline);
        read_http_request(&mut reader)?
    };
    let Some(request) = request else {
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
    reconcile_all_pending_controlled_reality_interactions(runtime)?;

    let intervention_mode = intervention_mode_from_control_file(&runtime.intervention_control_path);
    let path = match normalized_event_path(&request) {
        Ok(path) => path,
        Err(error) => {
            // #212: ambiguous request targets are rejected with an audited
            // 400 before any policy evaluation, recon accounting, or upstream
            // forwarding. A fixed placeholder prevents the rejected spelling
            // itself from leaking attacker-controlled data into evidence.
            let request_id = RequestId::new();
            let surface_request = surface_request_meta(&request, REJECTED_REQUEST_TARGET);
            let session = match effective_session_context(
                runtime,
                &request,
                &surface_request,
                client_peer_ip,
                request_id,
            ) {
                Ok(session) => session,
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                    return write_session_continuity_rejection(&mut client_stream, &request.method);
                }
                Err(error) => return Err(error),
            };
            write_debug(
                runtime,
                "ambiguous_request_target_rejected",
                Some(session.session_id),
                json!({
                    "request_id": request_id.0,
                    "method": request.method.as_str(),
                    "error": error.to_string(),
                }),
            )?;
            let decision = policy::PolicyDecision::new(
                policy_state_for_session(runtime, session.session_id)?,
                RoutingDecision::EidolonOwned,
                "ambiguous HTTP request target rejected before policy evaluation",
            );
            return write_direct_response(DirectResponseContext {
                client_stream,
                runtime,
                session: &session,
                request: &request,
                path: REJECTED_REQUEST_TARGET,
                request_id,
                decision: &decision,
                discovery_recon_score: policy::DiscoveryReconAggregationScore::default(),
                discovery_recon_threshold: policy::discovery_recon_aggregation_score_threshold(),
                response: surface_text_response(400, "ambiguous request target\n"),
                controlled_reality_interaction: None,
                controlled_reality_pending_commit: false,
                intervention_mode,
                surface_requested_intervention: true,
            });
        }
    };
    let surface_request = surface_request_meta(&request, &path);
    let request_id = RequestId::new();
    let session = match effective_session_context(
        runtime,
        &request,
        &surface_request,
        client_peer_ip,
        request_id,
    ) {
        Ok(session) => session,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            return write_session_continuity_rejection(&mut client_stream, &request.method);
        }
        Err(error) => return Err(error),
    };
    let (mut policy_state, capacity_fail_closed) =
        policy_state_resolution_for_session(runtime, session.session_id)?;
    if capacity_fail_closed {
        write_debug(
            runtime,
            "policy_capacity_fail_closed",
            Some(session.session_id),
            json!({
                "request_id": request_id.0,
                "policy_state": policy_state,
                "max_sessions": eidolon_proxy::policy_store::MAX_POLICY_SESSIONS,
            }),
        )?;
        let decision = policy::PolicyDecision::new(
            PolicyState::Blocked,
            RoutingDecision::EidolonOwned,
            "policy state capacity saturated; unknown session failed closed",
        );
        return write_direct_response(DirectResponseContext {
            client_stream,
            runtime,
            session: &session,
            request: &request,
            path: &path,
            request_id,
            decision: &decision,
            discovery_recon_score: policy::DiscoveryReconAggregationScore::default(),
            discovery_recon_threshold: policy::discovery_recon_aggregation_score_threshold(),
            response: surface_text_response(503, "service temporarily unavailable\n"),
            controlled_reality_interaction: None,
            controlled_reality_pending_commit: false,
            intervention_mode,
            surface_requested_intervention: true,
        });
    }
    if let Some(floor) = session.enforcement_floor {
        if enforcement_rank(floor) > enforcement_rank(policy_state) {
            write_debug(
                runtime,
                "session_enforcement_floor_applied",
                Some(session.session_id),
                json!({
                    "loaded_policy_state": policy_state,
                    "enforcement_floor": floor,
                }),
            )?;
            set_policy_state_for_session(runtime, session.session_id, floor)?;
            policy_state = floor;
        }
    }
    note_session_enforcement(runtime, &session, policy_state);
    let request_facts =
        request_evaluation::classify_request(request_evaluation::RequestClassificationInput {
            bait_registry: &runtime.bait_registry,
            request: &surface_request,
            session_id: session.session_id,
            bait_signing_secret: runtime.bait_signing_secret.as_deref(),
            docs_discovery_target: DOCS_DISCOVERY_TARGET,
            canonical_openapi_discovery_target: OPENAPI_DISCOVERY_TARGET,
            legacy_openapi_query: LEGACY_IMPORT_OPENAPI_QUERY,
        });
    let discovery_recon_state = update_discovery_recon_state_for_request(
        runtime,
        session.session_id,
        &surface_request,
        request_facts,
    )?;
    let evaluation = request_evaluation::evaluate_request(RequestEvaluationInput {
        starting_policy_state: policy_state,
        intervention_mode,
        path: &surface_request.path,
        trusted_bait_soften_path_prefixes: &runtime.trusted_bait_soften_path_prefixes,
        ingress_identity: &session.ingress_identity,
        ingress_signals: &session.ingress_signals,
        discovery_recon_state,
        request_facts,
    });
    for transition in &evaluation.transitions {
        apply_policy_transition(runtime, &session, request_id, transition)?;
    }
    policy_state = evaluation.decision.policy_state;
    let discovery_recon_score = evaluation.discovery_recon_score;
    let discovery_recon_threshold = evaluation.discovery_recon_threshold;
    let decision = evaluation.decision;
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
            "authenticated_ingress_rule_rejection":
                &session.authenticated_ingress_rule_rejection,
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

    if is_controlled_follow_up_path(&surface_request.path)
        && (!intervention_mode.interventions_enabled()
            || decision.routing_decision == RoutingDecision::ProtectedUpstream)
    {
        let response = runtime.controlled_reality.fail_closed_follow_up_response();
        let follow_up_decision = policy::PolicyDecision::new(
            decision.policy_state,
            RoutingDecision::EidolonOwned,
            "synthetic controlled-reality follow-up namespace failed closed",
        );
        return write_direct_response(DirectResponseContext {
            client_stream,
            runtime,
            session: &session,
            request: &request,
            path: &path,
            request_id,
            decision: &follow_up_decision,
            discovery_recon_score,
            discovery_recon_threshold,
            response,
            controlled_reality_interaction: None,
            controlled_reality_pending_commit: false,
            intervention_mode,
            surface_requested_intervention: true,
        });
    }

    if !intervention_mode.interventions_enabled()
        && request_facts.owns_configured_unsafe_bait_action
    {
        let response = runtime
            .controlled_reality
            .fail_closed_bait_action_response(&surface_request);
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
        let decision =
            request_evaluation::interventions_disabled_bait_action_decision(policy_state);

        return write_direct_response(DirectResponseContext {
            client_stream,
            runtime,
            session: &session,
            request: &request,
            path: &path,
            request_id,
            decision: &decision,
            discovery_recon_score,
            discovery_recon_threshold,
            response,
            controlled_reality_interaction: None,
            controlled_reality_pending_commit: false,
            intervention_mode,
            surface_requested_intervention: true,
        });
    }

    let mut controlled_reality_interaction = None;
    let mut controlled_reality_pending_commit = false;
    let mut _controlled_reality_workflow_guard = None;
    let controller_surface_action = match request_evaluation::initial_route_plan(
        &decision,
        intervention_mode,
    ) {
        request_evaluation::InitialRoutePlan::ProtectedUpstream => SurfaceAction::ProtectedUpstream,
        request_evaluation::InitialRoutePlan::SurfaceController => runtime
            .surface_controller
            .decide(&surface_request, session.session_id)?,
        request_evaluation::InitialRoutePlan::ControlledReality => {
            _controlled_reality_workflow_guard = Some(
                runtime
                    .controlled_reality_workflow_locks
                    .lock(session.session_id)?,
            );
            let (action, transition, interaction, pending_commit) = controlled_reality_action(
                runtime,
                session.session_id,
                request_id,
                &surface_request,
                decision.reason.clone(),
            )?;
            controlled_reality_pending_commit = pending_commit;
            if let Some(transition) = transition {
                stage_controlled_reality_policy_transition(
                    runtime,
                    session.session_id,
                    request_id,
                    &transition,
                )?;
                let blocked_decision = transition.decision(action.routing_decision());
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
                    request_id,
                    decision: &blocked_decision,
                    discovery_recon_score,
                    discovery_recon_threshold,
                    response,
                    controlled_reality_interaction: None,
                    controlled_reality_pending_commit,
                    intervention_mode,
                    surface_requested_intervention: true,
                });
            }
            controlled_reality_interaction = interaction;
            action
        }
        request_evaluation::InitialRoutePlan::RateLimited => SurfaceAction::RateLimited {
            reason: decision.reason.clone(),
            response: rate_limited_response(runtime.controlled_reality_config.retry_after_seconds),
        },
        request_evaluation::InitialRoutePlan::Blocked => SurfaceAction::EidolonOwned {
            response: surface_text_response(403, "blocked by eidolon policy\n"),
        },
        request_evaluation::InitialRoutePlan::InvalidRewrittenUpstream => {
            return Err(invalid_data(
                "policy requested rewritten upstream without a surface rewrite plan",
            ));
        }
    };
    let suspicious_discovery_plan = request_evaluation::suspicious_discovery_plan(
        decision.policy_state,
        &controller_surface_action,
        request_facts,
    );
    let candidate_surface_action = render_suspicious_discovery_action(
        runtime,
        session.session_id,
        controller_surface_action.clone(),
        suspicious_discovery_plan,
    )?;
    let surface_evaluation =
        request_evaluation::evaluate_surface(request_evaluation::SurfaceEvaluationInput {
            policy_decision: &decision,
            candidate_action: candidate_surface_action.clone(),
            trusted_bait_soften_path_prefixes: &runtime.trusted_bait_soften_path_prefixes,
            local_trusted_bait_soften_path_prefixes: session
                .trusted_bait_soften_path_prefixes
                .as_deref(),
            ingress_identity: &session.ingress_identity,
            request_method: &surface_request.method,
            request_path: &surface_request.path,
        });
    let surface_action = surface_evaluation.action;
    let trusted_ingress_softening_reason = surface_evaluation.trusted_ingress_softening_reason;
    let mut effective_decision = surface_evaluation.decision;
    let surface_requested_intervention = surface_evaluation.requested_intervention;
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
        request_id,
        &effective_decision,
    )? {
        stage_controlled_reality_policy_transition(
            runtime,
            session.session_id,
            request_id,
            &transition,
        )?;
        let blocked_decision = transition.decision(RoutingDecision::EidolonOwned);
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
            request_id,
            decision: &blocked_decision,
            discovery_recon_score,
            discovery_recon_threshold,
            response: blocked_response,
            controlled_reality_interaction: None,
            controlled_reality_pending_commit,
            intervention_mode,
            surface_requested_intervention: true,
        });
    }

    if intervention_mode.interventions_enabled()
        && (request_evaluation::surface_action_can_reach_upstream(&surface_action)
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
            let mut mint_status = action_match.header_value_mint_status;
            if mint_status == Some(BaitHeaderValueMintStatus::MatchedSessionValue) {
                let proof_value = action_match
                    .bait
                    .expected_action
                    .header_name
                    .as_deref()
                    .and_then(|name| {
                        request
                            .headers
                            .iter()
                            .find(|header| header.name.eq_ignore_ascii_case(name))
                    })
                    .map(|header| header.value.clone())
                    .ok_or_else(|| invalid_data("matched minted proof had no header value"))?;
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let expires_at = proof_expiry_epoch_seconds(&action_match.bait, &proof_value)?;
                let outcome = runtime
                    .consumed_bait_proofs
                    .lock()
                    .map_err(|_| io::Error::other("consumed bait proof store lock poisoned"))?
                    .check_and_mark(
                        session.session_id,
                        action_match.bait.id.clone(),
                        proof_value,
                        expires_at,
                        now,
                    );
                mint_status = Some(match outcome {
                    ConsumeProofOutcome::Fresh => BaitHeaderValueMintStatus::MatchedSessionValue,
                    ConsumeProofOutcome::Replay => BaitHeaderValueMintStatus::ReplaySeen,
                    ConsumeProofOutcome::CapacityExceeded => {
                        BaitHeaderValueMintStatus::ReplayStateCapacityExceeded
                    }
                    ConsumeProofOutcome::Unavailable => {
                        BaitHeaderValueMintStatus::ReplayStateUnavailable
                    }
                });
            }
            let proof_accepted = matches!(
                mint_status,
                None | Some(BaitHeaderValueMintStatus::MatchedSessionValue)
            );
            effective_decision =
                request_evaluation::bait_action_interception_decision(&decision, proof_accepted);
            write_event(
                &runtime.event_log,
                &request_seen_event(
                    &request,
                    &path,
                    &session,
                    request_id,
                    &effective_decision,
                    discovery_recon_score,
                    discovery_recon_threshold,
                ),
            )?;
            let action_exposure_id = write_bait_action_observed_event(
                runtime,
                &session,
                request_id,
                decision.policy_state,
                &action_match.bait,
                &request.method,
                &surface_request.path,
                mint_status,
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
                    "header_value_mint_status": mint_status.map(|status| format!("{status:?}")),
                }),
            )?;

            let mut response_interaction = None;
            let mut response_pending_commit = false;
            let mut _response_workflow_guard = None;
            let mut response = if !proof_accepted {
                write_event(
                    &runtime.event_log,
                    &policy::policy_intervention_event(
                        session.session_id,
                        request_id,
                        &effective_decision,
                    ),
                )?;
                surface_response_to_http(
                    runtime
                        .controlled_reality
                        .fail_closed_bait_action_response(&surface_request),
                )
            } else if let Some(transition) = request_evaluation::correlated_bait_action_transition(
                decision.policy_state,
                proof_accepted,
                action_exposure_id.is_some(),
            ) {
                apply_policy_transition(runtime, &session, request_id, &transition)?;
                _response_workflow_guard = Some(
                    runtime
                        .controlled_reality_workflow_locks
                        .lock(session.session_id)?,
                );
                let (action, controlled_transition, interaction, pending_commit) =
                    controlled_reality_action(
                        runtime,
                        session.session_id,
                        request_id,
                        &surface_request,
                        transition.reason.clone(),
                    )?;
                response_interaction = interaction;
                response_pending_commit = pending_commit;
                effective_decision = if let Some(controlled_transition) = controlled_transition {
                    stage_controlled_reality_policy_transition(
                        runtime,
                        session.session_id,
                        request_id,
                        &controlled_transition,
                    )?;
                    controlled_transition.decision(action.routing_decision())
                } else {
                    request_evaluation::direct_surface_decision(
                        transition.to,
                        &action,
                        transition.reason,
                        transition.persistence,
                    )
                };
                write_event(
                    &runtime.event_log,
                    &policy::policy_intervention_event(
                        session.session_id,
                        request_id,
                        &effective_decision,
                    ),
                )?;
                direct_surface_response(action)
                    .expect("controlled reality action should produce direct response")
            } else {
                write_event(
                    &runtime.event_log,
                    &policy::policy_intervention_event(
                        session.session_id,
                        request_id,
                        &effective_decision,
                    ),
                )?;
                bait_action_synthetic_response()
            };
            apply_response_headers(&mut response, &session, &request.method);
            write_controlled_reality_response_event(
                runtime,
                &policy::response_audit_event_with_controlled_reality(
                    session.session_id,
                    request_id,
                    &effective_decision,
                    response.status,
                    response_interaction,
                ),
                response_pending_commit,
            )?;
            commit_controlled_reality_interaction(
                runtime,
                &session,
                request_id,
                response_pending_commit,
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

            client_stream.write_all(&response.to_http_bytes_for_method(&request.method))?;
            return client_stream.flush();
        }
    }

    if intervention_mode.interventions_enabled()
        && request_evaluation::surface_action_can_reach_upstream(&surface_action)
    {
        if let Some(action_shape_match) = runtime.bait_registry.match_action_shape(
            &request.method,
            &surface_request.path,
            header_pairs(&request.headers),
        ) {
            let prior_same_bait_exposure = write_bait_action_near_miss_event(
                runtime,
                &session,
                request_id,
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

            if let Some(transition) = request_evaluation::same_bait_near_miss_transition(
                decision.policy_state,
                &surface_request.path,
                &action_shape_match.bait.id,
                prior_same_bait_exposure,
            ) {
                apply_policy_transition(runtime, &session, request_id, &transition)?;
                let response =
                    rate_limited_response(runtime.controlled_reality_config.retry_after_seconds);
                let action = SurfaceAction::RateLimited {
                    reason: transition.reason.clone(),
                    response: response.clone(),
                };
                effective_decision = request_evaluation::direct_surface_decision(
                    transition.to,
                    &action,
                    transition.reason,
                    transition.persistence,
                );
                return write_direct_response(DirectResponseContext {
                    client_stream,
                    runtime,
                    session: &session,
                    request: &request,
                    path: &path,
                    request_id,
                    decision: &effective_decision,
                    discovery_recon_score,
                    discovery_recon_threshold,
                    response,
                    controlled_reality_interaction: None,
                    controlled_reality_pending_commit,
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
                request_id,
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

            if let Some(transition) = request_evaluation::same_bait_near_miss_transition(
                decision.policy_state,
                &surface_request.path,
                &action_shape_match.bait.id,
                prior_same_bait_exposure,
            ) {
                apply_policy_transition(runtime, &session, request_id, &transition)?;
                effective_decision = transition.decision(RoutingDecision::EidolonOwned);
                return write_direct_response(DirectResponseContext {
                    client_stream,
                    runtime,
                    session: &session,
                    request: &request,
                    path: &path,
                    request_id,
                    decision: &effective_decision,
                    discovery_recon_score,
                    discovery_recon_threshold,
                    response: surface_text_response(403, "blocked by eidolon policy\n"),
                    controlled_reality_interaction: None,
                    controlled_reality_pending_commit,
                    intervention_mode,
                    surface_requested_intervention: true,
                });
            }
        }
    }

    if request_facts.owns_configured_unsafe_bait_action
        && request_evaluation::surface_action_can_reach_upstream(&surface_action)
    {
        let rejected_decision =
            request_evaluation::fail_closed_unsafe_bait_action_decision(&decision);
        write_debug(
            runtime,
            "bait_action_rejected_fail_closed",
            Some(session.session_id),
            json!({
                "method": request.method.as_str(),
                "path": debug_path(&surface_request.path),
                "query_present": surface_request.query.is_some(),
                "response_status": 403,
            }),
        )?;
        return write_direct_response(DirectResponseContext {
            client_stream,
            runtime,
            session: &session,
            request: &request,
            path: &path,
            request_id,
            decision: &rejected_decision,
            discovery_recon_score,
            discovery_recon_threshold,
            response: runtime
                .controlled_reality
                .fail_closed_bait_action_response(&surface_request),
            controlled_reality_interaction: None,
            controlled_reality_pending_commit,
            intervention_mode,
            surface_requested_intervention: true,
        });
    }

    if let Some(mut response) = direct_surface_response(surface_action.clone()) {
        effective_decision = request_evaluation::direct_surface_decision(
            decision.policy_state,
            &surface_action,
            decision.reason.clone(),
            decision.persistence,
        );
        write_request_and_policy_events(
            runtime,
            &request_seen_event(
                &request,
                &path,
                &session,
                request_id,
                &effective_decision,
                discovery_recon_score,
                discovery_recon_threshold,
            ),
            request_id,
            &effective_decision,
            intervention_mode,
            surface_requested_intervention,
        )?;
        apply_response_headers(&mut response, &session, &request.method);
        if let Some(bait) = bait_exposure_for_direct_surface(
            &decision,
            &surface_action,
            &surface_request,
            &runtime.bait_registry,
        ) {
            write_bait_exposed_event(
                runtime,
                &session,
                request_id,
                decision.policy_state,
                bait,
                surface_request.path.clone(),
            )?;
        }
        write_controlled_reality_response_event(
            runtime,
            &policy::response_audit_event_with_controlled_reality(
                session.session_id,
                request_id,
                &effective_decision,
                response.status,
                controlled_reality_interaction,
            ),
            controlled_reality_pending_commit,
        )?;
        commit_controlled_reality_interaction(
            runtime,
            &session,
            request_id,
            controlled_reality_pending_commit,
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

        client_stream.write_all(&response.to_http_bytes_for_method(&request.method))?;
        return client_stream.flush();
    }

    let upstream_request_decision = request_evaluation::upstream_request_decision(
        decision.policy_state,
        &surface_action,
        effective_decision.reason.clone(),
        effective_decision.persistence,
    );
    write_event(
        &runtime.event_log,
        &request_seen_event(
            &request,
            &path,
            &session,
            request_id,
            &upstream_request_decision,
            discovery_recon_score,
            discovery_recon_threshold,
        ),
    )?;
    if intervention_mode == InterventionMode::Disabled {
        write_event(
            &runtime.event_log,
            &policy::policy_intervention_event(
                session.session_id,
                request_id,
                &upstream_request_decision,
            ),
        )?;
    }

    let upstream_cache_policy = match &surface_action {
        SurfaceAction::RewrittenUpstream { plan } => plan.cache_policy,
        _ => ResponseCachePolicy::Preserve,
    };
    let mut upstream_request_source = request.clone();
    let stripped_cache_request_headers =
        if upstream_cache_policy == ResponseCachePolicy::PrivateNoStore {
            strip_session_proof_cache_request_headers(&mut upstream_request_source)
        } else {
            0
        };
    let upstream_request = request_to_upstream_bytes(&upstream_request_source, &runtime.upstream)?;
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
            "session_proof_cache_request_headers_stripped": stripped_cache_request_headers,
        }),
    )?;
    let mut upstream_stream = connect_upstream(&runtime.upstream)?;
    upstream_stream.write_all(&upstream_request)?;
    upstream_stream.flush()?;

    let mut response = read_http_response_for_method(&mut upstream_stream, &request.method)?;
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
        if is_rewriteable_response_status(response.status) {
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
                response.cache_policy = plan.cache_policy;
                effective_decision = request_evaluation::rewrite_response_decision(
                    &effective_decision,
                    request_evaluation::RewriteEvaluation::Rewritten,
                );
                if let Some(bait) = runtime.bait_registry.bait_for_class(BaitClass::OpenApi) {
                    if is_openapi_discovery_request(&surface_request, bait) {
                        pending_bait_exposure =
                            Some((bait.clone(), surface_request.target.clone()));
                    }
                }
            } else if let Some(refusal) = outcome.refusal() {
                effective_decision = request_evaluation::rewrite_response_decision(
                    &effective_decision,
                    request_evaluation::RewriteEvaluation::Refused(refusal.to_string()),
                );
            } else {
                effective_decision = request_evaluation::rewrite_response_decision(
                    &effective_decision,
                    request_evaluation::RewriteEvaluation::Unchanged,
                );
            }
            response.body = outcome.into_body();
        } else {
            write_debug(
                runtime,
                "surface_rewrite_skipped",
                Some(session.session_id),
                json!({
                    "reason": "non_200_upstream_response",
                    "status": response.status,
                    "plan": debug_rewrite_plan(&plan),
                }),
            )?;
            effective_decision = request_evaluation::rewrite_response_decision(
                &effective_decision,
                request_evaluation::RewriteEvaluation::SkippedNonSuccess,
            );
        }
    }
    apply_response_headers(&mut response, &session, &request.method);

    if surface_requested_intervention {
        write_event(
            &runtime.event_log,
            &policy::policy_intervention_event(session.session_id, request_id, &effective_decision),
        )?;
    }
    if let Some((bait, surface)) = pending_bait_exposure {
        write_bait_exposed_event(
            runtime,
            &session,
            request_id,
            decision.policy_state,
            &bait,
            surface,
        )?;
    }
    write_event(
        &runtime.event_log,
        &policy::response_audit_event(
            session.session_id,
            request_id,
            &effective_decision,
            response.status,
        ),
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

    client_stream.write_all(&response.to_http_bytes_for_method(&request.method))?;
    client_stream.flush()
}

fn maybe_transition_to_blocked_from_reality_escape_attempt(
    runtime: &ProxyRuntime,
    session: &SessionContext,
    request: &HttpRequest,
    surface_request: &SurfaceRequestMeta,
    request_id: RequestId,
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
            request_id,
            decision.policy_state,
            request.method.clone(),
            redacted_event_target(&surface_request.path),
            decision.routing_decision,
            "controlled session requested a path outside the configured controlled-reality branch",
        ),
    )?;

    Ok(request_evaluation::reality_escape_transition(
        decision.policy_state,
        &surface_request.path,
        attempt_count,
    ))
}

fn write_session_continuity_rejection(
    client_stream: &mut TcpStream,
    request_method: &str,
) -> io::Result<()> {
    let mut response =
        surface_response_to_http(surface_text_response(400, "invalid ingress continuity\n"));
    response.set_header("Connection", "close");
    response.set_header("Content-Length", response.body.len().to_string());
    client_stream.write_all(&response.to_http_bytes_for_method(request_method))?;
    client_stream.flush()
}

struct DirectResponseContext<'a> {
    client_stream: TcpStream,
    runtime: &'a ProxyRuntime,
    session: &'a SessionContext,
    request: &'a HttpRequest,
    path: &'a str,
    request_id: RequestId,
    decision: &'a policy::PolicyDecision,
    discovery_recon_score: policy::DiscoveryReconAggregationScore,
    discovery_recon_threshold: u8,
    response: SurfaceResponse,
    controlled_reality_interaction: Option<ControlledRealityInteraction>,
    controlled_reality_pending_commit: bool,
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
        request_id,
        decision,
        discovery_recon_score,
        discovery_recon_threshold,
        response,
        controlled_reality_interaction,
        controlled_reality_pending_commit,
        intervention_mode,
        surface_requested_intervention,
    } = context;

    write_direct_response_request_audit(
        runtime,
        session,
        request,
        path,
        request_id,
        decision,
        discovery_recon_score,
        discovery_recon_threshold,
        controlled_reality_pending_commit,
        intervention_mode,
        surface_requested_intervention,
    )?;

    let mut response = surface_response_to_http(response);
    apply_response_headers(&mut response, session, &request.method);
    write_controlled_reality_response_event(
        runtime,
        &policy::response_audit_event_with_controlled_reality(
            session.session_id,
            request_id,
            decision,
            response.status,
            controlled_reality_interaction,
        ),
        controlled_reality_pending_commit,
    )?;
    commit_controlled_reality_interaction(
        runtime,
        session,
        request_id,
        controlled_reality_pending_commit,
    )?;
    write_debug(
        runtime,
        "response_served",
        Some(session.session_id),
        json!({
            "request_id": request_id.0,
            "route": "direct_response",
            "decision": {
                "policy_state": decision.policy_state,
                "routing_decision": decision.routing_decision,
                "reason": decision.reason.as_str(),
            },
            "response": debug_response_fields(&response),
        }),
    )?;

    client_stream.write_all(&response.to_http_bytes_for_method(&request.method))?;
    client_stream.flush()
}

#[allow(clippy::too_many_arguments)]
fn write_direct_response_request_audit(
    runtime: &ProxyRuntime,
    session: &SessionContext,
    request: &HttpRequest,
    path: &str,
    request_id: RequestId,
    decision: &policy::PolicyDecision,
    discovery_recon_score: policy::DiscoveryReconAggregationScore,
    discovery_recon_threshold: u8,
    controlled_reality_pending_commit: bool,
    intervention_mode: InterventionMode,
    surface_requested_intervention: bool,
) -> io::Result<()> {
    let precommit_decision = staged_controlled_reality_precommit_decision(
        runtime,
        session.session_id,
        request_id,
        controlled_reality_pending_commit,
        intervention_mode,
    )?;
    let request_decision = precommit_decision.as_ref().unwrap_or(decision);
    let request_event = request_seen_event(
        request,
        path,
        session,
        request_id,
        request_decision,
        discovery_recon_score,
        discovery_recon_threshold,
    );
    if precommit_decision.is_some() {
        // A staged transition is not an observed policy outcome until its
        // response transaction is durable. A failed response may leave only
        // this pre-commit request fact in the log.
        write_event(&runtime.event_log, &request_event)
    } else {
        write_request_and_policy_events(
            runtime,
            &request_event,
            request_id,
            decision,
            intervention_mode,
            surface_requested_intervention,
        )
    }
}

fn staged_controlled_reality_precommit_decision(
    runtime: &ProxyRuntime,
    session_id: SessionId,
    request_id: RequestId,
    pending_commit: bool,
    intervention_mode: InterventionMode,
) -> io::Result<Option<policy::PolicyDecision>> {
    if !pending_commit {
        return Ok(None);
    }

    let record = runtime
        .policy_store
        .lock()
        .map_err(|_| io::Error::other("policy state store lock poisoned"))?
        .record(session_id);
    let pending = record
        .controlled_reality_pending_update
        .ok_or_else(|| invalid_data("controlled-reality response had no pending state"))?;
    if pending.request_id != request_id {
        return Err(invalid_data(
            "controlled-reality response request id did not match pending state",
        ));
    }
    let Some(commit_policy_state) = pending.commit_policy_state else {
        return Ok(None);
    };
    let Some(expected_policy_changed) = pending.expected_policy_changed else {
        return Err(invalid_data(
            "staged controlled-reality policy transition had no event contract",
        ));
    };
    let EventKind::PolicyChanged { from, to, .. } = expected_policy_changed.kind else {
        return Err(invalid_data(
            "staged controlled-reality policy event was not policy_changed",
        ));
    };
    if from != record.policy_state || to != commit_policy_state {
        return Err(invalid_data(
            "staged controlled-reality policy transition did not match current state",
        ));
    }

    Ok(Some(policy::decide_for_state(
        record.policy_state,
        intervention_mode,
    )))
}

fn policy_state_for_session(
    runtime: &ProxyRuntime,
    session_id: SessionId,
) -> io::Result<PolicyState> {
    policy_state_resolution_for_session(runtime, session_id).map(|(state, _)| state)
}

fn policy_state_resolution_for_session(
    runtime: &ProxyRuntime,
    session_id: SessionId,
) -> io::Result<(PolicyState, bool)> {
    let now_unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    let mut store = runtime
        .policy_store
        .lock()
        .map_err(|_| io::Error::other("policy state store lock poisoned"))?;
    store.note_session_seen(session_id, now_unix_secs)?;

    Ok((
        store.policy_state(session_id),
        store.uses_fail_closed_fallback(session_id),
    ))
}

/// Best-effort enforcement-floor feedback for peer continuity. The policy
/// store remains authoritative; a poisoned authority lock only weakens the
/// rotation-abuse safety net for later requests, never current routing.
fn note_session_enforcement(
    runtime: &ProxyRuntime,
    session: &SessionContext,
    policy_state: PolicyState,
) {
    let now_unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    if let Ok(mut authority) = runtime.session_authority.lock() {
        authority.note_enforcement_with_continuity(
            session.continuity_key(),
            session.session_id,
            policy_state,
            now_unix_secs,
        );
    }
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

    let result = store.set_policy_state(session_id, policy_state);
    if let Err(error) = &result {
        write_debug(
            runtime,
            "policy_persist_failed",
            Some(session_id),
            json!({
                "policy_state": policy_state,
                "error": error.to_string(),
            }),
        )?;
    }

    result
}

fn apply_policy_transition(
    runtime: &ProxyRuntime,
    session: &SessionContext,
    request_id: RequestId,
    transition: &policy::PolicyTransition,
) -> io::Result<()> {
    let session_id = session.session_id;
    write_debug(
        runtime,
        "policy_transition_selected",
        Some(session_id),
        json!({
            "from": transition.from,
            "to": transition.to,
            "reason": transition.reason.as_str(),
        }),
    )?;
    set_policy_state_for_session(runtime, session_id, transition.to)?;
    note_session_enforcement(runtime, session, transition.to);
    write_event(
        &runtime.event_log,
        &policy::policy_changed_event(session_id, request_id, transition),
    )
}

fn stage_controlled_reality_policy_transition(
    runtime: &ProxyRuntime,
    session_id: SessionId,
    request_id: RequestId,
    transition: &policy::PolicyTransition,
) -> io::Result<()> {
    if transition.from != PolicyState::ControlledReality || transition.to != PolicyState::Blocked {
        return Err(invalid_data(
            "controlled-reality pending transition must move from containment to blocked",
        ));
    }
    write_debug(
        runtime,
        "policy_transition_selected",
        Some(session_id),
        json!({
            "from": transition.from,
            "to": transition.to,
            "reason": transition.reason.as_str(),
            "durable_response_pending": true,
        }),
    )?;
    let staged = runtime
        .policy_store
        .lock()
        .map_err(|_| io::Error::other("policy state store lock poisoned"))?
        .stage_controlled_reality_policy_state(
            session_id,
            request_id,
            transition.to,
            policy::policy_changed_event(session_id, request_id, transition),
        )?;
    if !staged {
        return Err(invalid_data(
            "controlled-reality policy transition had no pending response",
        ));
    }
    Ok(())
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
    request_facts: RequestPolicyFacts,
) -> io::Result<policy::DiscoveryReconState> {
    let mut store = runtime
        .policy_store
        .lock()
        .map_err(|_| io::Error::other("policy state store lock poisoned"))?;

    if let Some(kind) = request_facts.discovery_surface {
        return store.note_discovery_surface_request(
            session_id,
            kind,
            request.query.is_some(),
            request_facts.legacy_openapi_discovery_query,
        );
    }

    if let Some(kind) = request_facts.linked_bait_surface {
        return store.note_linked_bait_surface_request(session_id, kind);
    }

    if let Some(kind) = request_facts.blind_decoy_write_probe {
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
    request_id: RequestId,
    request: &SurfaceRequestMeta,
    default_reason: String,
) -> io::Result<(
    SurfaceAction,
    Option<policy::PolicyTransition>,
    Option<ControlledRealityInteraction>,
    bool,
)> {
    reconcile_pending_controlled_reality_interaction(runtime, session_id)?;
    let (request_kind, progress) = {
        let mut store = runtime
            .policy_store
            .lock()
            .map_err(|_| io::Error::other("policy state store lock poisoned"))?;
        let record = store.record(session_id);
        let request_kind = runtime.controlled_reality.classify(
            session_id,
            record.controlled_reality_origin_request_id,
            request,
        );
        let progress = store.note_controlled_reality_interaction(
            session_id,
            request_id,
            request_kind.store_action(),
            runtime.controlled_reality_config.max_action_depth,
        )?;
        (request_kind, progress)
    };
    let depth = progress.depth;

    let depth_limit = runtime.controlled_reality_config.max_action_depth;
    if depth > depth_limit {
        let tarpit_delay = runtime.controlled_reality_config.tarpit_delay;
        if !tarpit_delay.is_zero() {
            thread::sleep(tarpit_delay);
        }
        let transition = request_evaluation::controlled_reality_depth_transition(
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
        return Ok((action, transition, None, true));
    }

    let controlled_decision = if let Some(backend) = &runtime.controlled_reality_backend {
        let rendered = progress
            .origin_request_id
            .map(|origin_request_id| {
                ControlledRealityResourceDescriptor::for_session(session_id, origin_request_id)
                    .map_err(|_| ControlledRealityBackendError::InvalidResourceDescriptor)
            })
            .transpose()
            .and_then(|resources| backend.render(request_id, request_kind, progress, resources));
        match rendered {
            Ok(rendered) => runtime.controlled_reality.decide_from_rendered(
                session_id,
                request_kind,
                progress,
                ControlledRealityRenderedResponse {
                    status: rendered.status,
                    body: rendered.body,
                },
            ),
            Err(error) => {
                let rolled_back = runtime
                    .policy_store
                    .lock()
                    .map_err(|_| io::Error::other("policy state store lock poisoned"))?
                    .reconcile_pending_controlled_reality(session_id, request_id, false)?;
                if !rolled_back {
                    return Err(invalid_data(
                        "controlled-reality renderer failure had no pending workflow state",
                    ));
                }
                write_debug(
                    runtime,
                    "controlled_reality_backend_failed",
                    Some(session_id),
                    json!({
                        "request_id": request_id.0,
                        "reason": error.audit_code(),
                        "response_status": 503,
                        "local_fallback": false,
                    }),
                )?;
                return Ok((
                    SurfaceAction::EidolonOwned {
                        response: runtime.controlled_reality.backend_unavailable_response(),
                    },
                    None,
                    None,
                    false,
                ));
            }
        }
    } else {
        runtime
            .controlled_reality
            .decide(session_id, request, request_kind, progress)
    };
    let mut action = controlled_decision.action;
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
            "workflow": &controlled_decision.interaction,
            "action": debug_surface_action(&action),
        }),
    )?;

    Ok((action, None, controlled_decision.interaction, true))
}

fn reconcile_pending_controlled_reality_interaction(
    runtime: &ProxyRuntime,
    session_id: SessionId,
) -> io::Result<()> {
    let record = runtime
        .policy_store
        .lock()
        .map_err(|_| io::Error::other("policy state store lock poisoned"))?
        .record(session_id);
    let Some(pending) = record.controlled_reality_pending_update else {
        return Ok(());
    };
    let request_id = pending.request_id;
    if pending.commit_policy_state.is_some() != pending.expected_policy_changed.is_some() {
        return Err(invalid_data(
            "pending controlled-reality policy transition contract was incomplete",
        ));
    }

    let durable_response = runtime
        .event_log
        .lock()
        .map_err(|_| io::Error::other("event log lock poisoned"))?
        .durable_response(session_id, request_id)?;
    let durable_response_seen = match (pending.expected_response, durable_response) {
        (_, DurableResponseMatch::Missing) => {
            if let Some(expected_policy_changed) = pending.expected_policy_changed.as_ref() {
                let mut log = runtime
                    .event_log
                    .lock()
                    .map_err(|_| io::Error::other("event log lock poisoned"))?;
                log.pin_durable_response(session_id, request_id);
                match log.durable_event_by_id(session_id, request_id, expected_policy_changed.id) {
                    Ok(None) => {
                        log.resolve_durable_response(session_id, request_id);
                    }
                    Ok(Some(_)) => {
                        return Err(invalid_data(
                            "durable policy transition existed without its workflow response",
                        ));
                    }
                    Err(error) => return Err(error),
                }
            }
            false
        }
        (
            None,
            DurableResponseMatch::Unique {
                event_id: _,
                policy_state: _,
                status: _,
                routing_decision: _,
                controlled_reality: _,
            },
        ) => {
            return Err(invalid_data(
                "durable response existed without a pending response contract",
            ));
        }
        (
            Some(expected),
            DurableResponseMatch::Unique {
                event_id,
                policy_state,
                status,
                routing_decision,
                controlled_reality,
            },
        ) => {
            let interaction_kind =
                controlled_reality
                    .as_ref()
                    .map(|interaction| match &interaction.action {
                        eidolon_core::ControlledRealityInteractionAction::JobSubmitted => {
                            ControlledRealityPendingInteractionKind::JobSubmitted
                        }
                        eidolon_core::ControlledRealityInteractionAction::StatusRead => {
                            ControlledRealityPendingInteractionKind::StatusRead
                        }
                        eidolon_core::ControlledRealityInteractionAction::ArtifactRead {
                            ..
                        } => ControlledRealityPendingInteractionKind::ArtifactRead,
                    });
            if event_id != expected.event_id
                || policy_state != expected.policy_state
                || status != expected.status
                || routing_decision != expected.routing_decision
                || expected.interaction_kind != interaction_kind
            {
                return Err(invalid_data(
                    "durable response conflicted with its pending response contract",
                ));
            }
            if controlled_reality_semantics_sha256(&controlled_reality)?
                != expected.controlled_reality_sha256
            {
                return Err(invalid_data(
                    "durable controlled-reality interaction conflicted with pending state",
                ));
            }
            if let Some(expected_policy_changed) = pending.expected_policy_changed.as_ref() {
                let mut log = runtime
                    .event_log
                    .lock()
                    .map_err(|_| io::Error::other("event log lock poisoned"))?;
                match log.durable_event_by_id(session_id, request_id, expected_policy_changed.id)? {
                    Some(actual) if actual == *expected_policy_changed => {}
                    Some(_) => {
                        return Err(invalid_data(
                            "durable policy transition conflicted with its pending contract",
                        ));
                    }
                    None => {
                        log.write_recovered_policy_event(expected_policy_changed)?;
                    }
                }
            }
            true
        }
    };
    runtime
        .policy_store
        .lock()
        .map_err(|_| io::Error::other("policy state store lock poisoned"))?
        .reconcile_pending_controlled_reality(session_id, request_id, durable_response_seen)?;
    runtime
        .event_log
        .lock()
        .map_err(|_| io::Error::other("event log lock poisoned"))?
        .resolve_durable_response(session_id, request_id);
    Ok(())
}

fn reconcile_all_pending_controlled_reality_interactions(runtime: &ProxyRuntime) -> io::Result<()> {
    let sessions = runtime
        .policy_store
        .lock()
        .map_err(|_| io::Error::other("policy state store lock poisoned"))?
        .pending_controlled_reality_sessions();
    if sessions.is_empty() {
        return Ok(());
    }
    for session_id in sessions {
        let _guard = runtime.controlled_reality_workflow_locks.lock(session_id)?;
        reconcile_pending_controlled_reality_interaction(runtime, session_id)?;
    }
    runtime
        .event_log
        .lock()
        .map_err(|_| io::Error::other("event log lock poisoned"))?
        .resolve_all_durable_responses();
    Ok(())
}

fn commit_controlled_reality_interaction(
    runtime: &ProxyRuntime,
    session: &SessionContext,
    request_id: RequestId,
    pending_commit: bool,
) -> io::Result<()> {
    if !pending_commit {
        return Ok(());
    }

    let session_id = session.session_id;
    let policy_state = {
        let mut store = runtime
            .policy_store
            .lock()
            .map_err(|_| io::Error::other("policy state store lock poisoned"))?;
        if !store.commit_controlled_reality_interaction(session_id, request_id)? {
            return Err(invalid_data(
                "controlled-reality response had no pending state to commit",
            ));
        }
        store.policy_state(session_id)
    };
    runtime
        .event_log
        .lock()
        .map_err(|_| io::Error::other("event log lock poisoned"))?
        .resolve_durable_response(session_id, request_id);
    note_session_enforcement(runtime, session, policy_state);
    Ok(())
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

fn render_suspicious_discovery_action(
    runtime: &ProxyRuntime,
    session_id: SessionId,
    controller_surface_action: SurfaceAction,
    plan: request_evaluation::SuspiciousDiscoveryPlan,
) -> io::Result<SurfaceAction> {
    match plan {
        request_evaluation::SuspiciousDiscoveryPlan::Preserve => Ok(controller_surface_action),
        request_evaluation::SuspiciousDiscoveryPlan::ServeDocsBait => {
            let bait = runtime
                .bait_registry
                .bait_for_class(BaitClass::Docs)
                .ok_or_else(|| invalid_data("docs discovery plan referenced a missing bait"))?;
            let bait =
                render_bait_for_session(bait, session_id, runtime.bait_signing_secret.as_deref())
                    .map_err(|error| invalid_data(error.to_string()))?;

            Ok(SurfaceAction::EidolonOwned {
                response: bait_surface_response(&bait, &runtime.bait_content),
            })
        }
        request_evaluation::SuspiciousDiscoveryPlan::ServeOpenApiBait => {
            let bait = runtime
                .bait_registry
                .bait_for_class(BaitClass::OpenApi)
                .ok_or_else(|| invalid_data("OpenAPI discovery plan referenced a missing bait"))?;
            let bait =
                render_bait_for_session(bait, session_id, runtime.bait_signing_secret.as_deref())
                    .map_err(|error| invalid_data(error.to_string()))?;

            Ok(SurfaceAction::EidolonOwned {
                response: owned_openapi_discovery_response(&bait, &runtime.bait_content.openapi),
            })
        }
    }
}

fn write_bait_exposed_event(
    runtime: &ProxyRuntime,
    session: &SessionContext,
    request_id: RequestId,
    policy_state: PolicyState,
    bait: &Bait,
    surface: impl Into<String>,
) -> io::Result<ExposureId> {
    let exposure_id = ExposureId(format!("exp-{}", SessionId::new().0));
    let surface = surface.into();
    let event = Event::new(
        session.session_id,
        EventSource::SurfaceController,
        policy_state,
        EventKind::BaitExposed {
            bait_id: bait.id.clone(),
            bait_class: Some(bait.bait_class),
            exposure_id: exposure_id.clone(),
            surface: redacted_event_target(&surface),
            header_value_mint: bait.header_value_mint_audit(),
        },
    )
    .with_request_id(request_id);
    let observed_at_unix_secs = u64::try_from(event.observed_at.timestamp()).unwrap_or_default();
    let mut exposures = runtime
        .bait_exposures
        .lock()
        .map_err(|_| io::Error::other("bait exposure store lock poisoned"))?;

    write_event(&runtime.event_log, &event)?;

    exposures.record_exposure_at(
        session.session_id,
        bait.id.clone(),
        exposure_id.clone(),
        observed_at_unix_secs,
        current_unix_secs(),
    )?;
    write_debug(
        runtime,
        "bait_exposed",
        Some(session.session_id),
        json!({
            "request_id": request_id.0,
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
    request_id: RequestId,
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
                bait_class: Some(bait.bait_class),
                exposure_id: exposure_id.clone(),
                method: method.to_string(),
                path: redacted_event_target(path),
                header_value_mint: bait.header_value_mint_audit(),
                header_value_mint_status,
            },
        )
        .with_request_id(request_id),
    )?;

    write_debug(
        runtime,
        "bait_action_observed",
        Some(session.session_id),
        json!({
            "request_id": request_id.0,
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

// Eight arguments are intrinsic to the audit payload (runtime, session,
// request linkage, policy state, and the observed bait action shape); the
// sibling with_exposure variant already uses the observation struct, so
// packing these separately would only add an artificial partial-struct type.
#[allow(clippy::too_many_arguments)]
fn write_bait_action_observed_event(
    runtime: &ProxyRuntime,
    session: &SessionContext,
    request_id: RequestId,
    policy_state: PolicyState,
    bait: &Bait,
    method: &str,
    path: &str,
    header_value_mint_status: Option<BaitHeaderValueMintStatus>,
) -> io::Result<Option<ExposureId>> {
    let accepted = matches!(
        header_value_mint_status,
        None | Some(BaitHeaderValueMintStatus::MatchedSessionValue)
    );
    let exposure_id = if accepted {
        bait_action_exposure_id(runtime, session, &bait.id)?
    } else {
        None
    };
    write_bait_action_observed_event_with_exposure(
        runtime,
        session,
        request_id,
        policy_state,
        BaitActionObservation {
            bait,
            method,
            path,
            exposure_id: exposure_id.clone(),
            prior_same_bait_exposure: exposure_id.is_some(),
            header_value_mint_status,
        },
    )?;

    Ok(exposure_id)
}

fn write_bait_action_near_miss_event(
    runtime: &ProxyRuntime,
    session: &SessionContext,
    request_id: RequestId,
    policy_state: PolicyState,
    bait: &Bait,
    method: &str,
    path: &str,
) -> io::Result<bool> {
    let prior_same_bait_exposure = bait_action_exposure_id(runtime, session, &bait.id)?.is_some();
    write_bait_action_observed_event_with_exposure(
        runtime,
        session,
        request_id,
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

fn header_pairs(headers: &[HttpHeader]) -> impl Iterator<Item = (&str, &str)> {
    headers
        .iter()
        .map(|header| (header.name.as_str(), header.value.as_str()))
}

fn strip_session_proof_cache_request_headers(request: &mut HttpRequest) -> usize {
    const CACHE_CONDITIONAL_AND_RANGE_HEADERS: &[&str] = &[
        "If-Match",
        "If-Modified-Since",
        "If-None-Match",
        "If-Range",
        "If-Unmodified-Since",
        "Range",
    ];

    let original_len = request.headers.len();
    request.headers.retain(|header| {
        !CACHE_CONDITIONAL_AND_RANGE_HEADERS
            .iter()
            .any(|name| header.name.eq_ignore_ascii_case(name))
    });
    original_len - request.headers.len()
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
        cache_policy: response.cache_policy,
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
        503 => "Service Unavailable",
        _ => "Unknown Status",
    }
}

fn normalized_event_path(request: &HttpRequest) -> io::Result<String> {
    canonical_request_target(request, RequestTargetMode::OriginOrAbsoluteHttp)
        .map_err(|error| invalid_data(error.to_string()))
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
    request_id: RequestId,
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
            authenticated_ingress_rule_rejection: session
                .authenticated_ingress_rule_rejection
                .clone(),
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
    .with_persistence(decision.persistence)
    .with_request_id(request_id)
}

fn write_request_and_policy_events(
    runtime: &ProxyRuntime,
    request_event: &Event,
    request_id: RequestId,
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
            &policy::policy_intervention_event(request_event.session_id, request_id, decision),
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

fn apply_response_headers(
    response: &mut HttpResponse,
    session: &SessionContext,
    request_method: &str,
) {
    let original_content_length = response
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("content-length"))
        .map(|header| header.value.clone());
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
    if (100..200).contains(&response.status) || response.status == 204 {
        response.remove_header("Content-Length");
    } else if request_method.eq_ignore_ascii_case("HEAD") || response.status == 304 {
        if response.body.is_empty() {
            response.remove_header("Content-Length");
            if let Some(content_length) = original_content_length {
                response.set_header("Content-Length", content_length);
            }
        } else {
            response.set_header("Content-Length", response.body.len().to_string());
        }
    } else {
        response.set_header("Content-Length", response.body.len().to_string());
    }

    if let Some(set_cookie) = session.set_cookie_value() {
        response.append_header(session::SET_COOKIE_HEADER_NAME, set_cookie);
    }

    apply_response_cache_policy(response);
}

fn apply_response_cache_policy(response: &mut HttpResponse) {
    if response.cache_policy != ResponseCachePolicy::PrivateNoStore {
        return;
    }

    for name in [
        "Accept-Ranges",
        "Age",
        "CDN-Cache-Control",
        "Cloudflare-CDN-Cache-Control",
        "Content-Digest",
        "Content-MD5",
        "Content-Range",
        "Digest",
        "ETag",
        "Expires",
        "Last-Modified",
        "Repr-Digest",
        "Surrogate-Control",
        "X-Accel-Expires",
    ] {
        response.remove_header(name);
    }

    response.set_header("Cache-Control", SESSION_PROOF_CACHE_CONTROL);
    ensure_vary_cookie(response);
}

fn ensure_vary_cookie(response: &mut HttpResponse) {
    let mut vary_tokens = Vec::new();
    for value in response
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("vary"))
        .map(|header| header.value.as_str())
    {
        for token in value
            .split(',')
            .map(str::trim)
            .filter(|token| !token.is_empty())
        {
            if token == "*" {
                return;
            }
            if !vary_tokens
                .iter()
                .any(|existing: &String| existing.eq_ignore_ascii_case(token))
            {
                vary_tokens.push(token.to_string());
            }
        }
    }

    if !vary_tokens
        .iter()
        .any(|token| token.eq_ignore_ascii_case("cookie"))
    {
        vary_tokens.push("Cookie".to_string());
    }
    response.set_header("Vary", vary_tokens.join(", "));
}

fn write_event(log: &Arc<Mutex<FileEventLogWriter>>, event: &Event) -> io::Result<()> {
    let result = log
        .lock()
        .map_err(|_| io::Error::other("event log lock poisoned"))
        .and_then(|mut log| log.write_event(event));
    if let Err(error) = &result {
        eprintln!("eidolon persistence failure: event log: {error}");
    }
    result
}

fn write_controlled_reality_response_event(
    runtime: &ProxyRuntime,
    event: &Event,
    pending_commit: bool,
) -> io::Result<()> {
    if !pending_commit {
        return write_event(&runtime.event_log, event);
    }

    let EventKind::ResponseServed {
        status,
        routing_decision,
        controlled_reality,
    } = &event.kind
    else {
        return Err(invalid_data(
            "controlled-reality durable event was not response_served",
        ));
    };
    let request_id = event
        .request_id
        .ok_or_else(|| invalid_data("controlled-reality durable response had no request id"))?;
    let record = runtime
        .policy_store
        .lock()
        .map_err(|_| io::Error::other("policy state store lock poisoned"))?
        .record(event.session_id);
    let Some(pending) = record.controlled_reality_pending_update else {
        return Err(invalid_data(
            "controlled-reality durable response had no pending state",
        ));
    };
    if pending.request_id != request_id {
        return Err(invalid_data(
            "controlled-reality durable response request id did not match pending state",
        ));
    }
    let (expected_status, expected_routing_decision, expected_interaction) =
        if pending.commit_policy_state == Some(PolicyState::Blocked) {
            (403, RoutingDecision::EidolonOwned, None)
        } else {
            let expected = runtime.controlled_reality.expected_response(
                event.session_id,
                ControlledRealityProgress {
                    depth: record.controlled_reality_depth,
                    from_state: pending.previous_state,
                    to_state: record.controlled_reality_workflow_state,
                    origin_request_id: record.controlled_reality_origin_request_id,
                },
                pending.request_action,
                runtime.controlled_reality_config.max_action_depth,
            );
            (
                expected.status,
                expected.routing_decision,
                expected.interaction,
            )
        };
    if *status != expected_status
        || *routing_decision != expected_routing_decision
        || *controlled_reality != expected_interaction
        || event.policy_state != pending.commit_policy_state.unwrap_or(record.policy_state)
    {
        return Err(invalid_data(
            "controlled-reality response conflicted with pending request semantics",
        ));
    }
    let interaction_kind =
        expected_interaction
            .as_ref()
            .map(|interaction| match &interaction.action {
                eidolon_core::ControlledRealityInteractionAction::JobSubmitted => {
                    ControlledRealityPendingInteractionKind::JobSubmitted
                }
                eidolon_core::ControlledRealityInteractionAction::StatusRead => {
                    ControlledRealityPendingInteractionKind::StatusRead
                }
                eidolon_core::ControlledRealityInteractionAction::ArtifactRead { .. } => {
                    ControlledRealityPendingInteractionKind::ArtifactRead
                }
            });
    let pending_registered = runtime
        .policy_store
        .lock()
        .map_err(|_| io::Error::other("policy state store lock poisoned"))?
        .set_pending_controlled_reality_response(
            event.session_id,
            request_id,
            ControlledRealityPendingResponse {
                event_id: event.id,
                policy_state: event.policy_state,
                status: *status,
                routing_decision: *routing_decision,
                interaction_kind,
                controlled_reality_sha256: controlled_reality_semantics_sha256(controlled_reality)?,
            },
        )?;
    if !pending_registered {
        return Err(invalid_data(
            "controlled-reality durable response contract was not registered",
        ));
    }

    let result = runtime
        .event_log
        .lock()
        .map_err(|_| io::Error::other("event log lock poisoned"))
        .and_then(|mut log| {
            log.write_durable_response_transaction(event, pending.expected_policy_changed.as_ref())
        });
    if let Err(error) = &result {
        eprintln!("eidolon persistence failure: durable workflow event log: {error}");
    }
    result
}

fn controlled_reality_semantics_sha256(
    interaction: &Option<ControlledRealityInteraction>,
) -> io::Result<[u8; 32]> {
    let serialized = serde_json::to_vec(interaction).map_err(|error| {
        invalid_data(format!(
            "failed to serialize controlled-reality response semantics: {error}"
        ))
    })?;
    Ok(Sha256::digest(serialized).into())
}

fn effective_session_context(
    runtime: &ProxyRuntime,
    request: &HttpRequest,
    surface_request: &SurfaceRequestMeta,
    client_peer_ip: Option<IpAddr>,
    request_id: RequestId,
) -> io::Result<SessionContext> {
    let headers: Vec<(&str, &str)> = header_pairs(&request.headers).collect();
    let request_host = effective_request_host(request);
    let now_unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    let session_resolution = {
        let mut authority = runtime
            .session_authority
            .lock()
            .map_err(|_| io::Error::other("session authority lock poisoned"))?;
        session::derive_session_from_headers_with_trusted_ingress_continuity(
            &mut authority,
            headers.iter().copied(),
            client_peer_ip,
            now_unix_secs,
            runtime.ingress_transport_auth_secret.as_deref(),
            runtime.require_authenticated_ingress_continuity,
            !runtime.require_authenticated_ingress_continuity,
        )
    };
    let mut session = match session_resolution {
        Ok(session) => session,
        Err(rejection) => {
            write_debug(
                runtime,
                "session_continuity_rejected",
                None,
                json!({
                    "request_id": request_id.0,
                    "reason": rejection.as_str(),
                }),
            )?;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "trusted ingress continuity rejected: {}",
                    rejection.as_str()
                ),
            ));
        }
    };
    write_debug(
        runtime,
        "session_resolved",
        Some(session.session_id),
        json!({
            "request_id": request_id.0,
            "session_source": match session.source {
                session::SessionSource::Cookie => "cookie",
                session::SessionSource::Generated => "generated",
            },
            "cookie_outcome": session.cookie_outcome.as_str(),
            "key_status": session.key_status.map(|status| status.as_str()),
            "presented_key_version": session.presented_key_version,
            "active_key_version": session.active_key_version,
            "continuity_outcome": session.continuity_outcome.as_str(),
            "continuity_source": session.continuity_source.map(|source| source.as_str()),
            "enforcement_floor": session.enforcement_floor,
        }),
    )?;
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
    let authenticated_trust_evaluation = runtime.ingress_identity_resolver.evaluate_authenticated(
        &session.ingress_identity,
        &session.ingress_signals,
        &request.method,
        &surface_request.path,
    );
    session.authenticated_ingress_rule_rejection =
        authenticated_trust_evaluation.rule_rejection.clone();
    let authenticated_trust = authenticated_trust_evaluation.resolved;
    if runtime
        .ingress_identity_resolver
        .has_authenticated_entries()
        && authenticated_trust.is_none()
        && ingress_identity::requires_authenticated_rule(&session.ingress_identity)
    {
        session.ingress_identity =
            ingress_identity::downgrade_to_weakly_asserted(session.ingress_identity.clone());
    }
    let merged_identity = ingress_identity::merge_ingress_identity(
        session.ingress_identity.clone(),
        local_trust.as_ref().map(|trust| trust.identity.clone()),
    );
    session.trusted_ingress_soften_match = authenticated_trust
        .as_ref()
        .and_then(|trust| {
            trusted_ingress_soften_match(trust, &merged_identity, &surface_request.path)
        })
        .or_else(|| {
            local_trust.as_ref().and_then(|trust| {
                trusted_ingress_soften_match(trust, &merged_identity, &surface_request.path)
            })
        });
    session.trusted_bait_soften_path_prefixes = session
        .trusted_ingress_soften_match
        .as_ref()
        .map(|scope| scope.bait_soften_path_prefixes.clone());
    session.ingress_identity = merged_identity;

    Ok(session)
}

fn trusted_ingress_soften_match(
    trust: &ingress_identity::ResolvedIngressTrust,
    merged_identity: &eidolon_core::IngressIdentity,
    request_path: &str,
) -> Option<eidolon_core::TrustedIngressSoftenMatch> {
    if merged_identity != &trust.identity {
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
            .any(|prefix| ingress_identity::path_matches_segment_prefix(request_path, prefix)),
        bait_soften_path_prefixes,
        user_agent_substrings: trust.user_agent_substrings.clone().unwrap_or_default(),
        hosts: trust.hosts.clone().unwrap_or_default(),
        source_cidrs: trust.source_cidrs.clone().unwrap_or_default(),
        required_header_names: trust.required_header_names.clone(),
        verified_categories: trust.verified_categories.clone(),
    })
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

    let result = log
        .lock()
        .map_err(|_| io::Error::other("debug log lock poisoned"))
        .and_then(|mut log| log.write_record(&record));
    if let Err(error) = &result {
        eprintln!("eidolon persistence failure: debug log: {error}");
    }
    result
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
    if query.is_some() {
        redacted.push_str("?<redacted>");
    }
    if fragment_present {
        redacted.push_str("#<redacted>");
    }

    redacted
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
struct HttpResponse {
    version: String,
    status: u16,
    reason: String,
    headers: Vec<HttpHeader>,
    body: Vec<u8>,
    cache_policy: ResponseCachePolicy,
}

fn request_to_upstream_bytes(
    request: &HttpRequest,
    upstream: &UpstreamTarget,
) -> io::Result<Vec<u8>> {
    let target = canonical_request_target(request, RequestTargetMode::OriginOrAbsoluteHttp)
        .map_err(|error| invalid_data(error.to_string()))?;
    let connection_nominated_headers = connection_nominated_headers(&request.headers);
    let should_emit_content_length = !request.body.is_empty()
        || request
            .headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case("content-length"));
    let mut bytes = Vec::new();

    write!(
        bytes,
        "{} {} {}\r\nHost: {}\r\nConnection: close\r\n",
        request.method, target, request.version, upstream.authority
    )?;

    if should_emit_content_length {
        write!(bytes, "Content-Length: {}\r\n", request.body.len())?;
    }

    for header in &request.headers {
        if should_skip_forwarded_header(&header.name, &connection_nominated_headers) {
            continue;
        }

        write!(bytes, "{}: {}\r\n", header.name, header.value)?;
    }

    bytes.extend_from_slice(b"\r\n");
    bytes.extend_from_slice(&request.body);
    Ok(bytes)
}

impl HttpResponse {
    #[cfg(test)]
    fn to_http_bytes(&self) -> Vec<u8> {
        self.to_http_bytes_for_method("GET")
    }

    fn to_http_bytes_for_method(&self, request_method: &str) -> Vec<u8> {
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
        if !response_has_no_message_body(request_method, self.status) {
            bytes.extend_from_slice(&self.body);
        }
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

#[cfg(test)]
fn read_http_response<R>(reader: &mut R) -> io::Result<HttpResponse>
where
    R: Read,
{
    read_http_response_for_method(reader, "GET")
}

fn read_http_response_for_method<R>(
    reader: &mut R,
    request_method: &str,
) -> io::Result<HttpResponse>
where
    R: Read,
{
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    let mut informational_count = 0;
    let (mut response, transfer_coding, content_length) = loop {
        let header_end = loop {
            if let Some(header_end) = find_header_end(&buffer) {
                break header_end;
            }
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
        };

        let head = buffer[..header_end - 4].to_vec();
        buffer.drain(..header_end);
        let response = parse_http_response_head(&head)?;
        let transfer_coding = response_transfer_coding(&response)?;
        let content_length = response_content_length(&response)?;
        if transfer_coding != ResponseTransferCoding::Identity && content_length.is_some() {
            return Err(invalid_data(
                "upstream response must not combine Transfer-Encoding and Content-Length",
            ));
        }
        if !(100..200).contains(&response.status) {
            break (response, transfer_coding, content_length);
        }
        if response.status == 101 {
            return Err(invalid_data(
                "upstream protocol switching is not supported by the v0 proxy",
            ));
        }
        informational_count += 1;
        if informational_count > MAX_INFORMATIONAL_RESPONSES {
            return Err(invalid_data(
                "upstream sent too many informational responses",
            ));
        }
    };

    if response_has_no_message_body(request_method, response.status) {
        return Ok(response);
    }
    response.body = buffer;

    match transfer_coding {
        ResponseTransferCoding::Identity => {
            if let Some(content_length) = content_length {
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

fn response_has_no_message_body(request_method: &str, status: u16) -> bool {
    request_method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&status)
        || status == 204
        || status == 304
}

fn is_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn is_valid_http_field_value(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte))
}

fn parse_http_request_head(head: &[u8]) -> io::Result<HttpRequest> {
    let head = std::str::from_utf8(head).map_err(|_| invalid_data("HTTP headers are not UTF-8"))?;
    let mut lines = head.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| invalid_data("missing HTTP request line"))?;
    let mut request_parts = request_line.split(' ');
    let method = request_parts
        .next()
        .ok_or_else(|| invalid_data("missing HTTP method"))?;
    let target = request_parts
        .next()
        .ok_or_else(|| invalid_data("missing HTTP request target"))?;
    let version = request_parts
        .next()
        .ok_or_else(|| invalid_data("missing HTTP version"))?;

    if method.is_empty()
        || target.is_empty()
        || version.is_empty()
        || request_parts.next().is_some()
    {
        return Err(invalid_data(
            "HTTP request line must contain exactly three fields separated by one space",
        ));
    }

    if !is_http_token(method) {
        return Err(invalid_data("HTTP method is not a valid token"));
    }
    let version = match version {
        "HTTP/1.0" => HttpVersion::Http10,
        "HTTP/1.1" => HttpVersion::Http11,
        _ => {
            return Err(invalid_data(
                "HTTP request version must be HTTP/1.0 or HTTP/1.1",
            ));
        }
    };

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }

        let Some((name, value)) = line.split_once(':') else {
            return Err(invalid_data("HTTP header is missing `:`"));
        };

        if !is_http_token(name) {
            return Err(invalid_data("HTTP header name is not a valid token"));
        }
        if !is_valid_http_field_value(value) {
            return Err(invalid_data("HTTP header value contains invalid bytes"));
        }

        headers.push(HttpHeader {
            name: name.to_string(),
            value: value.trim().to_string(),
        });
    }

    Ok(HttpRequest {
        method: method.to_string(),
        target: target.to_string(),
        version,
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
    let reason = status_parts
        .next()
        .ok_or_else(|| invalid_data("missing HTTP response reason separator"))?;

    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(invalid_data(
            "HTTP response version must be HTTP/1.0 or HTTP/1.1",
        ));
    }
    if status.len() != 3 || !status.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid_data(
            "HTTP response status must contain exactly three digits",
        ));
    }
    if !is_valid_http_field_value(reason) {
        return Err(invalid_data(
            "HTTP response reason phrase contains invalid bytes",
        ));
    }

    let status = status
        .parse::<u16>()
        .map_err(|error| invalid_data(format!("invalid HTTP response status: {error}")))?;
    if !(100..=599).contains(&status) {
        return Err(invalid_data(
            "HTTP response status must be between 100 and 599",
        ));
    }

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }

        let Some((name, value)) = line.split_once(':') else {
            return Err(invalid_data("HTTP response header is missing `:`"));
        };

        if !is_http_token(name) {
            return Err(invalid_data(
                "HTTP response header name is not a valid token",
            ));
        }
        if !is_valid_http_field_value(value) {
            return Err(invalid_data(
                "HTTP response header value contains invalid bytes",
            ));
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
        cache_policy: ResponseCachePolicy::Preserve,
    })
}

fn request_content_length(request: &HttpRequest) -> io::Result<usize> {
    if request
        .headers
        .iter()
        .any(|header| header.name.eq_ignore_ascii_case("transfer-encoding"))
    {
        return Err(invalid_data(
            "request Transfer-Encoding is not supported by the v0 proxy",
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

fn effective_request_host(request: &HttpRequest) -> Option<String> {
    normalized_request_host(request).ok()
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
  --session-signing-key-file <PATH>
                         JSON session signing key ring. When omitted, sessions are
                         minted under an ephemeral key that changes on restart
  --ingress-trust-config <PATH>
                         JSON ingress trust config for local allowlists and trusted
                         automation claims
  --ingress-transport-auth-secret-file <PATH>
                         Shared-secret file required before explicit
                         X-Eidolon-Ingress-* identity headers are trusted
  --require-authenticated-ingress-continuity
                         Require one valid transport-auth and continuity header
                         pair on every request. Requires the transport secret
  --trusted-bait-soften-prefix <PATH_PREFIX>
                         Repeatable path prefix where strong trusted identities may
                         skip bait exposure surfaces [default: /docs, /openapi.json]
  --intervention-control <PATH>
                         Optional control file; write `disabled` to bypass ordinary
                         surface interventions. Recognized unsafe bait actions and
                         synthetic follow-ups still fail closed
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
  --controlled-reality-backend-addr <ADDR>
                         Optional signed renderer host and TCP port
  --controlled-reality-backend-auth-secret-file <PATH>
                         Required 64-hex HMAC secret when a remote renderer is configured
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
        sync::mpsc,
        thread::JoinHandle,
        time::{SystemTime, UNIX_EPOCH},
    };

    use eidolon_core::{
        ControlledRealityWorkflowState, ExpectedAction, PersistenceMetadata, SessionId, SurfaceKind,
    };
    use eidolon_proxy::{
        controlled_reality_backend::{
            serve_render_connection, ControlledRealityBackendConnectionOutcome,
            ControlledRealityBackendReplayCache,
        },
        surface::{HtmlInsertion, RewritePlan},
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

    fn write_controlled_reality_backend_secret() -> PathBuf {
        let path = unique_temp_path("controlled-reality-backend-secret.txt");
        must_ok(
            fs::write(
                &path,
                concat!(
                    "30313233", "34353637", "38396162", "63646566", "30313233", "34353637",
                    "38396162", "63646566",
                ),
            ),
            "controlled reality backend secret should write",
        );
        path
    }

    fn test_controlled_reality_backend_secret() -> ControlledRealityBackendAuthSecret {
        ControlledRealityBackendAuthSecret::new(b"0123456789abcdef0123456789abcdef".to_vec())
            .expect("test backend secret should be accepted")
    }

    fn start_controlled_reality_backend_once() -> (
        Arc<ControlledRealityBackendClient>,
        JoinHandle<ControlledRealityBackendConnectionOutcome>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("backend should bind");
        let address = listener.local_addr().expect("backend address should exist");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("backend should accept");
            serve_render_connection(
                stream,
                &test_controlled_reality_backend_secret(),
                &ControlledRealityBackendReplayCache::new(),
            )
        });
        (
            Arc::new(ControlledRealityBackendClient::new(
                address,
                test_controlled_reality_backend_secret(),
            )),
            server,
        )
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
            client_request_deadline: CLIENT_REQUEST_DEADLINE,
            event_log: Arc::new(Mutex::new(
                FileEventLogWriter::open(event_log_path).expect("event log should open"),
            )),
            debug_log: None,
            intervention_control_path,
            policy_store: Arc::new(Mutex::new(PolicyStateStore::in_memory())),
            session_authority: Arc::new(Mutex::new(test_session_authority())),
            controlled_reality_config: ControlledRealityConfig::default(),
            controlled_reality: Arc::new(ControlledRealityResponder),
            controlled_reality_backend: None,
            controlled_reality_workflow_locks: Arc::new(ControlledRealityWorkflowLocks::new()),
            surface_controller,
            ingress_identity_resolver: Arc::new(IngressIdentityResolver::default()),
            ingress_transport_auth_secret: None,
            require_authenticated_ingress_continuity: false,
            bait_signing_secret: None,
            trusted_bait_soften_path_prefixes: default_trusted_bait_soften_path_prefixes(),
            bait_registry,
            bait_content: BaitContentOverrides::default(),
            bait_exposures: Arc::new(Mutex::new(BaitExposureStore::default())),
            consumed_bait_proofs: Arc::new(Mutex::new(ConsumedBaitProofStore::default())),
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
            client_request_deadline: CLIENT_REQUEST_DEADLINE,
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
            controlled_reality_backend: None,
            controlled_reality_workflow_locks: Arc::new(ControlledRealityWorkflowLocks::new()),
            surface_controller: Arc::new(M1DemoSurfaceController::with_content_overrides(
                Arc::clone(&bait_registry),
                BaitContentOverrides::default(),
                None,
            )),
            ingress_identity_resolver: Arc::new(IngressIdentityResolver::default()),
            ingress_transport_auth_secret: None,
            require_authenticated_ingress_continuity: false,
            bait_signing_secret: None,
            trusted_bait_soften_path_prefixes: default_trusted_bait_soften_path_prefixes(),
            bait_registry,
            bait_content: BaitContentOverrides::default(),
            bait_exposures: Arc::new(Mutex::new(BaitExposureStore::default())),
            consumed_bait_proofs: Arc::new(Mutex::new(ConsumedBaitProofStore::default())),
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
            client_request_deadline: CLIENT_REQUEST_DEADLINE,
            event_log: Arc::new(Mutex::new(
                FileEventLogWriter::open(event_log_path).expect("event log should open"),
            )),
            debug_log: None,
            intervention_control_path,
            policy_store: Arc::new(Mutex::new(PolicyStateStore::in_memory())),
            session_authority: Arc::new(Mutex::new(test_session_authority())),
            controlled_reality_config: ControlledRealityConfig::default(),
            controlled_reality: Arc::new(ControlledRealityResponder),
            controlled_reality_backend: None,
            controlled_reality_workflow_locks: Arc::new(ControlledRealityWorkflowLocks::new()),
            surface_controller: Arc::new(M1DemoSurfaceController::with_content_overrides(
                Arc::clone(&bait_registry),
                BaitContentOverrides::default(),
                None,
            )),
            ingress_identity_resolver: Arc::new(IngressIdentityResolver::default()),
            ingress_transport_auth_secret: None,
            require_authenticated_ingress_continuity: false,
            bait_signing_secret: None,
            trusted_bait_soften_path_prefixes: default_trusted_bait_soften_path_prefixes(),
            bait_registry,
            bait_content: BaitContentOverrides::default(),
            bait_exposures: Arc::new(Mutex::new(bait_exposures)),
            consumed_bait_proofs: Arc::new(Mutex::new(ConsumedBaitProofStore::default())),
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
            client_request_deadline: CLIENT_REQUEST_DEADLINE,
            event_log: Arc::new(Mutex::new(
                FileEventLogWriter::open(event_log_path).expect("event log should open"),
            )),
            debug_log: None,
            intervention_control_path,
            policy_store: Arc::new(Mutex::new(PolicyStateStore::in_memory())),
            session_authority: Arc::new(Mutex::new(test_session_authority())),
            controlled_reality_config: ControlledRealityConfig::default(),
            controlled_reality: Arc::new(ControlledRealityResponder),
            controlled_reality_backend: None,
            controlled_reality_workflow_locks: Arc::new(ControlledRealityWorkflowLocks::new()),
            surface_controller: Arc::new(M1DemoSurfaceController::with_content_overrides(
                Arc::clone(&bait_registry),
                bait_content.clone(),
                bait_signing_secret.clone(),
            )),
            ingress_identity_resolver: Arc::new(IngressIdentityResolver::default()),
            ingress_transport_auth_secret: None,
            require_authenticated_ingress_continuity: false,
            bait_signing_secret,
            trusted_bait_soften_path_prefixes: default_trusted_bait_soften_path_prefixes(),
            bait_registry,
            bait_content,
            bait_exposures: Arc::new(Mutex::new(BaitExposureStore::default())),
            consumed_bait_proofs: Arc::new(Mutex::new(ConsumedBaitProofStore::default())),
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
                  "prefix": "minted",
                  "proof_window_seconds": 60
                }
              }
            }
          ]
        }"##
    }

    fn session_minted_openapi_profile_json() -> &'static str {
        r##"{
          "schema_version": 1,
          "profile_id": "session_minted_openapi",
          "baits": [
            {
              "id": "minted_openapi_trace",
              "bait_class": "open_api",
              "surface": "/openapi.json",
              "surface_kind": "open_api",
              "expected_action": {
                "method": "POST",
                "path": "/api/v2/import/reconcile",
                "header_name": "X-OpenAPI-Trace",
                "header_value_mint": {
                  "kind": "session_hmac_sha256_v1",
                  "prefix": "oapi",
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

    fn custom_unsafe_action_profile_json(method: &str) -> String {
        custom_unsafe_action_profile_json_with_path(method, "/eidolon-lab/custom-commit")
    }

    fn custom_unsafe_action_profile_json_with_path(method: &str, action_path: &str) -> String {
        r##"{
          "schema_version": 1,
          "profile_id": "custom_unsafe_action",
          "baits": [
            {
              "id": "custom_commit_trace",
              "bait_class": "docs",
              "surface": "/docs/custom-commit",
              "surface_kind": "docs",
              "expected_action": {
                "method": "__METHOD__",
                "path": "__ACTION_PATH__",
                "header_name": "X-Eidolon-Custom-Proof",
                "header_value": "custom-proof-value"
              }
            }
          ]
        }"##
        .replace("__METHOD__", method)
        .replace("__ACTION_PATH__", action_path)
    }

    // Simulate malformed registry state so the runtime guard remains testable after loader rejection.
    fn unchecked_custom_unsafe_action_profile(action_path: &str) -> LoadedBaitProfile {
        let mut registry = BaitRegistry::new();
        registry.add(Bait {
            id: BaitId("custom_commit_trace".to_string()),
            bait_class: BaitClass::Docs,
            surface: "/docs/custom-commit".to_string(),
            surface_kind: SurfaceKind::Docs,
            expected_action: ExpectedAction {
                method: "PUT".to_string(),
                path: action_path.to_string(),
                header_name: Some("X-Eidolon-Custom-Proof".to_string()),
                header_value: Some("custom-proof-value".to_string()),
                header_value_mint: None,
            },
        });

        LoadedBaitProfile {
            registry,
            content: BaitContentOverrides::default(),
            metadata: Some(BaitProfileMetadata {
                profile_id: "unchecked_custom_unsafe_action".to_string(),
                hypothesis: None,
            }),
        }
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

    struct RecordingUpstream {
        stop: mpsc::Sender<()>,
        handle: JoinHandle<Vec<Vec<u8>>>,
    }

    impl RecordingUpstream {
        fn finish(self) -> Vec<Vec<u8>> {
            self.stop
                .send(())
                .expect("recording upstream should accept stop signal");
            must_join(self.handle.join(), "recording upstream should join")
        }
    }

    fn spawn_recording_upstream(
        responses: impl IntoIterator<Item = Vec<u8>>,
    ) -> (UpstreamTarget, RecordingUpstream) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("recording upstream should bind");
        let addr = listener
            .local_addr()
            .expect("recording upstream should have address");
        listener
            .set_nonblocking(true)
            .expect("recording upstream should be nonblocking");
        let responses: Vec<Vec<u8>> = responses.into_iter().collect();
        assert!(
            !responses.is_empty(),
            "recording upstream needs a fallback response"
        );
        let (ready_tx, ready_rx) = mpsc::channel();
        let (stop_tx, stop_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            ready_tx
                .send(())
                .expect("recording upstream should signal readiness");
            let mut requests = Vec::new();
            loop {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(1)))
                            .expect("recording upstream read timeout should set");
                        let mut request = Vec::new();
                        let mut chunk = [0_u8; 1024];
                        loop {
                            let bytes_read = stream
                                .read(&mut chunk)
                                .expect("recording upstream request should read");
                            if bytes_read == 0 {
                                break;
                            }
                            request.extend_from_slice(&chunk[..bytes_read]);
                            if find_header_end(&request).is_some() {
                                break;
                            }
                        }
                        let response = responses
                            .get(requests.len())
                            .unwrap_or_else(|| responses.last().expect("responses are nonempty"));
                        stream
                            .write_all(response)
                            .expect("recording upstream response should write");
                        stream.flush().expect("recording upstream should flush");
                        requests.push(request);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        match stop_rx.try_recv() {
                            Ok(()) | Err(mpsc::TryRecvError::Disconnected) => return requests,
                            Err(mpsc::TryRecvError::Empty) => {
                                thread::sleep(Duration::from_millis(2));
                            }
                        }
                    }
                    Err(error) => panic!("recording upstream accept failed: {error}"),
                }
            }
        });
        ready_rx
            .recv()
            .expect("recording upstream should become ready");
        let upstream = must_ok(
            parse_upstream(&format!("http://{addr}"), false),
            "recording upstream target should parse",
        );

        (
            upstream,
            RecordingUpstream {
                stop: stop_tx,
                handle,
            },
        )
    }

    fn upstream_request_lines(requests: &[Vec<u8>]) -> Vec<String> {
        requests
            .iter()
            .map(|request| {
                let request =
                    std::str::from_utf8(request).expect("upstream request should be utf8");
                request
                    .lines()
                    .next()
                    .expect("upstream request should have a request line")
                    .to_string()
            })
            .collect()
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
            let permit = ConnectionLimiter::new(1)
                .try_acquire()
                .expect("test connection permit should acquire");
            handle_connection(stream, &runtime, permit).expect("runtime should handle request");
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
            let permit = ConnectionLimiter::new(1)
                .try_acquire()
                .expect("test connection permit should acquire");
            handle_connection(stream, &runtime, permit)
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

    const TEST_SESSION_KEY: [u8; 32] = [0x5a; 32];
    const TEST_INGRESS_CONTINUITY_ID: &str = "test_client_0123456789abcdef";

    fn test_session_authority() -> SessionAuthority {
        SessionAuthority::new(
            vec![eidolon_proxy::session_auth::SessionKeyVersion {
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

    fn session_id_from_cookie(cookie: &str) -> Option<SessionId> {
        let value = cookie.strip_prefix("eidolon_session=")?;
        let mut parts = value.split('.');
        parts.next()?;
        parts.next()?;
        parts.next()?;
        let uuid = uuid::Uuid::parse_str(parts.next()?).ok()?;
        Some(SessionId(uuid))
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
        request_with_cookie_exact(method, path, cookie, headers)
    }

    fn request_with_cookie_exact(
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

    fn cacheable_json_response(status: u16, reason: &str, body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nCache-Control: public, max-age=3600\r\nCDN-Cache-Control: public, max-age=3600\r\nCloudflare-CDN-Cache-Control: public, max-age=3600\r\nSurrogate-Control: max-age=3600\r\nX-Accel-Expires: 3600\r\nETag: \"upstream-v1\"\r\nLast-Modified: Tue, 21 Jul 2026 10:00:00 GMT\r\nExpires: Tue, 21 Jul 2026 11:00:00 GMT\r\nContent-Digest: sha-256=:dGVzdA==:\r\nRepr-Digest: sha-256=:dGVzdA==:\r\nDigest: sha-256=dGVzdA==\r\nContent-MD5: dGVzdA==\r\nAge: 30\r\nAccept-Ranges: bytes\r\nContent-Range: bytes 0-{}/{}\r\nVary: Accept-Encoding\r\nContent-Length: {}\r\n\r\n{}",
            body.len().saturating_sub(1),
            body.len(),
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

    fn assert_session_proof_cache_safety(response: &HttpResponse) {
        assert_eq!(
            header_values(response, "cache-control"),
            vec![SESSION_PROOF_CACHE_CONTROL]
        );
        for name in [
            "accept-ranges",
            "age",
            "cdn-cache-control",
            "cloudflare-cdn-cache-control",
            "content-digest",
            "content-md5",
            "content-range",
            "digest",
            "etag",
            "expires",
            "last-modified",
            "repr-digest",
            "surrogate-control",
            "x-accel-expires",
        ] {
            assert!(
                header_values(response, name).is_empty(),
                "proof response retained stale {name} metadata"
            );
        }
        assert!(header_values(response, "vary")
            .iter()
            .flat_map(|value| value.split(','))
            .any(|token| token.trim().eq_ignore_ascii_case("cookie")));
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
        assert!(!config.require_authenticated_ingress_continuity);
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
        assert_eq!(config.controlled_reality_backend, None);
        assert!(!config.owned_cluster_lab);
    }

    #[test]
    fn remote_renderer_config_requires_a_complete_loopback_pair() {
        let secret_path = write_controlled_reality_backend_secret();
        let config = run_config(&[
            "--controlled-reality-backend-addr",
            "127.0.0.1:9103",
            "--controlled-reality-backend-auth-secret-file",
            path_str(&secret_path, "backend secret path should be utf8"),
        ])
        .expect("complete remote renderer config should parse");

        assert_eq!(
            config.controlled_reality_backend,
            Some(ControlledRealityBackendConfig {
                address: "127.0.0.1:9103".to_string(),
                auth_secret_path: secret_path,
            })
        );
        assert_error_contains(
            &["--controlled-reality-backend-addr", "127.0.0.1:9103"],
            "configured together",
        );
    }

    #[test]
    fn remote_renderer_dns_requires_owned_cluster_lab() {
        let secret_path = write_controlled_reality_backend_secret();
        let target = "eidolon-controlled-reality.shield-controlled-reality.svc.cluster.local:9103";
        let config = run_config(&[
            "--owned-cluster-lab",
            "--controlled-reality-backend-addr",
            target,
            "--controlled-reality-backend-auth-secret-file",
            path_str(&secret_path, "backend secret path should be utf8"),
        ])
        .expect("owned cluster renderer DNS should parse");

        assert_eq!(
            config
                .controlled_reality_backend
                .expect("renderer config should exist")
                .address,
            target
        );
        assert_error_contains(
            &[
                "--controlled-reality-backend-addr",
                target,
                "--controlled-reality-backend-auth-secret-file",
                path_str(&secret_path, "backend secret path should be utf8"),
            ],
            "--owned-cluster-lab",
        );
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
            "--require-authenticated-ingress-continuity",
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
        assert!(config.require_authenticated_ingress_continuity);
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
    fn strict_ingress_continuity_requires_transport_secret() {
        assert_error_contains(
            &["--require-authenticated-ingress-continuity"],
            "--ingress-transport-auth-secret-file",
        );
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
    fn byte_drip_client_hits_total_deadline_and_releases_connection_capacity() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let addr = listener.local_addr().expect("listener should have address");
        let event_log_path = unique_temp_path("slow-client-events.jsonl");
        let mut runtime = test_runtime(
            closed_upstream(),
            &event_log_path,
            unique_temp_path("slow-client-control.txt"),
            SurfaceAction::ProtectedUpstream,
        );
        runtime.client_request_deadline = Duration::from_millis(80);
        let limiter = ConnectionLimiter::new(1);
        let worker_limiter = limiter.clone();
        let handle = thread::spawn(move || {
            let permit = worker_limiter
                .try_acquire()
                .expect("worker permit should acquire");
            let (server, _) = listener.accept().expect("listener should accept");
            let started = Instant::now();

            let error = handle_connection(server, &runtime, permit)
                .expect_err("production request handling must enforce the total deadline");
            assert!(
                matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ),
                "unexpected timeout error: {error}"
            );
            started.elapsed()
        });

        let mut client = TcpStream::connect(addr).expect("client should connect");
        for byte in b"GET /docs HTTP/1.1\r\nHost: proxy.local\r\n"
            .iter()
            .cycle()
            .take(100)
        {
            if client.write_all(&[*byte]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let elapsed = handle.join().expect("slow-client worker should join");

        assert!(elapsed < Duration::from_millis(300));
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
    fn surface_content_overrides_reject_informational_statuses() {
        for status in 100..200 {
            let override_config = SurfaceContentOverride {
                status: Some(status),
                content_type: Some("text/plain".to_string()),
                body: "hint".to_string(),
            };

            let error = override_config
                .validate("test-bait")
                .expect_err("direct surfaces must emit a final response");
            assert!(error
                .to_string()
                .contains("must be a final HTTP status code (200-599)"));
        }

        for status in [200, 204, 304, 599] {
            SurfaceContentOverride {
                status: Some(status),
                content_type: Some("text/plain".to_string()),
                body: "final".to_string(),
            }
            .validate("test-bait")
            .expect("representative final statuses should be accepted");
        }
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
    fn bait_profile_rejects_query_and_fragment_in_expected_action_path() {
        for action_path in [
            "/eidolon-lab/custom-commit?attempt=1",
            "/eidolon-lab/custom-commit#proof",
        ] {
            let path = write_bait_profile(&custom_unsafe_action_profile_json_with_path(
                "PUT",
                action_path,
            ));

            let error = load_bait_profile(&path)
                .expect_err("non-path expected action target should be rejected");

            assert_eq!(
                error.to_string(),
                "bait.expected_action.path must be a canonical path-only value without a query string or fragment"
            );
        }
    }

    #[test]
    fn bait_profile_rejects_percent_encoded_reserved_path_bytes() {
        for action_path in [
            "/eidolon-lab/custom-commit%3Fattempt=1",
            "/eidolon-lab/custom-commit%23proof",
            "/eidolon-lab/custom%2Fcommit",
        ] {
            let path = write_bait_profile(&custom_unsafe_action_profile_json_with_path(
                "PUT",
                action_path,
            ));

            let error = load_bait_profile(&path)
                .expect_err("percent-encoded expected action path should be rejected");

            assert_eq!(
                error.to_string(),
                "bait.expected_action.path must be a canonical path-only value without percent-encoded bytes"
            );
        }
    }

    #[test]
    fn bait_profile_rejects_noncanonical_or_malformed_percent_encoding() {
        for (action_path, expected_error) in [
            (
                "/eidolon-lab/route-%63",
                "bait.expected_action.path must be a canonical path-only value without percent-encoded bytes",
            ),
            (
                "/eidolon-lab/custom-commit%3fproof",
                "bait.expected_action.path must be a canonical path-only value without percent-encoded bytes",
            ),
            (
                "/eidolon-lab/custom-commit%",
                "bait.expected_action.path must be a canonical path-only value: percent escape is incomplete",
            ),
            (
                "/eidolon-lab/custom-commit%GG",
                "bait.expected_action.path must be a canonical path-only value: percent escape is not hexadecimal",
            ),
        ] {
            let path = write_bait_profile(&custom_unsafe_action_profile_json_with_path(
                "PUT",
                action_path,
            ));

            let error = load_bait_profile(&path)
                .expect_err("noncanonical expected action path should be rejected");

            assert_eq!(error.to_string(), expected_error);
        }
    }

    #[test]
    fn minted_bait_profile_requires_signing_secret() {
        let path = write_bait_profile(session_minted_profile_json());
        let loaded = load_bait_profile(&path).expect("minted profile should load");

        assert!(bait_profile_requires_signing_secret(&loaded));
    }

    #[test]
    fn minted_bait_profile_rejects_proof_windows_beyond_replay_retention() {
        let profile = session_minted_profile_json().replace(
            "\"proof_window_seconds\": 60",
            &format!("\"proof_window_seconds\": {}", MAX_BAIT_PROOF_TTL_SECS + 1),
        );
        let path = write_bait_profile(&profile);

        let error = load_bait_profile(&path).expect_err("overlong proof window must fail");

        assert!(error
            .to_string()
            .contains("proof_window_seconds must not exceed"));
    }

    #[test]
    fn proof_cache_policy_requires_generated_minted_content() {
        let docs_path = write_bait_profile(session_minted_profile_json());
        let docs_profile = load_bait_profile(&docs_path).expect("minted docs profile should load");
        let docs_bait = docs_profile
            .registry
            .bait_for_surface("/docs/minted-trace")
            .expect("minted docs bait should exist");
        let rendered_docs =
            render_bait_for_session(docs_bait, SessionId::new(), Some("mint-secret"))
                .expect("minted docs bait should render");

        let generated_docs =
            bait_surface_response(&rendered_docs, &BaitContentOverrides::default());
        assert_eq!(
            generated_docs.cache_policy,
            ResponseCachePolicy::PrivateNoStore
        );

        let overridden_docs = bait_surface_response(
            &rendered_docs,
            &BaitContentOverrides {
                surfaces: HashMap::from([(
                    rendered_docs.id.0.clone(),
                    SurfaceContentOverride {
                        status: Some(200),
                        content_type: Some("text/plain".to_string()),
                        body: "static override without a minted value".to_string(),
                    },
                )]),
                ..BaitContentOverrides::default()
            },
        );
        assert_eq!(overridden_docs.cache_policy, ResponseCachePolicy::Preserve);

        let openapi_path = write_bait_profile(session_minted_openapi_profile_json());
        let openapi_profile =
            load_bait_profile(&openapi_path).expect("minted OpenAPI profile should load");
        let openapi_bait = openapi_profile
            .registry
            .bait_for_surface("/openapi.json")
            .expect("minted OpenAPI bait should exist");
        let rendered_openapi =
            render_bait_for_session(openapi_bait, SessionId::new(), Some("mint-secret"))
                .expect("minted OpenAPI bait should render");
        assert_eq!(
            owned_openapi_discovery_response(
                &rendered_openapi,
                &OpenApiOperationOverride::default()
            )
            .cache_policy,
            ResponseCachePolicy::PrivateNoStore
        );

        let static_openapi_override = OpenApiOperationOverride {
            path_item: Some(json!({"post": {"summary": "static override"}})),
            ..OpenApiOperationOverride::default()
        };
        assert_eq!(
            owned_openapi_discovery_response(&rendered_openapi, &static_openapi_override)
                .cache_policy,
            ResponseCachePolicy::Preserve
        );
        assert_eq!(
            generated_openapi_cache_policy(&rendered_openapi, &static_openapi_override),
            ResponseCachePolicy::Preserve
        );
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
    fn runtime_committed_docs_bait_is_stable_per_session_and_verifies_action() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/m3/bait-profiles/docs-session-minted-probe.json");
        let loaded = load_bait_profile(&path).expect("committed docs profile should load");
        let bait = loaded
            .registry
            .bait_for_surface("/docs/legacy-import")
            .expect("session-minted docs bait should exist")
            .clone();
        assert_eq!(bait.id.0, "rel_2025_04_b7f2");
        assert_eq!(bait.bait_class, BaitClass::Docs);
        let signing_secret: Arc<str> = Arc::from("mint-secret");
        let event_log_path = unique_temp_path("committed-docs-bait-events.jsonl");
        let (upstream, upstream_recorder) =
            spawn_recording_upstream([json_response(r#"{"mode":"unexpected_upstream"}"#)]);
        let runtime = test_runtime_with_bait_profile(
            upstream,
            &event_log_path,
            unique_temp_path("committed-docs-bait-control.txt"),
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
            &get_request_with_cookie("/docs/legacy-import", &cookie_a),
        ));
        let response_a_repeat = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &get_request_with_cookie("/docs/legacy-import", &cookie_a),
        ));
        let response_b = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &get_request_with_cookie("/docs/legacy-import", &cookie_b),
        ));

        assert_eq!(response_a.status, 200);
        assert_eq!(response_a_repeat.status, 200);
        assert_eq!(response_b.status, 200);
        assert_session_proof_cache_safety(&response_a);
        assert_session_proof_cache_safety(&response_a_repeat);
        assert_session_proof_cache_safety(&response_b);

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
        let upstream_requests = upstream_recorder.finish();

        assert_eq!(action_response.status, 202);
        assert!(
            upstream_requests.is_empty(),
            "valid minted action reached protected upstream"
        );
        let action = first_event_of_type(&event_log_path, "bait_action_observed");
        assert_eq!(action["kind"]["bait_id"], "rel_2025_04_b7f2");
        assert_eq!(action["kind"]["bait_class"], "docs");
        assert_eq!(
            action["kind"]["header_value_mint_status"],
            "matched_session_value"
        );
        assert_eq!(
            action["kind"]["header_value_mint"]["header_name"],
            header_name
        );
        assert_eq!(
            action["kind"]["header_value_mint"]["kind"],
            "session_hmac_sha256_v1"
        );
        assert_eq!(action["kind"]["header_value_mint"]["prefix"], "mig");
        assert!(!action.to_string().contains(&header_value_a));
        let exposure = events_of_type(&event_log_path, "bait_exposed")
            .into_iter()
            .rev()
            .find(|event| {
                event["kind"]["bait_id"] == "rel_2025_04_b7f2"
                    && event["session_id"] == action["session_id"]
            })
            .expect("same-session minted exposure should exist");
        assert_eq!(exposure["kind"]["bait_class"], "docs");
        assert_eq!(
            action["kind"]["exposure_id"],
            exposure["kind"]["exposure_id"]
        );
        assert_eq!(
            exposure["kind"]["header_value_mint"]["header_name"],
            header_name
        );
        assert_eq!(exposure["kind"]["header_value_mint"]["prefix"], "mig");
        assert_ne!(
            exposure["request_id"], action["request_id"],
            "surface exposure and follow-through must remain distinct requests"
        );
        assert!(events_of_type(&event_log_path, "request_seen")
            .iter()
            .any(|event| {
                event["request_id"] == action["request_id"]
                    && event["kind"]["path"] == "/api/v2/import/reconcile"
                    && event["kind"]["routing_decision"] == "eidolon_owned"
            }));
        assert!(events_of_type(&event_log_path, "policy_changed")
            .iter()
            .any(|event| {
                event["request_id"] == action["request_id"]
                    && event["kind"]["from"] == "observe"
                    && event["kind"]["to"] == "controlled_reality"
            }));
        assert!(
            events_of_type(&event_log_path, "controlled_reality_entered")
                .iter()
                .any(|event| {
                    event["request_id"] == action["request_id"]
                        && event["policy_state"] == "controlled_reality"
                })
        );
        assert!(!exposure.to_string().contains(&header_value_a));
    }

    #[test]
    fn runtime_session_minted_openapi_rewrite_is_private_no_store() {
        let path = write_bait_profile(session_minted_openapi_profile_json());
        let loaded = load_bait_profile(&path).expect("minted OpenAPI profile should load");
        let event_log_path = unique_temp_path("session-minted-openapi-cache-events.jsonl");
        let original = r#"{"openapi":"3.0.3","info":{"title":"demo","version":"0"},"paths":{}}"#;
        let (upstream, upstream_recorder) =
            spawn_recording_upstream([cacheable_json_response(200, "OK", original)]);
        let runtime = test_runtime_with_bait_profile(
            upstream,
            &event_log_path,
            unique_temp_path("session-minted-openapi-cache-control.txt"),
            loaded,
            Some(Arc::from("mint-secret")),
        );
        let cookie = cookie_header();

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &request_with_cookie(
                "GET",
                "/openapi.json",
                &cookie,
                &[
                    ("If-Modified-Since", "Tue, 21 Jul 2026 10:00:00 GMT"),
                    ("If-None-Match", "\"upstream-v1\""),
                    ("If-Range", "\"upstream-v1\""),
                    ("Range", "bytes=0-99"),
                ],
            ),
        ));
        let upstream_requests = upstream_recorder.finish();

        assert_eq!(response.status, 200);
        assert_session_proof_cache_safety(&response);
        let vary = header_values(&response, "vary").join(",");
        assert!(vary
            .split(',')
            .any(|token| token.trim().eq_ignore_ascii_case("accept-encoding")));
        let document: Value =
            serde_json::from_slice(&response.body).expect("rewritten OpenAPI should be JSON");
        let minted_example = document["paths"]["/api/v2/import/reconcile"]["post"]["parameters"][0]
            ["schema"]["example"]
            .as_str()
            .expect("rewritten OpenAPI should contain a minted example");
        assert!(minted_example.starts_with("oapi_"));

        assert_eq!(upstream_requests.len(), 1);
        let forwarded = String::from_utf8_lossy(&upstream_requests[0]).to_ascii_lowercase();
        for name in [
            "if-modified-since:",
            "if-none-match:",
            "if-range:",
            "range:",
        ] {
            assert!(
                !forwarded.contains(name),
                "proof rewrite forwarded cache request header {name}"
            );
        }
    }

    #[test]
    fn runtime_session_minted_openapi_refusal_preserves_upstream_cache_headers() {
        let path = write_bait_profile(session_minted_openapi_profile_json());
        let loaded = load_bait_profile(&path).expect("minted OpenAPI profile should load");
        let event_log_path = unique_temp_path("session-minted-openapi-refusal-events.jsonl");
        let original = r#"{"openapi": invalid"#;
        let (upstream, upstream_handle) =
            spawn_upstream(cacheable_json_response(200, "OK", original));
        let runtime = test_runtime_with_bait_profile(
            upstream,
            &event_log_path,
            unique_temp_path("session-minted-openapi-refusal-control.txt"),
            loaded,
            Some(Arc::from("mint-secret")),
        );

        let response =
            parse_downstream_response(&run_runtime_request(runtime, &get_request("/openapi.json")));
        upstream_handle.join().expect("upstream thread should join");

        assert_eq!(response.body, original.as_bytes());
        assert_eq!(
            header_values(&response, "cache-control"),
            vec!["public, max-age=3600"]
        );
        assert_eq!(header_values(&response, "etag"), vec!["\"upstream-v1\""]);
        assert_eq!(
            header_values(&response, "last-modified"),
            vec!["Tue, 21 Jul 2026 10:00:00 GMT"]
        );
        assert!(header_values(&response, "vary")
            .iter()
            .flat_map(|value| value.split(','))
            .all(|token| !token.trim().eq_ignore_ascii_case("cookie")));
        assert_event_type_absent(&event_log_path, "bait_exposed");
    }

    #[test]
    fn runtime_session_minted_openapi_does_not_rewrite_partial_response() {
        let path = write_bait_profile(session_minted_openapi_profile_json());
        let loaded = load_bait_profile(&path).expect("minted OpenAPI profile should load");
        let event_log_path = unique_temp_path("session-minted-openapi-partial-events.jsonl");
        let original = r#"{"openapi":"3.0.3","info":{"title":"demo","version":"0"},"paths":{}}"#;
        let upstream_response = format!(
            "HTTP/1.1 206 Partial Content\r\nContent-Type: application/json\r\nCache-Control: public, max-age=3600\r\nETag: \"upstream-v1\"\r\nContent-Range: bytes 0-{}/{}\r\nContent-Length: {}\r\n\r\n{}",
            original.len() - 1,
            original.len(),
            original.len(),
            original
        )
        .into_bytes();
        let (upstream, upstream_handle) = spawn_upstream(upstream_response);
        let runtime = test_runtime_with_bait_profile(
            upstream,
            &event_log_path,
            unique_temp_path("session-minted-openapi-partial-control.txt"),
            loaded,
            Some(Arc::from("mint-secret")),
        );

        let response =
            parse_downstream_response(&run_runtime_request(runtime, &get_request("/openapi.json")));
        upstream_handle.join().expect("upstream thread should join");

        assert_eq!(response.status, 206);
        assert_eq!(response.body, original.as_bytes());
        assert_eq!(
            header_values(&response, "cache-control"),
            vec!["public, max-age=3600"]
        );
        let expected_content_range = format!("bytes 0-{}/{}", original.len() - 1, original.len());
        assert_eq!(
            header_values(&response, "content-range"),
            vec![expected_content_range.as_str()]
        );
        assert_event_type_absent(&event_log_path, "bait_exposed");
    }

    #[test]
    fn runtime_replayed_session_proof_fails_closed_without_upstream_request() {
        let path = write_bait_profile(session_minted_profile_json());
        let loaded = load_bait_profile(&path).expect("profile");
        let bait = loaded
            .registry
            .bait_for_surface("/docs/minted-trace")
            .expect("bait")
            .clone();
        let secret: Arc<str> = Arc::from("mint-secret");
        let session = SessionId::new();
        let cookie = format!("eidolon_session={}", minted_cookie_value(session));
        let rendered = render_bait_for_session(&bait, session, Some(secret.as_ref()))
            .expect("render")
            .into_owned();
        let name = rendered
            .expected_action
            .header_name
            .as_deref()
            .expect("name")
            .to_string();
        let value = rendered.expected_action.header_value.expect("value");
        let event_log = unique_temp_path("replayed-proof-events.jsonl");
        let (upstream, recorder) = spawn_recording_upstream([
            json_response(r#"{"unexpected":1}"#),
            json_response(r#"{"unexpected":2}"#),
        ]);
        let runtime = test_runtime_with_bait_profile(
            upstream,
            &event_log,
            unique_temp_path("replayed-proof-control.txt"),
            loaded,
            Some(secret),
        );

        let first = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &post_request_with_cookie(&bait.expected_action.path, &cookie, &[(&name, &value)]),
        ));
        let replay = parse_downstream_response(&run_runtime_request(
            runtime,
            &post_request_with_cookie(&bait.expected_action.path, &cookie, &[(&name, &value)]),
        ));

        assert_eq!(first.status, 202);
        assert_eq!(replay.status, 403);
        assert!(
            recorder.finish().is_empty(),
            "proof request reached upstream"
        );
        let actions = events_of_type(&event_log, "bait_action_observed");
        assert_eq!(actions.len(), 2);
        assert_eq!(
            actions[0]["kind"]["header_value_mint_status"],
            "matched_session_value"
        );
        assert_eq!(
            actions[1]["kind"]["header_value_mint_status"],
            "replay_seen"
        );
        assert!(actions[1]["kind"]["exposure_id"].is_null());
    }

    #[test]
    fn runtime_rejects_invalid_trusted_ingress_continuity_without_upstream_request() {
        let cases: &[(&str, &[(&str, &str)])] = &[
            (
                "missing",
                &[(session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret")],
            ),
            (
                "duplicate",
                &[
                    (session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
                    (
                        session::INGRESS_CONTINUITY_HEADER_NAME,
                        "client_A_0123456789abcdef",
                    ),
                    (
                        session::INGRESS_CONTINUITY_HEADER_NAME,
                        "client_B_0123456789abcdef",
                    ),
                ],
            ),
            (
                "invalid",
                &[
                    (session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
                    (session::INGRESS_CONTINUITY_HEADER_NAME, "too-short"),
                ],
            ),
            (
                "unauthenticated",
                &[
                    (session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "wrong-secret"),
                    (
                        session::INGRESS_CONTINUITY_HEADER_NAME,
                        "client_A_0123456789abcdef",
                    ),
                ],
            ),
        ];

        for (label, headers) in cases {
            let event_log = unique_temp_path(&format!("continuity-{label}-events.jsonl"));
            let (upstream, recorder) =
                spawn_recording_upstream([json_response(r#"{"mode":"unexpected_upstream"}"#)]);
            let mut runtime = test_runtime(
                upstream,
                &event_log,
                unique_temp_path(&format!("continuity-{label}-control.txt")),
                SurfaceAction::ProtectedUpstream,
            );
            runtime.ingress_transport_auth_secret = Some(Arc::from("edge-secret"));
            runtime.require_authenticated_ingress_continuity = true;
            let request = request_with_cookie_exact("GET", "/ordinary", &cookie_header(), headers);

            let (result, response) = run_runtime_request_result(runtime, &request);

            assert!(
                result.is_ok(),
                "{label} rejection response failed: {result:?}"
            );
            assert!(
                response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"),
                "{label} continuity returned an unexpected response: {response:?}"
            );
            assert!(
                recorder.finish().is_empty(),
                "{label} continuity reached protected upstream"
            );
        }
    }

    #[test]
    fn configured_transport_secret_does_not_break_non_strict_lab_traffic() {
        let event_log = unique_temp_path("optional-continuity-events.jsonl");
        let (upstream, recorder) =
            spawn_recording_upstream([json_response(r#"{"mode":"ordinary_upstream"}"#)]);
        let mut runtime = test_runtime(
            upstream,
            &event_log,
            unique_temp_path("optional-continuity-control.txt"),
            SurfaceAction::ProtectedUpstream,
        );
        runtime.ingress_transport_auth_secret = Some(Arc::from("edge-secret"));

        let response =
            parse_downstream_response(&run_runtime_request(runtime, &get_request("/ordinary")));

        assert_eq!(response.body, br#"{"mode":"ordinary_upstream"}"#);
        assert_eq!(recorder.finish().len(), 1);
    }

    #[test]
    fn runtime_replay_capacity_failure_fails_closed_without_upstream_request() {
        let path = write_bait_profile(session_minted_profile_json());
        let loaded = load_bait_profile(&path).expect("profile");
        let bait = loaded
            .registry
            .bait_for_surface("/docs/minted-trace")
            .expect("bait")
            .clone();
        let secret: Arc<str> = Arc::from("mint-secret");
        let session = SessionId::new();
        let cookie = format!("eidolon_session={}", minted_cookie_value(session));
        let rendered = render_bait_for_session(&bait, session, Some(secret.as_ref()))
            .expect("render")
            .into_owned();
        let name = rendered
            .expected_action
            .header_name
            .as_deref()
            .expect("name")
            .to_string();
        let value = rendered.expected_action.header_value.expect("value");
        let event_log = unique_temp_path("proof-capacity-events.jsonl");
        let (upstream, recorder) = spawn_recording_upstream([json_response(r#"{"unexpected":1}"#)]);
        let runtime = test_runtime_with_bait_profile(
            upstream,
            &event_log,
            unique_temp_path("proof-capacity-control.txt"),
            loaded,
            Some(secret),
        );
        {
            let mut store = runtime.consumed_bait_proofs.lock().expect("store");
            for index in 0..MAX_CONSUMED_BAIT_PROOFS {
                store.consumed.insert(
                    (
                        SessionId::new(),
                        BaitId(format!("bait-{index}")),
                        proof_digest(&format!("proof-{index}")),
                    ),
                    u64::MAX,
                );
            }
        }

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &post_request_with_cookie(&bait.expected_action.path, &cookie, &[(&name, &value)]),
        ));

        assert_eq!(response.status, 403);
        assert!(
            recorder.finish().is_empty(),
            "capacity failure reached upstream"
        );
        let action = first_event_of_type(&event_log, "bait_action_observed");
        assert_eq!(
            action["kind"]["header_value_mint_status"],
            "replay_state_capacity_exceeded"
        );
        assert!(action["kind"]["exposure_id"].is_null());
    }

    #[test]
    fn runtime_replay_after_store_rebuild_fails_closed_without_upstream_request() {
        let path = write_bait_profile(session_minted_profile_json());
        let loaded = load_bait_profile(&path).expect("profile");
        let bait = loaded
            .registry
            .bait_for_surface("/docs/minted-trace")
            .expect("bait")
            .clone();
        let secret: Arc<str> = Arc::from("mint-secret");
        let session = SessionId::new();
        let cookie = format!("eidolon_session={}", minted_cookie_value(session));
        let rendered = render_bait_for_session(&bait, session, Some(secret.as_ref()))
            .expect("render")
            .into_owned();
        let name = rendered
            .expected_action
            .header_name
            .as_deref()
            .expect("name")
            .to_string();
        let value = rendered.expected_action.header_value.expect("value");
        let event_log = unique_temp_path("restart-replay-events.jsonl");
        let (first_upstream, first_recorder) =
            spawn_recording_upstream([json_response(r#"{"unexpected":1}"#)]);
        let first_runtime = test_runtime_with_bait_profile(
            first_upstream,
            &event_log,
            unique_temp_path("restart-replay-first-control.txt"),
            loaded.clone(),
            Some(Arc::clone(&secret)),
        );

        let first = parse_downstream_response(&run_runtime_request(
            first_runtime,
            &post_request_with_cookie(&bait.expected_action.path, &cookie, &[(&name, &value)]),
        ));
        assert_eq!(first.status, 202);
        assert!(
            first_recorder.finish().is_empty(),
            "first proof reached upstream"
        );

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let restored = ConsumedBaitProofStore::open_or_rebuild(
            &event_log,
            &loaded.registry,
            Some(secret.as_ref()),
            now,
        )
        .expect("restore consumed proofs");
        let (second_upstream, second_recorder) =
            spawn_recording_upstream([json_response(r#"{"unexpected":2}"#)]);
        let mut second_runtime = test_runtime_with_bait_profile(
            second_upstream,
            &event_log,
            unique_temp_path("restart-replay-second-control.txt"),
            loaded,
            Some(secret),
        );
        second_runtime.consumed_bait_proofs = Arc::new(Mutex::new(restored));

        let replay = parse_downstream_response(&run_runtime_request(
            second_runtime,
            &post_request_with_cookie(&bait.expected_action.path, &cookie, &[(&name, &value)]),
        ));

        assert_eq!(replay.status, 403);
        assert!(
            second_recorder.finish().is_empty(),
            "restart replay reached upstream"
        );
        let actions = events_of_type(&event_log, "bait_action_observed");
        assert_eq!(actions.len(), 2);
        assert_eq!(
            actions[1]["kind"]["header_value_mint_status"],
            "replay_seen"
        );
        assert!(actions[1]["kind"]["exposure_id"].is_null());
    }

    #[test]
    fn runtime_replay_persistence_failure_fails_closed_without_upstream_request() {
        let path = write_bait_profile(session_minted_profile_json());
        let loaded = load_bait_profile(&path).expect("profile");
        let bait = loaded
            .registry
            .bait_for_surface("/docs/minted-trace")
            .expect("bait")
            .clone();
        let secret: Arc<str> = Arc::from("mint-secret");
        let session = SessionId::new();
        let cookie = format!("eidolon_session={}", minted_cookie_value(session));
        let rendered = render_bait_for_session(&bait, session, Some(secret.as_ref()))
            .expect("render")
            .into_owned();
        let name = rendered
            .expected_action
            .header_name
            .as_deref()
            .expect("name")
            .to_string();
        let value = rendered.expected_action.header_value.expect("value");
        let event_log = unique_temp_path("proof-persistence-failure-events.jsonl");
        let (upstream, recorder) = spawn_recording_upstream([json_response(r#"{"unexpected":1}"#)]);
        let mut runtime = test_runtime_with_bait_profile(
            upstream,
            &event_log,
            unique_temp_path("proof-persistence-failure-control.txt"),
            loaded,
            Some(secret),
        );
        runtime.consumed_bait_proofs = Arc::new(Mutex::new(ConsumedBaitProofStore {
            path: Some(
                unique_temp_path("missing-proof-persistence-parent").join("proof-state.json"),
            ),
            ..ConsumedBaitProofStore::default()
        }));

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &post_request_with_cookie(&bait.expected_action.path, &cookie, &[(&name, &value)]),
        ));

        assert_eq!(response.status, 403);
        assert!(
            recorder.finish().is_empty(),
            "proof persistence failure reached protected upstream"
        );
        let action = first_event_of_type(&event_log, "bait_action_observed");
        assert_eq!(
            action["kind"]["header_value_mint_status"],
            "replay_state_unavailable"
        );
        assert!(action["kind"]["exposure_id"].is_null());
    }

    #[test]
    fn runtime_expired_session_proof_fails_closed_without_upstream_request() {
        let path = write_bait_profile(session_minted_profile_json());
        let loaded = load_bait_profile(&path).expect("profile");
        let bait = loaded
            .registry
            .bait_for_surface("/docs/minted-trace")
            .expect("bait")
            .clone();
        let secret: Arc<str> = Arc::from("mint-secret");
        let session = SessionId::new();
        let cookie = format!("eidolon_session={}", minted_cookie_value(session));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        let rendered = eidolon_bait::render_bait_for_session_at(
            &bait,
            session,
            Some(secret.as_ref()),
            now.saturating_sub(180),
        )
        .expect("render")
        .into_owned();
        let name = rendered
            .expected_action
            .header_name
            .as_deref()
            .expect("name")
            .to_string();
        let value = rendered.expected_action.header_value.expect("value");
        let event_log = unique_temp_path("expired-proof-events.jsonl");
        let (upstream, recorder) = spawn_recording_upstream([json_response(r#"{"unexpected":1}"#)]);
        let runtime = test_runtime_with_bait_profile(
            upstream,
            &event_log,
            unique_temp_path("expired-proof-control.txt"),
            loaded,
            Some(secret),
        );

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &post_request_with_cookie(&bait.expected_action.path, &cookie, &[(&name, &value)]),
        ));

        assert_eq!(response.status, 403);
        assert!(
            recorder.finish().is_empty(),
            "expired proof reached upstream"
        );
        let action = first_event_of_type(&event_log, "bait_action_observed");
        assert_eq!(
            action["kind"]["header_value_mint_status"],
            "expired_session_value"
        );
        assert!(action["kind"]["exposure_id"].is_null());
    }

    #[test]
    fn runtime_session_minted_bait_from_other_session_fails_closed_without_correlation() {
        let path = write_bait_profile(session_minted_profile_json());
        let loaded = load_bait_profile(&path).expect("minted profile should load");
        let bait = loaded
            .registry
            .bait_for_surface("/docs/minted-trace")
            .expect("minted bait should exist")
            .clone();
        let signing_secret: Arc<str> = Arc::from("mint-secret");
        let event_log_path = unique_temp_path("session-minted-bait-replay-events.jsonl");
        let (upstream, upstream_recorder) =
            spawn_recording_upstream([json_response(r#"{"mode":"unexpected_upstream"}"#)]);
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
        let upstream_requests = upstream_recorder.finish();

        assert_eq!(exposure_a.status, 200);
        assert_eq!(exposure_b.status, 200);
        assert_eq!(replay_response.status, 403);
        assert!(
            upstream_requests.is_empty(),
            "request reached protected upstream"
        );

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
        assert_eq!(
            replay_action["kind"]["header_value_mint_status"],
            "session_value_mismatch"
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
    fn runtime_missing_session_proof_fails_closed_with_explicit_outcome() {
        let path = write_bait_profile(session_minted_profile_json());
        let loaded = load_bait_profile(&path).expect("profile");
        let bait = loaded
            .registry
            .bait_for_surface("/docs/minted-trace")
            .expect("bait")
            .clone();
        let event_log = unique_temp_path("missing-proof-events.jsonl");
        let (upstream, recorder) = spawn_recording_upstream([json_response(r#"{"unexpected":1}"#)]);
        let runtime = test_runtime_with_bait_profile(
            upstream,
            &event_log,
            unique_temp_path("missing-proof-control.txt"),
            loaded,
            Some(Arc::from("mint-secret")),
        );

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &post_request_with_cookie(&bait.expected_action.path, &cookie_header(), &[]),
        ));

        assert_eq!(response.status, 403);
        assert!(
            recorder.finish().is_empty(),
            "missing proof reached upstream"
        );
        let action = first_event_of_type(&event_log, "bait_action_observed");
        assert_eq!(
            action["kind"]["header_value_mint_status"],
            "missing_session_value"
        );
        assert!(action["kind"]["exposure_id"].is_null());
    }

    #[test]
    fn runtime_invalid_session_minted_bait_value_fails_closed() {
        let path = write_bait_profile(session_minted_profile_json());
        let loaded = load_bait_profile(&path).expect("minted profile should load");
        let bait = loaded
            .registry
            .bait_for_surface("/docs/minted-trace")
            .expect("minted bait should exist")
            .clone();
        let header_name = bait
            .expected_action
            .header_name
            .as_deref()
            .expect("minted bait should keep header name")
            .to_string();
        let event_log_path = unique_temp_path("invalid-minted-bait-events.jsonl");
        let (upstream, upstream_recorder) =
            spawn_recording_upstream([json_response(r#"{"mode":"unexpected_upstream"}"#)]);
        let runtime = test_runtime_with_bait_profile(
            upstream,
            &event_log_path,
            unique_temp_path("invalid-minted-bait-control.txt"),
            loaded,
            Some(Arc::from("mint-secret")),
        );

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &post_request_with_cookie(
                &bait.expected_action.path,
                &cookie_header(),
                &[(&header_name, "minted.not-a-valid-proof")],
            ),
        ));
        let upstream_requests = upstream_recorder.finish();

        assert_eq!(response.status, 403);
        assert!(
            upstream_requests.is_empty(),
            "request reached protected upstream"
        );
        let rejected_action = first_event_of_type(&event_log_path, "bait_action_observed");
        assert_eq!(rejected_action["kind"]["bait_id"], "minted_trace");
        assert!(rejected_action["kind"]["exposure_id"].is_null());
        assert_eq!(
            rejected_action["kind"]["header_value_mint_status"],
            "malformed_session_value"
        );
        assert_event_routing(&event_log_path, "request_seen", "eidolon_owned");
    }

    #[test]
    fn parses_http_request_with_body() {
        let mut request_bytes = &b"POST /api/v1/imports HTTP/1.1\r\nHost: proxy.local\r\nContent-Length: 16\r\n\r\n{\"source\":\"lab\"}"[..];
        let request = read_http_request(&mut request_bytes)
            .expect("request should parse")
            .expect("request should be present");

        assert_eq!(request.method, "POST");
        assert_eq!(request.target, "/api/v1/imports");
        assert_eq!(request.version, HttpVersion::Http11);
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

        let forwarded = String::from_utf8(request_to_upstream_bytes(&request, &upstream).unwrap())
            .expect("forwarded request should be utf8");

        assert!(forwarded.starts_with("GET /docs?view=full HTTP/1.1\r\n"));
        assert!(forwarded.contains("\r\nHost: 127.0.0.1:9001\r\n"));
        assert!(forwarded.contains("\r\nConnection: close\r\n"));
        assert!(forwarded.contains("\r\nUser-Agent: eidolon-test\r\n"));
        assert!(!forwarded.contains("keep-alive"));
    }

    #[test]
    fn upstream_forwarding_uses_the_canonical_request_target() {
        let upstream = must_ok(
            parse_upstream("http://127.0.0.1:9001", false),
            "upstream should parse",
        );
        let mut request_bytes =
            &b"GET http://proxy.local/do%63s?x=%7e&slash=%2f HTTP/1.1\r\nHost: proxy.local\r\n\r\n"
                [..];
        let request = read_http_request(&mut request_bytes)
            .expect("request should parse")
            .expect("request should be present");

        assert_eq!(
            normalized_event_path(&request).expect("target should canonicalize"),
            "/docs?x=~&slash=%2F"
        );
        let forwarded = String::from_utf8(request_to_upstream_bytes(&request, &upstream).unwrap())
            .expect("forwarded request should be utf8");
        assert!(forwarded.starts_with("GET /docs?x=~&slash=%2F HTTP/1.1\r\n"));
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
            version: HttpVersion::Http11,
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

        let forwarded = String::from_utf8(request_to_upstream_bytes(&request, &upstream).unwrap())
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

        let forwarded = String::from_utf8(request_to_upstream_bytes(&request, &upstream).unwrap())
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
            canonicalize_request_target("http://127.0.0.1:8080/openapi.json?x=1").unwrap(),
            "/openapi.json?x=1"
        );
        assert_eq!(
            canonicalize_request_target("http://127.0.0.1:8080").unwrap(),
            "/"
        );
    }

    #[test]
    fn rejects_all_request_transfer_codings_for_v0() {
        for coding in ["chunked", "gzip", "identity"] {
            let request =
                format!("POST /api/v1/imports HTTP/1.1\r\nTransfer-Encoding: {coding}\r\n\r\n");
            let error = read_http_request(&mut request.as_bytes())
                .expect_err("unsupported transfer coding should fail");

            assert!(error.to_string().contains("Transfer-Encoding"));
        }
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
    fn rejects_whitespace_before_header_colon() {
        let mut request_bytes = &b"GET /docs HTTP/1.1\r\nHost : trusted.example\r\n\r\n"[..];
        let error = read_http_request(&mut request_bytes)
            .expect_err("whitespace before the header colon must be rejected");

        assert!(error.to_string().contains("valid token"));
    }

    #[test]
    fn rejects_control_bytes_in_header_values() {
        let mut request_bytes =
            &b"GET /docs HTTP/1.1\r\nHost: proxy.local\r\nX-Test: safe\0smuggled\r\n\r\n"[..];
        let error = read_http_request(&mut request_bytes)
            .expect_err("control bytes in header values must be rejected");

        assert!(error.to_string().contains("invalid bytes"));
    }

    #[test]
    fn rejects_ambiguous_or_unsupported_http_start_lines() {
        for raw in [
            "GET  /docs HTTP/1.1\r\nHost: proxy.local\r\n\r\n",
            "GET\t/docs\tHTTP/1.1\r\nHost: proxy.local\r\n\r\n",
            "GET /docs HTTP/2.0\r\nHost: proxy.local\r\n\r\n",
        ] {
            assert!(
                read_http_request(&mut raw.as_bytes()).is_err(),
                "request start line should be rejected: {raw:?}"
            );
        }

        for raw in [
            "HTTP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 20 OK\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 600 Unknown\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 200 OK\nInjected: yes\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 200 OK\0Injected\r\nContent-Length: 0\r\n\r\n",
        ] {
            assert!(
                read_http_response(&mut raw.as_bytes()).is_err(),
                "response start line should be rejected: {raw:?}"
            );
        }
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
    fn skips_bounded_informational_responses_before_the_final_response() {
        let mut response_bytes = &b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"[..];
        let response =
            read_http_response(&mut response_bytes).expect("final response should parse");

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok");
    }

    #[test]
    fn rejects_upstream_protocol_switching() {
        let mut response_bytes =
            &b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"[..];
        let error = read_http_response(&mut response_bytes).expect_err("101 should fail");

        assert!(error.to_string().contains("protocol switching"));
    }

    #[test]
    fn head_and_no_content_statuses_never_read_or_emit_a_message_body() {
        let mut head_bytes = &b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n"[..];
        let head = read_http_response_for_method(&mut head_bytes, "HEAD")
            .expect("HEAD response should not wait for a body");
        assert!(head.body.is_empty());

        for status_line in ["204 No Content", "304 Not Modified"] {
            let raw = format!("HTTP/1.1 {status_line}\r\nContent-Length: 7\r\n\r\nignored");
            let response = read_http_response(&mut raw.as_bytes())
                .expect("no-body status should not consume a body");
            assert!(response.body.is_empty());
            assert!(!String::from_utf8(response.to_http_bytes_for_method("GET"))
                .expect("response should be utf8")
                .ends_with("ignored"));
        }
    }

    #[test]
    fn no_body_responses_still_validate_framing_headers() {
        for (method, raw) in [
            (
                "HEAD",
                "HTTP/1.1 200 OK\r\nContent-Length: invalid\r\n\r\n",
            ),
            (
                "HEAD",
                "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
            ),
            (
                "GET",
                "HTTP/1.1 304 Not Modified\r\nContent-Length: invalid\r\n\r\n",
            ),
            (
                "GET",
                "HTTP/1.1 204 No Content\r\nTransfer-Encoding: gzip\r\n\r\n",
            ),
            (
                "GET",
                "HTTP/1.1 100 Continue\r\nContent-Length: invalid\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            ),
        ] {
            assert!(
                read_http_response_for_method(&mut raw.as_bytes(), method).is_err(),
                "{method} response framing should be rejected: {raw:?}"
            );
        }

        let both =
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n0\r\n\r\n";
        let error = read_http_response(&mut both.as_bytes())
            .expect_err("Transfer-Encoding plus Content-Length must be rejected");
        assert!(error.to_string().contains("must not combine"));
    }

    #[test]
    fn canonicalizes_plain_and_absolute_form_targets() {
        assert_eq!(
            canonicalize_request_target("/docs/legacy-import").expect("plain path"),
            "/docs/legacy-import"
        );
        assert_eq!(
            canonicalize_request_target("http://proxy.local/docs/legacy-import")
                .expect("absolute form"),
            "/docs/legacy-import"
        );
        assert_eq!(
            canonicalize_request_target("/docs?topic=imports&x=1").expect("query preserved"),
            "/docs?topic=imports&x=1"
        );
        assert_eq!(
            canonicalize_request_target("http://proxy.local?topic=%7e&slash=%2f")
                .expect("absolute form without a path"),
            "/?topic=~&slash=%2F"
        );
        assert_eq!(
            canonicalize_request_target("*").expect("asterisk form"),
            "*"
        );
    }

    #[test]
    fn canonicalizes_unreserved_percent_encodings_once() {
        assert_eq!(
            canonicalize_request_target("/api/v2/import/recon%63ile").expect("unreserved encoding"),
            "/api/v2/import/reconcile"
        );
        assert_eq!(
            canonicalize_request_target("/d%6Fcs/a%7Eb%2Dc_d.e").expect("mixed unreserved"),
            "/docs/a~b-c_d.e"
        );
        // Idempotent: the canonical form re-canonicalizes to itself.
        assert_eq!(
            canonicalize_request_target("/api/v2/import/reconcile").expect("canonical form again"),
            "/api/v2/import/reconcile"
        );
    }

    #[test]
    fn rejects_reserved_and_invalid_percent_encodings() {
        for target in [
            "/api%2Fops",
            "/api%2fops",
            "/a%25b",
            "/%2e%2e/etc",
            "/a%00b",
            "/a%3Fb",
            "/a%23b",
            "/a%4",
            "/a%zzb",
            "/%80%80/a",
        ] {
            assert!(
                canonicalize_request_target(target).is_err(),
                "{target} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_dot_segments_backslashes_empty_segments_and_fragments() {
        for target in [
            "/a/./b",
            "/a/../b",
            "/./x",
            "/../x",
            "/a/b/../../x",
            "/a\\b",
            "/a//b",
            "//a/b",
            "/docs#fragment",
        ] {
            assert!(
                canonicalize_request_target(target).is_err(),
                "{target} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_malformed_absolute_form_authority() {
        for target in [
            "http:///docs",
            "http://?x=1",
            "http://",
            "http://user@proxy.local/docs",
            "http://proxy.local:/docs",
            "http://proxy.local:0/docs",
            "http://bad..host/docs",
            "http://-bad.host/docs",
            "http://[not-an-ip]/docs",
            "http://proxy%2Elocal/docs",
        ] {
            assert!(
                canonicalize_request_target(target).is_err(),
                "{target} must be rejected"
            );
        }
    }

    #[test]
    fn absolute_form_authority_must_agree_with_host_header() {
        let request = HttpRequest {
            method: "GET".to_string(),
            target: "http://proxy.local/docs".to_string(),
            version: HttpVersion::Http11,
            headers: vec![HttpHeader {
                name: "Host".to_string(),
                value: "other.local".to_string(),
            }],
            body: Vec::new(),
        };
        assert!(normalized_event_path(&request).is_err());

        let matching = HttpRequest {
            headers: vec![HttpHeader {
                name: "Host".to_string(),
                value: "proxy.local:80".to_string(),
            }],
            ..request
        };
        assert_eq!(
            normalized_event_path(&matching).expect("default ports should agree"),
            "/docs"
        );
    }

    #[test]
    fn origin_form_requires_exactly_one_valid_host_header() {
        let request = HttpRequest {
            method: "GET".to_string(),
            target: "/docs".to_string(),
            version: HttpVersion::Http11,
            headers: Vec::new(),
            body: Vec::new(),
        };
        assert!(normalized_event_path(&request).is_err());

        let malformed = HttpRequest {
            headers: vec![HttpHeader {
                name: "Host".to_string(),
                value: "bad..host".to_string(),
            }],
            ..request.clone()
        };
        assert!(normalized_event_path(&malformed).is_err());

        let duplicate = HttpRequest {
            headers: vec![
                HttpHeader {
                    name: "Host".to_string(),
                    value: "proxy.local".to_string(),
                },
                HttpHeader {
                    name: "host".to_string(),
                    value: "trusted.local".to_string(),
                },
            ],
            ..request.clone()
        };
        assert!(normalized_event_path(&duplicate).is_err());

        let valid = HttpRequest {
            headers: vec![HttpHeader {
                name: "Host".to_string(),
                value: "proxy.local:8080".to_string(),
            }],
            ..request
        };
        assert_eq!(
            normalized_event_path(&valid).expect("valid Host should pass"),
            "/docs"
        );
    }

    #[test]
    fn percent_encoding_canonicalization_is_exhaustive_and_idempotent_for_ascii() {
        for byte in 0_u8..=127 {
            let target = format!("/a%{byte:02X}b");
            let result = canonicalize_request_target(&target);
            let is_unreserved = matches!(
                byte,
                b'A'..=b'Z'
                    | b'a'..=b'z'
                    | b'0'..=b'9'
                    | b'-'
                    | b'.'
                    | b'_'
                    | b'~'
            );
            if is_unreserved {
                let expected = format!("/a{}b", byte as char);
                let canonical = result.unwrap_or_else(|error| {
                    panic!("unreserved byte {byte:#04x} should canonicalize: {error}")
                });
                assert_eq!(canonical, expected);
                assert_eq!(
                    canonicalize_request_target(&canonical)
                        .expect("canonical target should remain valid"),
                    canonical
                );
            } else {
                assert!(
                    result.is_err(),
                    "reserved byte {byte:#04x} must be rejected in a path"
                );
            }
        }
    }

    #[test]
    fn malformed_query_percent_encodings_are_rejected() {
        for target in ["/docs?x=%", "/docs?x=%2", "/docs?x=%GG"] {
            assert!(
                canonicalize_request_target(target).is_err(),
                "{target} must be rejected"
            );
        }
    }

    #[test]
    fn raw_target_characters_follow_the_conservative_uri_grammar() {
        for byte in 0x21_u8..=0x7e {
            if matches!(byte, b'%' | b'?' | b'#') {
                continue;
            }
            let target = format!("/a{}b", byte as char);
            let expected = byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'-' | b'.'
                        | b'_'
                        | b'~'
                        | b'!'
                        | b'$'
                        | b'&'
                        | b'\''
                        | b'('
                        | b')'
                        | b'*'
                        | b'+'
                        | b','
                        | b'='
                        | b':'
                        | b'@'
                        | b'/'
                );
            assert_eq!(
                canonicalize_request_target(&target).is_ok(),
                expected,
                "unexpected raw path treatment for byte {byte:#04x}"
            );
        }

        for byte in 0x21_u8..=0x7e {
            if matches!(byte, b'%' | b'#') {
                continue;
            }
            let target = format!("/docs?x={}y", byte as char);
            let expected = byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'-' | b'.'
                        | b'_'
                        | b'~'
                        | b'!'
                        | b'$'
                        | b'&'
                        | b'\''
                        | b'('
                        | b')'
                        | b'*'
                        | b'+'
                        | b','
                        | b'='
                        | b':'
                        | b'@'
                        | b'/'
                        | b'?'
                );
            assert_eq!(
                canonicalize_request_target(&target).is_ok(),
                expected,
                "unexpected raw query treatment for byte {byte:#04x}"
            );
        }

        assert!(canonicalize_request_target("/docs;ignored").is_err());
    }

    #[test]
    fn ambiguous_targets_reject_deterministically() {
        for target in ["/a/../b", "/api%2Fops", "/docs#x", "/a//b"] {
            let first = canonicalize_request_target(target);
            let second = canonicalize_request_target(target);
            assert!(first.is_err() && second.is_err());
            assert_eq!(
                first.expect_err("first").to_string(),
                second.expect_err("second").to_string()
            );
        }
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
            cache_policy: ResponseCachePolicy::Preserve,
        };

        apply_response_headers(&mut response, &session, "GET");

        assert!(header_values(&response, "transfer-encoding").is_empty());
        assert!(header_values(&response, "keep-alive").is_empty());
        assert!(header_values(&response, "trailer").is_empty());
        assert!(header_values(&response, "upgrade").is_empty());
        assert!(header_values(&response, "x-hop-by-hop").is_empty());
        assert_eq!(header_values(&response, "content-length"), vec!["2"]);
        assert_eq!(header_values(&response, "connection"), vec!["close"]);
    }

    #[test]
    fn downstream_head_and_no_content_headers_match_body_semantics() {
        let mut authority = test_session_authority();
        let session = session::derive_session_from_headers(
            &mut authority,
            [("Cookie", cookie_header())],
            None,
            now_unix_secs(),
        );
        let mut head = HttpResponse {
            version: "HTTP/1.1".to_string(),
            status: 200,
            reason: "OK".to_string(),
            headers: vec![HttpHeader {
                name: "Content-Length".to_string(),
                value: "99".to_string(),
            }],
            body: Vec::new(),
            cache_policy: ResponseCachePolicy::Preserve,
        };
        apply_response_headers(&mut head, &session, "HEAD");
        assert_eq!(header_values(&head, "content-length"), vec!["99"]);
        assert!(String::from_utf8(head.to_http_bytes_for_method("HEAD"))
            .expect("HEAD response should be utf8")
            .ends_with("\r\n\r\n"));

        let mut no_content = HttpResponse {
            version: "HTTP/1.1".to_string(),
            status: 204,
            reason: "No Content".to_string(),
            headers: vec![HttpHeader {
                name: "Content-Length".to_string(),
                value: "7".to_string(),
            }],
            body: b"ignored".to_vec(),
            cache_policy: ResponseCachePolicy::Preserve,
        };
        apply_response_headers(&mut no_content, &session, "GET");
        assert!(header_values(&no_content, "content-length").is_empty());
        assert!(
            String::from_utf8(no_content.to_http_bytes_for_method("GET"))
                .expect("204 response should be utf8")
                .ends_with("\r\n\r\n")
        );
    }

    #[test]
    fn bait_exposure_store_evicts_oldest_exposure_at_cap() {
        let mut store = BaitExposureStore::default();
        let oldest_session_id = SessionId::new();
        let oldest_bait_id = BaitId("oldest".to_string());
        store
            .record_exposure(
                oldest_session_id,
                oldest_bait_id.clone(),
                ExposureId("oldest-exposure".to_string()),
            )
            .expect("exposure should record");

        for index in 0..MAX_BAIT_EXPOSURES {
            store
                .record_exposure(
                    SessionId::new(),
                    BaitId(format!("bait-{index}")),
                    ExposureId(format!("exp-{index}")),
                )
                .expect("exposure should record");
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
        store
            .record_exposure(
                session_id,
                bait_id.clone(),
                ExposureId("old-exposure".to_string()),
            )
            .expect("exposure should record");

        for index in 0..MAX_BAIT_EXPOSURES - 1 {
            store
                .record_exposure(
                    SessionId::new(),
                    BaitId(format!("bait-{index}")),
                    ExposureId(format!("exp-{index}")),
                )
                .expect("exposure should record");
        }
        store
            .record_exposure(
                session_id,
                bait_id.clone(),
                ExposureId("new-exposure".to_string()),
            )
            .expect("exposure should record");
        store
            .record_exposure(
                SessionId::new(),
                BaitId("overflow".to_string()),
                ExposureId("overflow-exp".to_string()),
            )
            .expect("exposure should record");

        assert_eq!(store.exposures.len(), MAX_BAIT_EXPOSURES);
        assert_eq!(
            store.exposure_for_action(session_id, &bait_id),
            Some(ExposureId("new-exposure".to_string()))
        );
    }

    #[test]
    fn bait_exposure_store_expires_records_by_ttl() {
        let mut store = BaitExposureStore::default();
        let session_id = SessionId::new();
        let bait_id = BaitId("ttl-bait".to_string());
        let exposure_id = ExposureId("ttl-exposure".to_string());
        let observed_at = 1_000;

        store
            .record_exposure_at(
                session_id,
                bait_id.clone(),
                exposure_id.clone(),
                observed_at,
                observed_at,
            )
            .expect("exposure should record");

        assert_eq!(
            store.exposure_for_action_at(
                session_id,
                &bait_id,
                observed_at + BAIT_EXPOSURE_TTL_SECS - 1,
            ),
            Some(exposure_id)
        );
        assert_eq!(
            store.exposure_for_action_at(
                session_id,
                &bait_id,
                observed_at + BAIT_EXPOSURE_TTL_SECS,
            ),
            None
        );

        let fresh_session = SessionId::new();
        store
            .record_exposure_at(
                fresh_session,
                BaitId("fresh".to_string()),
                ExposureId("fresh-exposure".to_string()),
                observed_at + BAIT_EXPOSURE_TTL_SECS,
                observed_at + BAIT_EXPOSURE_TTL_SECS,
            )
            .expect("fresh exposure should record");
        assert_eq!(store.len(), 1);
        assert_eq!(store.ttl_evicted, 1);
    }

    #[test]
    fn bait_exposure_store_starts_empty_when_event_log_is_missing() {
        let path = unique_temp_path("missing-exposure-events.jsonl");

        let store = BaitExposureStore::from_event_log(&path).expect("missing log should rebuild");

        assert_eq!(store.len(), 0);
    }

    #[test]
    fn consumed_proof_store_is_per_proof_and_fails_closed_at_capacity() {
        let mut store = ConsumedBaitProofStore::default();
        let session = SessionId::new();
        let bait = BaitId("minted".to_string());

        assert_eq!(
            store.check_and_mark(session, bait.clone(), "proof-a".to_string(), 100, 0),
            ConsumeProofOutcome::Fresh
        );
        assert_eq!(
            store.check_and_mark(session, bait.clone(), "proof-a".to_string(), 100, 0),
            ConsumeProofOutcome::Replay
        );
        assert_eq!(
            store.check_and_mark(session, bait, "proof-b".to_string(), 100, 0),
            ConsumeProofOutcome::Fresh
        );

        while store.consumed.len() < MAX_CONSUMED_BAIT_PROOFS {
            let index = store.consumed.len();
            assert_eq!(
                store.check_and_mark(
                    SessionId::new(),
                    BaitId(format!("bait-{index}")),
                    format!("proof-{index}"),
                    100,
                    0,
                ),
                ConsumeProofOutcome::Fresh
            );
        }
        assert_eq!(
            store.check_and_mark(
                SessionId::new(),
                BaitId("overflow".to_string()),
                "overflow".to_string(),
                100,
                0,
            ),
            ConsumeProofOutcome::CapacityExceeded
        );
        assert_eq!(store.consumed.len(), MAX_CONSUMED_BAIT_PROOFS);
        assert_eq!(
            store.check_and_mark(
                SessionId::new(),
                BaitId("after-expiry".to_string()),
                "fresh".to_string(),
                200,
                100,
            ),
            ConsumeProofOutcome::Fresh
        );
        assert_eq!(store.consumed.len(), 1);
    }

    #[test]
    fn consumed_proof_store_persists_replay_state_without_raw_proof_values() {
        let profile_path = write_bait_profile(session_minted_profile_json());
        let loaded = load_bait_profile(&profile_path).expect("profile");
        let event_log = unique_temp_path("consumed-proof-state.jsonl");
        let session = SessionId::new();
        let bait = BaitId("durable-proof".to_string());
        let proof = "secret-proof-value".to_string();
        let state_path = state_path_for_event_log(&event_log, ".consumed-proofs.json");

        let mut store =
            ConsumedBaitProofStore::open_or_rebuild(&event_log, &loaded.registry, None, 1_000)
                .expect("store should open");
        assert_eq!(
            store.check_and_mark(session, bait.clone(), proof.clone(), 1_100, 1_000),
            ConsumeProofOutcome::Fresh
        );
        drop(store);

        let state = fs::read_to_string(&state_path).expect("state should persist");
        assert!(
            !state.contains(&proof),
            "raw proof leaked into durable state"
        );
        assert!(state.contains(&digest_hex(&proof_digest(&proof))));

        let mut reopened =
            ConsumedBaitProofStore::open_or_rebuild(&event_log, &loaded.registry, None, 1_001)
                .expect("store should reopen");
        assert_eq!(
            reopened.check_and_mark(session, bait, proof, 1_100, 1_001),
            ConsumeProofOutcome::Replay
        );
    }

    #[test]
    fn clean_first_boot_sidecars_do_not_trigger_replay_quarantine() {
        let profile_path = write_bait_profile(session_minted_profile_json());
        let loaded = load_bait_profile(&profile_path).expect("profile");
        let event_log = unique_temp_path("clean-first-boot.jsonl");
        let exposure_store =
            BaitExposureStore::open_or_rebuild(&event_log, 1_000).expect("exposure store");
        assert!(exposure_store.path.is_some());
        drop(exposure_store);

        let mut proof_store =
            ConsumedBaitProofStore::open_or_rebuild(&event_log, &loaded.registry, None, 1_000)
                .expect("proof store");

        assert_eq!(proof_store.migration_quarantine_until, None);
        assert_eq!(
            proof_store.check_and_mark(
                SessionId::new(),
                BaitId("first-proof".to_string()),
                "proof-value".to_string(),
                1_100,
                1_000,
            ),
            ConsumeProofOutcome::Fresh
        );
    }

    #[test]
    fn concurrent_duplicate_proof_consumption_accepts_exactly_once() {
        let store = Arc::new(Mutex::new(ConsumedBaitProofStore::default()));
        let session = SessionId::new();
        let bait = BaitId("concurrent-proof".to_string());
        let threads = (0..8)
            .map(|_| {
                let store = Arc::clone(&store);
                let bait = bait.clone();
                thread::spawn(move || {
                    store.lock().expect("store lock").check_and_mark(
                        session,
                        bait,
                        "same-proof".to_string(),
                        1_100,
                        1_000,
                    )
                })
            })
            .collect::<Vec<_>>();
        let outcomes = threads
            .into_iter()
            .map(|thread| thread.join().expect("worker should join"))
            .collect::<Vec<_>>();

        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == ConsumeProofOutcome::Fresh)
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == ConsumeProofOutcome::Replay)
                .count(),
            7
        );
    }

    #[test]
    fn consumed_proof_store_failed_persist_is_unavailable_and_rolls_back() {
        let missing_parent = unique_temp_path("missing-consumed-proof-parent");
        let mut store = ConsumedBaitProofStore {
            path: Some(missing_parent.join("state.json")),
            ..ConsumedBaitProofStore::default()
        };

        assert_eq!(
            store.check_and_mark(
                SessionId::new(),
                BaitId("proof".to_string()),
                "proof-value".to_string(),
                1_100,
                1_000,
            ),
            ConsumeProofOutcome::Unavailable
        );
        assert!(store.consumed.is_empty());
    }

    #[test]
    fn consumed_proof_store_keeps_committed_state_when_directory_sync_is_uncertain() {
        let mut store = ConsumedBaitProofStore::default();
        let session = SessionId::new();
        let bait = BaitId("committed-proof".to_string());
        let proof = "committed-proof-value".to_string();

        assert_eq!(
            store.check_and_mark_with_persist(
                session,
                bait.clone(),
                proof.clone(),
                1_100,
                1_000,
                |_| { Ok(AtomicStateWriteOutcome::CommittedDurabilityUncertain) },
            ),
            ConsumeProofOutcome::Unavailable
        );
        assert_eq!(store.consumed.len(), 1);
        assert_eq!(
            store.check_and_mark(session, bait, proof, 1_100, 1_001),
            ConsumeProofOutcome::Replay
        );
    }

    #[test]
    fn consumed_proof_store_migration_quarantine_survives_restart() {
        let profile_path = write_bait_profile(session_minted_profile_json());
        let loaded = load_bait_profile(&profile_path).expect("profile");
        let event_log = unique_temp_path("consumed-proof-migration.jsonl");
        let session = SessionId::new();
        let bait = loaded
            .registry
            .bait_for_surface("/docs/minted-trace")
            .expect("minted bait")
            .clone();
        let now = 1_200;
        let rendered =
            eidolon_bait::render_bait_for_session_at(&bait, session, Some("mint-secret"), now)
                .expect("proof should render")
                .into_owned();
        let known_proof = rendered.expected_action.header_value.expect("proof value");
        let known_expiry =
            proof_expiry_epoch_seconds(&bait, &known_proof).expect("proof expiry should parse");
        let mut accepted = Event::new(
            session,
            EventSource::BaitEngine,
            PolicyState::Observe,
            EventKind::BaitActionObserved {
                bait_id: bait.id.clone(),
                bait_class: Some(bait.bait_class),
                exposure_id: None,
                method: "POST".to_string(),
                path: bait.expected_action.path.clone(),
                header_value_mint: bait.header_value_mint_audit(),
                header_value_mint_status: Some(BaitHeaderValueMintStatus::MatchedSessionValue),
            },
        );
        accepted.observed_at = chrono::DateTime::from_timestamp(now as i64, 0).expect("timestamp");
        fs::write(
            &event_log,
            format!(
                "{}\n",
                serde_json::to_string(&accepted).expect("event should serialize")
            ),
        )
        .expect("history should write");
        let unknown_proof = "unknown-proof".to_string();
        let quarantine_until = now + MAX_BAIT_PROOF_TTL_SECS;

        let mut store = ConsumedBaitProofStore::open_or_rebuild(
            &event_log,
            &loaded.registry,
            Some("mint-secret"),
            now,
        )
        .expect("migration should open");
        assert_eq!(
            store.check_and_mark(
                session,
                bait.id.clone(),
                known_proof.clone(),
                known_expiry,
                now,
            ),
            ConsumeProofOutcome::Replay
        );
        assert_eq!(
            store.check_and_mark(
                session,
                bait.id.clone(),
                unknown_proof.clone(),
                now + 100,
                now,
            ),
            ConsumeProofOutcome::Unavailable
        );
        drop(store);

        let mut quarantined = ConsumedBaitProofStore::open_or_rebuild(
            &event_log,
            &loaded.registry,
            Some("mint-secret"),
            now + 1,
        )
        .expect("quarantine should persist");
        assert_eq!(
            quarantined.check_and_mark(
                session,
                bait.id.clone(),
                known_proof,
                known_expiry,
                now + 1,
            ),
            ConsumeProofOutcome::Replay
        );
        assert_eq!(
            quarantined.check_and_mark(
                session,
                bait.id.clone(),
                unknown_proof.clone(),
                now + 100,
                now + 1,
            ),
            ConsumeProofOutcome::Unavailable
        );
        drop(quarantined);

        let mut recovered = ConsumedBaitProofStore::open_or_rebuild(
            &event_log,
            &loaded.registry,
            Some("mint-secret"),
            quarantine_until,
        )
        .expect("expired quarantine should clear");
        assert_eq!(
            recovered.check_and_mark(
                session,
                bait.id,
                unknown_proof,
                quarantine_until + 100,
                quarantine_until,
            ),
            ConsumeProofOutcome::Fresh
        );
    }

    #[test]
    fn consumed_proof_store_rejects_invalid_expiry_without_mutation() {
        let mut store = ConsumedBaitProofStore::default();
        let session = SessionId::new();
        let bait = BaitId("proof".to_string());

        assert_eq!(
            store.check_and_mark(session, bait.clone(), "expired".to_string(), 1_000, 1_000),
            ConsumeProofOutcome::Unavailable
        );
        assert_eq!(
            store.check_and_mark(
                session,
                bait,
                "overlong".to_string(),
                1_000 + MAX_BAIT_PROOF_TTL_SECS + 1,
                1_000,
            ),
            ConsumeProofOutcome::Unavailable
        );
        assert!(store.consumed.is_empty());
    }

    #[test]
    fn consumed_proof_state_rejects_over_capacity_on_restart() {
        let path = unique_temp_path("over-capacity-proof-state.json");
        let consumed = (0..MAX_CONSUMED_BAIT_PROOFS + 1)
            .map(|index| StoredConsumedProof {
                session_id: SessionId::new(),
                bait_id: BaitId(format!("bait-{index}")),
                proof_digest_hex: digest_hex(&proof_digest(&format!("proof-{index}"))),
                expires_at_unix_secs: 1_100,
            })
            .collect();
        let bytes = serde_json::to_vec(&StoredConsumedProofState {
            schema_version: CONSUMED_PROOF_STATE_SCHEMA_VERSION,
            migration_quarantine_until: None,
            consumed,
        })
        .expect("state should serialize");

        let error = ConsumedBaitProofStore::from_state_bytes(path, &bytes, 1_000)
            .expect_err("over-capacity replay state must fail startup");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error
            .to_string()
            .contains("active consumed bait proof state exceeds configured capacity"));
    }

    #[test]
    fn atomic_state_write_supports_relative_paths() {
        let unique = unique_temp_path("relative-state.json");
        let relative = PathBuf::from(unique.file_name().expect("unique file name"));

        atomic_state_write(&relative, &json!({"healthy": true}))
            .expect("relative state should persist");

        let stored: Value = serde_json::from_slice(
            &fs::read(&relative).expect("relative state should be readable"),
        )
        .expect("relative state should parse");
        assert_eq!(stored["healthy"], true);
        fs::remove_file(relative).expect("relative state should remove");
    }

    #[test]
    fn atomic_state_write_distinguishes_post_rename_sync_failure() {
        let path = unique_temp_path("post-rename-sync-failure.json");

        let outcome =
            atomic_state_write_with_parent_sync(&path, &json!({"committed": true}), |_| {
                Err(io::Error::other("directory sync failed"))
            })
            .expect("rename should commit");

        assert_eq!(
            outcome,
            AtomicStateWriteOutcome::CommittedDurabilityUncertain
        );
        let stored: Value = serde_json::from_slice(
            &fs::read(&path).expect("committed state should remain readable"),
        )
        .expect("committed state should parse");
        assert_eq!(stored["committed"], true);
        fs::remove_file(path).expect("state should remove");
    }

    #[test]
    fn consumed_proof_store_restores_active_proofs_from_event_log() {
        let path = write_bait_profile(session_minted_profile_json());
        let loaded = load_bait_profile(&path).expect("profile");
        let bait = loaded
            .registry
            .bait_for_surface("/docs/minted-trace")
            .expect("bait")
            .clone();
        let session = SessionId::new();
        let mut event = Event::new(
            session,
            EventSource::BaitEngine,
            PolicyState::Observe,
            EventKind::BaitActionObserved {
                bait_id: bait.id.clone(),
                bait_class: Some(bait.bait_class),
                exposure_id: None,
                method: "POST".to_string(),
                path: bait.expected_action.path.clone(),
                header_value_mint: bait.header_value_mint_audit(),
                header_value_mint_status: Some(BaitHeaderValueMintStatus::MatchedSessionValue),
            },
        );
        event.observed_at = chrono::DateTime::from_timestamp(1_200, 0).expect("timestamp");
        let event_log = unique_temp_path("consumed-proof-rebuild.jsonl");
        fs::write(
            &event_log,
            format!(
                "{line}\n{line}\n",
                line = serde_json::to_string(&event).expect("serialize")
            ),
        )
        .expect("write event log");
        let rendered =
            eidolon_bait::render_bait_for_session_at(&bait, session, Some("mint-secret"), 1_200)
                .expect("render")
                .into_owned();
        let proof = rendered.expected_action.header_value.expect("proof");

        let mut store = ConsumedBaitProofStore::from_event_log(
            &event_log,
            &loaded.registry,
            Some("mint-secret"),
            1_259,
        )
        .expect("restore");

        assert_eq!(store.consumed.len(), 1);
        assert_eq!(
            store.check_and_mark(session, bait.id, proof, 1_260, 1_259),
            ConsumeProofOutcome::Replay
        );
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
                    bait_class: None,
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
                    bait_class: None,
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
                    bait_class: None,
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
    fn bait_exposure_store_committed_state_survives_log_loss() {
        let event_log = unique_temp_path("exposure-state-log-loss.jsonl");
        let session = SessionId::new();
        let bait = BaitId("durable-bait".to_string());
        let exposure = ExposureId("durable-exposure".to_string());
        let mut store =
            BaitExposureStore::open_or_rebuild(&event_log, 1_000).expect("store should open");
        store
            .record_exposure_at(session, bait.clone(), exposure.clone(), 1_000, 1_000)
            .expect("exposure should persist");
        drop(store);

        fs::write(&event_log, "\n").expect("active log should exist");
        fs::remove_file(&event_log).expect("active log should be removable");
        let reopened = BaitExposureStore::open_or_rebuild(&event_log, 1_001)
            .expect("state should survive event-log rotation or loss");
        assert_eq!(
            reopened.exposure_for_action_at(session, &bait, 1_001),
            Some(exposure)
        );
    }

    #[test]
    fn bait_exposure_state_compacts_over_capacity_on_restart() {
        let event_log = unique_temp_path("over-capacity-exposure-state.jsonl");
        let state_path = state_path_for_event_log(&event_log, ".exposures.json");
        let exposures = (0..MAX_BAIT_EXPOSURES + 3)
            .map(|index| StoredBaitExposure {
                session_id: SessionId::new(),
                bait_id: BaitId(format!("bait-{index}")),
                exposure_id: ExposureId(format!("exposure-{index}")),
                observed_at_unix_secs: 1_000 + index as u64,
            })
            .collect();
        fs::write(
            &state_path,
            serde_json::to_vec(&StoredBaitExposureState {
                schema_version: BAIT_EXPOSURE_STATE_SCHEMA_VERSION,
                exposures,
            })
            .expect("state should serialize"),
        )
        .expect("state should write");

        let store = BaitExposureStore::open_or_rebuild(&event_log, 2_000)
            .expect("over-capacity state should compact");

        assert_eq!(store.len(), MAX_BAIT_EXPOSURES);
        let persisted: StoredBaitExposureState =
            serde_json::from_slice(&fs::read(&state_path).expect("compacted state should read"))
                .expect("compacted state should parse");
        assert_eq!(persisted.exposures.len(), MAX_BAIT_EXPOSURES);
    }

    #[test]
    fn bait_exposure_store_does_not_recover_failed_commit_from_event_log() {
        let event_log = unique_temp_path("exposure-failed-commit.jsonl");
        let session = SessionId::new();
        let bait = BaitId("failed-bait".to_string());
        let exposure = ExposureId("failed-exposure".to_string());
        let mut store =
            BaitExposureStore::open_or_rebuild(&event_log, 1_000).expect("store should open");
        let committed_state_path = store.path.clone().expect("state path");
        let mut event = Event::new(
            session,
            EventSource::SurfaceController,
            PolicyState::Observe,
            EventKind::BaitExposed {
                bait_id: bait.clone(),
                bait_class: None,
                exposure_id: exposure.clone(),
                surface: "/docs".to_string(),
                header_value_mint: None,
            },
        );
        event.observed_at = chrono::DateTime::from_timestamp(1_000, 0).expect("timestamp");
        fs::write(
            &event_log,
            format!(
                "{}\n",
                serde_json::to_string(&event).expect("event should serialize")
            ),
        )
        .expect("event log should write");
        store.path = Some(unique_temp_path("missing-exposure-parent").join("state.json"));
        store
            .record_exposure_at(session, bait.clone(), exposure, 1_000, 1_000)
            .expect_err("state persistence should fail");
        drop(store);

        assert!(committed_state_path.exists());
        let reopened = BaitExposureStore::open_or_rebuild(&event_log, 1_001)
            .expect("committed state should remain authoritative");

        assert_eq!(reopened.exposure_for_action_at(session, &bait, 1_001), None);
    }

    #[test]
    fn bait_exposure_store_failed_persist_rolls_back() {
        let missing_parent = unique_temp_path("missing-exposure-parent");
        let mut store = BaitExposureStore {
            path: Some(missing_parent.join("state.json")),
            ..BaitExposureStore::default()
        };

        let error = store
            .record_exposure_at(
                SessionId::new(),
                BaitId("bait".to_string()),
                ExposureId("exposure".to_string()),
                1_000,
                1_000,
            )
            .expect_err("failed persistence must be visible");

        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(store.exposures.is_empty());
        assert!(store.exposure_order.is_empty());
    }

    #[test]
    fn bait_exposure_store_keeps_committed_state_when_directory_sync_is_uncertain() {
        let session = SessionId::new();
        let bait = BaitId("committed-bait".to_string());
        let exposure = ExposureId("committed-exposure".to_string());
        let mut store = BaitExposureStore::default();

        store
            .record_exposure_at_with_persist(
                session,
                bait.clone(),
                exposure.clone(),
                1_000,
                1_000,
                |_| Ok(AtomicStateWriteOutcome::CommittedDurabilityUncertain),
            )
            .expect("committed exposure should not roll back");

        assert_eq!(
            store.exposure_for_action_at(session, &bait, 1_001),
            Some(exposure)
        );
    }

    #[test]
    fn bait_exposure_store_rebuild_discards_expired_exposures() {
        let stale_session = SessionId::new();
        let fresh_session = SessionId::new();
        let now = BAIT_EXPOSURE_TTL_SECS + 1_000;
        let mut stale = Event::new(
            stale_session,
            EventSource::SurfaceController,
            PolicyState::Observe,
            EventKind::BaitExposed {
                bait_id: BaitId("stale".to_string()),
                bait_class: None,
                exposure_id: ExposureId("stale-exposure".to_string()),
                surface: "/docs".to_string(),
                header_value_mint: None,
            },
        );
        stale.observed_at = chrono::DateTime::from_timestamp(999, 0).expect("timestamp");
        let mut fresh = Event::new(
            fresh_session,
            EventSource::SurfaceController,
            PolicyState::Observe,
            EventKind::BaitExposed {
                bait_id: BaitId("fresh".to_string()),
                bait_class: None,
                exposure_id: ExposureId("fresh-exposure".to_string()),
                surface: "/docs".to_string(),
                header_value_mint: None,
            },
        );
        fresh.observed_at =
            chrono::DateTime::from_timestamp(i64::try_from(now - 1).expect("timestamp"), 0)
                .expect("timestamp");
        let jsonl = [stale, fresh]
            .iter()
            .map(|event| serde_json::to_string(event).expect("event should serialize"))
            .collect::<Vec<_>>()
            .join("\n");

        let store =
            BaitExposureStore::from_event_log_reader_at(Cursor::new(format!("{jsonl}\n")), now)
                .expect("event log should rebuild");

        assert_eq!(store.len(), 1);
        assert_eq!(store.ttl_evicted, 1);
        assert!(store
            .exposure_for_action_at(stale_session, &BaitId("stale".to_string()), now)
            .is_none());
        assert_eq!(
            store.exposure_for_action_at(fresh_session, &BaitId("fresh".to_string()), now),
            Some(ExposureId("fresh-exposure".to_string()))
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
                bait_class: None,
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

    fn bait_exposed_jsonl_line(session_id: SessionId) -> String {
        serde_json::to_string(&Event::new(
            session_id,
            EventSource::SurfaceController,
            PolicyState::Observe,
            EventKind::BaitExposed {
                bait_id: BaitId("torn-bait".to_string()),
                bait_class: None,
                exposure_id: ExposureId("torn-exposure".to_string()),
                surface: "/docs".to_string(),
                header_value_mint: None,
            },
        ))
        .expect("event should serialize")
    }

    #[test]
    fn torn_final_event_log_line_is_tolerated_and_reported() {
        let session_id = SessionId::new();
        let valid = bait_exposed_jsonl_line(session_id);
        let truncated = "{\"schema_version\":2,\"id\":\"half-written";

        let store =
            BaitExposureStore::from_event_log_reader(Cursor::new(format!("{valid}\n{truncated}")))
                .expect("crash-torn tail should be tolerated");

        assert_eq!(store.len(), 1);
        assert_eq!(store.torn_tail_line, Some(2));
    }

    #[test]
    fn mid_file_corruption_fails_reconstruction_loudly() {
        let session_id = SessionId::new();
        let valid = bait_exposed_jsonl_line(session_id);

        let error = BaitExposureStore::from_event_log_reader(Cursor::new(format!(
            "{{not json}}\n{valid}\n"
        )))
        .expect_err("mid-file corruption must fail");

        assert!(error
            .to_string()
            .contains("could not rebuild bait exposure store from event log line 1"));
    }

    #[test]
    fn truncated_final_line_with_trailing_newline_is_corruption_not_a_tear() {
        let session_id = SessionId::new();
        let valid = bait_exposed_jsonl_line(session_id);
        let truncated = "{\"schema_version\":2,\"id\":\"half-written";

        let error = BaitExposureStore::from_event_log_reader(Cursor::new(format!(
            "{valid}\n{truncated}\n"
        )))
        .expect_err("corrupt final line with trailing newline must fail");

        assert!(error
            .to_string()
            .contains("could not rebuild bait exposure store from event log line 2"));
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
            cache_policy: ResponseCachePolicy::Preserve,
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
            "/docs/legacy-import?<redacted>"
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
                (
                    session::INGRESS_CONTINUITY_HEADER_NAME,
                    TEST_INGRESS_CONTINUITY_ID,
                ),
            ],
        );
        let _response = run_runtime_request(runtime, &request);
        must_join(upstream_handle.join(), "upstream thread should join");
        assert!(!fs::read_to_string(&event_log_path)
            .expect("event log should read")
            .contains("test_client_0123456789abcdef"));
        assert!(!fs::read_to_string(&debug_log_path)
            .expect("debug log should read")
            .contains("test_client_0123456789abcdef"));

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
        let session_debug = first_debug_event(&debug_log_path, "session_resolved");
        assert_eq!(
            session_debug["fields"]["continuity_source"],
            "authenticated_ingress"
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
                (
                    session::INGRESS_CONTINUITY_HEADER_NAME,
                    TEST_INGRESS_CONTINUITY_ID,
                ),
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
                    (
                        session::INGRESS_CONTINUITY_HEADER_NAME,
                        TEST_INGRESS_CONTINUITY_ID,
                    ),
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
                    (
                        session::INGRESS_CONTINUITY_HEADER_NAME,
                        TEST_INGRESS_CONTINUITY_ID,
                    ),
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
            (
                session::INGRESS_CONTINUITY_HEADER_NAME,
                TEST_INGRESS_CONTINUITY_ID,
            ),
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
                    (
                        session::INGRESS_CONTINUITY_HEADER_NAME,
                        TEST_INGRESS_CONTINUITY_ID,
                    ),
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
            (
                session::INGRESS_CONTINUITY_HEADER_NAME,
                TEST_INGRESS_CONTINUITY_ID,
            ),
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
            policy_changes[1]["persistence"]["pre_containment_persistence_class"],
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
            (
                session::INGRESS_CONTINUITY_HEADER_NAME,
                TEST_INGRESS_CONTINUITY_ID,
            ),
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
            policy_changes[2]["persistence"]["pre_containment_persistence_class"],
            "discovery_recon"
        );
        assert_eq!(
            policy_changes[2]["persistence"]["pre_containment_persistence_kind"],
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
                    (
                        session::INGRESS_CONTINUITY_HEADER_NAME,
                        TEST_INGRESS_CONTINUITY_ID,
                    ),
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
        let (upstream, upstream_recorder) = spawn_recording_upstream([html_response(original)]);
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
            (
                session::INGRESS_CONTINUITY_HEADER_NAME,
                TEST_INGRESS_CONTINUITY_ID,
            ),
        ];

        let first_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &request_with_cookie("GET", "/docs?topic=imports", &cookie, &headers),
        ));
        let second_response = parse_downstream_response(&run_runtime_request(
            runtime,
            &post_request_with_cookie("/api/v2/import/reconcile", &cookie, &headers),
        ));
        let upstream_requests = upstream_recorder.finish();

        assert_eq!(first_response.status, 200);
        assert_eq!(second_response.status, 403);
        assert_eq!(
            upstream_request_lines(&upstream_requests),
            vec!["GET /docs?topic=imports HTTP/1.1".to_string()]
        );

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
        let (upstream, upstream_recorder) = spawn_recording_upstream([html_response(original)]);
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
            (
                session::INGRESS_CONTINUITY_HEADER_NAME,
                TEST_INGRESS_CONTINUITY_ID,
            ),
        ];

        let first_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &request_with_cookie("GET", "/docs?topic=imports", &cookie, &headers),
        ));
        let second_response = parse_downstream_response(&run_runtime_request(
            runtime,
            &post_request_with_cookie("/api/v2/import/validate", &cookie, &headers),
        ));
        let upstream_requests = upstream_recorder.finish();

        let first_body = must_ok(
            String::from_utf8(first_response.body),
            "body should be utf8",
        );

        assert_eq!(first_response.status, 200);
        assert!(first_body.contains("/docs/import-validate"));
        assert_eq!(second_response.status, 403);
        assert_eq!(
            upstream_request_lines(&upstream_requests),
            vec!["GET /docs?topic=imports HTTP/1.1".to_string()]
        );

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
        let (upstream, upstream_recorder) = spawn_recording_upstream([html_response(original)]);
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
            (
                session::INGRESS_CONTINUITY_HEADER_NAME,
                TEST_INGRESS_CONTINUITY_ID,
            ),
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
        let upstream_requests = upstream_recorder.finish();

        assert_eq!(first_response.status, 200);
        assert_eq!(second_response.status, 403);
        assert_eq!(third_response.status, 403);
        assert_eq!(fourth_response.status, 429);
        assert_eq!(header_values(&fourth_response, "retry-after"), vec!["30"]);
        assert_eq!(
            upstream_request_lines(&upstream_requests),
            vec!["GET /docs?topic=imports HTTP/1.1".to_string()]
        );

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
            (
                session::INGRESS_CONTINUITY_HEADER_NAME,
                TEST_INGRESS_CONTINUITY_ID,
            ),
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
            policy_changes[1]["persistence"]["pre_containment_persistence_class"],
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
        let (upstream, upstream_recorder) = spawn_recording_upstream([html_response(original)]);
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
            (
                session::INGRESS_CONTINUITY_HEADER_NAME,
                TEST_INGRESS_CONTINUITY_ID,
            ),
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
        let upstream_requests = upstream_recorder.finish();

        assert_eq!(first_response.status, 200);
        assert_eq!(second_response.status, 403);
        assert_eq!(third_response.status, 429);
        assert_eq!(header_values(&third_response, "retry-after"), vec!["30"]);
        assert_eq!(
            upstream_request_lines(&upstream_requests),
            vec!["GET /docs?topic=imports HTTP/1.1".to_string()]
        );

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
            policy_changes[1]["persistence"]["pre_containment_persistence_class"],
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
        let (upstream, upstream_recorder) = spawn_recording_upstream([html_response(original)]);
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
            (
                session::INGRESS_CONTINUITY_HEADER_NAME,
                TEST_INGRESS_CONTINUITY_ID,
            ),
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
        let upstream_requests = upstream_recorder.finish();

        assert_eq!(first_response.status, 200);
        assert_eq!(second_response.status, 403);
        assert_eq!(third_response.status, 429);
        assert_eq!(header_values(&third_response, "retry-after"), vec!["30"]);
        assert_eq!(
            upstream_request_lines(&upstream_requests),
            vec!["GET /docs?topic=imports HTTP/1.1".to_string()]
        );

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
        let (upstream, upstream_recorder) = spawn_recording_upstream([html_response(original)]);
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
            (
                session::INGRESS_CONTINUITY_HEADER_NAME,
                TEST_INGRESS_CONTINUITY_ID,
            ),
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
        let upstream_requests = upstream_recorder.finish();

        assert_eq!(first_response.status, 200);
        assert_eq!(second_response.status, 403);
        assert_eq!(third_response.status, 429);
        assert_eq!(fourth_response.status, 403);
        assert_eq!(header_values(&third_response, "retry-after"), vec!["30"]);
        assert_eq!(
            upstream_request_lines(&upstream_requests),
            vec!["GET /docs?topic=imports HTTP/1.1".to_string()]
        );

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
        assert!(policy_decisions.iter().any(|decision| {
            decision["kind"]["reason"].as_str().is_some_and(|reason| {
                reason.contains("configured unsafe bait action failed closed")
            })
        }));
        let blocked_decision = policy_decisions
            .iter()
            .find(|decision| {
                decision["kind"]["reason"].as_str().is_some_and(|reason| {
                    reason.contains("rate-limited discovery recon retry moved session to blocked")
                })
            })
            .expect("blocked policy decision should exist");
        assert!(blocked_decision["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| {
                reason.contains("rate-limited discovery recon retry moved session to blocked")
            }));
        assert!(blocked_decision["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("decoy_write_probe_seen=true")));
        assert!(blocked_decision["kind"]["reason"]
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
        let (upstream, upstream_recorder) = spawn_recording_upstream([html_response(original)]);
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
            (
                session::INGRESS_CONTINUITY_HEADER_NAME,
                TEST_INGRESS_CONTINUITY_ID,
            ),
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
        let upstream_requests = upstream_recorder.finish();

        assert_eq!(first_response.status, 200);
        assert_eq!(second_response.status, 403);
        assert_eq!(third_response.status, 429);
        assert_eq!(fourth_response.status, 403);
        assert_eq!(header_values(&third_response, "retry-after"), vec!["30"]);
        assert_eq!(
            upstream_request_lines(&upstream_requests),
            vec!["GET /docs?topic=imports HTTP/1.1".to_string()]
        );

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
        assert!(policy_decisions.iter().any(|decision| {
            decision["kind"]["reason"].as_str().is_some_and(|reason| {
                reason.contains("configured unsafe bait action failed closed")
            })
        }));
        let blocked_decision = policy_decisions
            .iter()
            .find(|decision| {
                decision["kind"]["reason"].as_str().is_some_and(|reason| {
                    reason.contains("rate-limited discovery recon retry moved session to blocked")
                })
            })
            .expect("blocked policy decision should exist");
        assert!(blocked_decision["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| {
                reason.contains("rate-limited discovery recon retry moved session to blocked")
            }));
        assert!(blocked_decision["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("decoy_write_probe_count=2")));
        assert!(blocked_decision["kind"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("decoy_write_probe_path_classes=2")));
        assert!(blocked_decision["kind"]["reason"]
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
            policy_changes[2]["persistence"]["pre_containment_persistence_class"],
            "write_recon"
        );
        assert_eq!(
            policy_changes[2]["persistence"]["pre_containment_persistence_kind"],
            "write_recon_retry"
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
            (
                session::INGRESS_CONTINUITY_HEADER_NAME,
                TEST_INGRESS_CONTINUITY_ID,
            ),
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
            (
                session::INGRESS_CONTINUITY_HEADER_NAME,
                TEST_INGRESS_CONTINUITY_ID,
            ),
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
            (
                session::INGRESS_CONTINUITY_HEADER_NAME,
                TEST_INGRESS_CONTINUITY_ID,
            ),
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
            (
                session::INGRESS_CONTINUITY_HEADER_NAME,
                TEST_INGRESS_CONTINUITY_ID,
            ),
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
            (
                session::INGRESS_CONTINUITY_HEADER_NAME,
                TEST_INGRESS_CONTINUITY_ID,
            ),
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
            (
                session::INGRESS_CONTINUITY_HEADER_NAME,
                TEST_INGRESS_CONTINUITY_ID,
            ),
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
                    (
                        session::INGRESS_CONTINUITY_HEADER_NAME,
                        TEST_INGRESS_CONTINUITY_ID,
                    ),
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
                    (
                        session::INGRESS_CONTINUITY_HEADER_NAME,
                        TEST_INGRESS_CONTINUITY_ID,
                    ),
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
                    (
                        session::INGRESS_CONTINUITY_HEADER_NAME,
                        TEST_INGRESS_CONTINUITY_ID,
                    ),
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
        assert!(!upstream_request.contains("X-Eidolon-Ingress-Continuity:"));
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
                (
                    session::INGRESS_CONTINUITY_HEADER_NAME,
                    TEST_INGRESS_CONTINUITY_ID,
                ),
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
                (
                    session::INGRESS_CONTINUITY_HEADER_NAME,
                    TEST_INGRESS_CONTINUITY_ID,
                ),
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
                    (
                        session::INGRESS_CONTINUITY_HEADER_NAME,
                        TEST_INGRESS_CONTINUITY_ID,
                    ),
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
                    (
                        session::INGRESS_CONTINUITY_HEADER_NAME,
                        TEST_INGRESS_CONTINUITY_ID,
                    ),
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
                    (
                        session::INGRESS_CONTINUITY_HEADER_NAME,
                        TEST_INGRESS_CONTINUITY_ID,
                    ),
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
                    (
                        session::INGRESS_CONTINUITY_HEADER_NAME,
                        TEST_INGRESS_CONTINUITY_ID,
                    ),
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
        assert_eq!(exposure["kind"]["surface"], "/openapi.json?<redacted>");
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
        assert!(header_values(&response, "cache-control").is_empty());
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
        let (upstream, upstream_handle) =
            spawn_upstream(cacheable_json_response(200, "OK", original));
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
        assert_eq!(
            header_values(&response, "cache-control"),
            vec!["public, max-age=3600"]
        );
        assert_eq!(header_values(&response, "etag"), vec!["\"upstream-v1\""]);
        assert_eq!(
            header_values(&response, "last-modified"),
            vec!["Tue, 21 Jul 2026 10:00:00 GMT"]
        );
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
        assert_policy_decision_reason_contains(&event_log_path, "non-200 upstream response");
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
            assert!(header_values(&response, "cache-control").is_empty());
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
    fn runtime_policy_capacity_fallback_never_reaches_upstream_even_when_disabled() {
        let event_log_path = unique_temp_path("capacity-fail-closed-events.jsonl");
        let policy_path = unique_temp_path("capacity-fail-closed-policy.json");
        let intervention_path = unique_temp_path("capacity-fail-closed-control.txt");
        fs::write(&intervention_path, b"disabled\n").expect("control file should write");
        fs::write(
            &policy_path,
            serde_json::to_vec_pretty(&json!({
                "schema_version": eidolon_proxy::policy_store::POLICY_STORE_SCHEMA_VERSION,
                "fail_closed_for_unknown_sessions": true,
                "sessions": [],
            }))
            .expect("policy state should serialize"),
        )
        .expect("policy state should write");
        let (upstream, upstream_recorder) =
            spawn_recording_upstream([json_response(r#"{"mode":"unexpected_upstream"}"#)]);
        let mut runtime = test_runtime(
            upstream,
            &event_log_path,
            intervention_path,
            SurfaceAction::ProtectedUpstream,
        );
        runtime.policy_store = Arc::new(Mutex::new(
            PolicyStateStore::open(&policy_path).expect("saturated policy store should open"),
        ));

        let response =
            parse_downstream_response(&run_runtime_request(runtime, &get_request("/ordinary")));
        let upstream_requests = upstream_recorder.finish();

        assert_eq!(response.status, 503);
        assert!(
            upstream_requests.is_empty(),
            "capacity fail-closed request reached protected upstream"
        );
        assert_event_routing(&event_log_path, "request_seen", "eidolon_owned");
        assert_event_routing(&event_log_path, "response_served", "eidolon_owned");
    }

    #[test]
    fn runtime_correlates_same_session_bait_action_and_does_not_forward() {
        let event_log_path = unique_temp_path("bait-action-events.jsonl");
        let (upstream, upstream_recorder) =
            spawn_recording_upstream([json_response(r#"{"mode":"unexpected_upstream"}"#)]);
        let runtime = test_runtime_with_m1_controller(
            upstream,
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
        let upstream_requests = upstream_recorder.finish();

        assert_eq!(exposure_response.status, 200);
        assert_eq!(action_response.status, 202);
        assert!(
            upstream_requests.is_empty(),
            "valid static action reached protected upstream"
        );
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
                        bait_class: Some(bait.bait_class),
                        exposure_id: restored_exposure_id.clone(),
                        surface: bait.surface.clone(),
                        header_value_mint: None,
                    },
                ))
                .expect("bait exposure event should write");
        }

        let restored_exposures =
            BaitExposureStore::open_or_rebuild(&event_log_path, current_unix_secs())
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
    fn runtime_wrong_bait_header_value_logs_near_miss_and_fails_closed() {
        let event_log_path = unique_temp_path("near-miss-events.jsonl");
        let (upstream, upstream_recorder) =
            spawn_recording_upstream([json_response(r#"{"mode":"unexpected_upstream"}"#)]);
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
        let upstream_requests = upstream_recorder.finish();

        assert_eq!(response.status, 403);
        assert!(
            upstream_requests.is_empty(),
            "request reached protected upstream"
        );
        assert_eq!(events_of_type(&event_log_path, "bait_exposed").len(), 1);
        let near_miss = first_event_of_type(&event_log_path, "bait_action_observed");
        assert_eq!(near_miss["policy_state"], "observe");
        assert_eq!(near_miss["kind"]["bait_id"], "rel_2025_04_b7f2");
        assert!(near_miss["kind"]["exposure_id"].is_null());
        assert_eq!(
            events_of_type(&event_log_path, "rate_limit_applied").len(),
            0
        );
        assert_event_routing(&event_log_path, "request_seen", "eidolon_owned");
    }

    #[test]
    fn runtime_missing_bait_header_on_shared_path_fails_closed_without_bait_action() {
        let event_log_path = unique_temp_path("missing-bait-header-events.jsonl");
        let (upstream, upstream_recorder) =
            spawn_recording_upstream([json_response(r#"{"mode":"unexpected_upstream"}"#)]);
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
        let upstream_requests = upstream_recorder.finish();

        assert_eq!(response.status, 403);
        assert!(
            upstream_requests.is_empty(),
            "request reached protected upstream"
        );
        assert_eq!(events_of_type(&event_log_path, "bait_exposed").len(), 1);
        assert_event_type_absent(&event_log_path, "bait_action_observed");
        assert_eq!(
            events_of_type(&event_log_path, "rate_limit_applied").len(),
            0
        );
        assert_event_routing(&event_log_path, "request_seen", "eidolon_owned");
    }

    #[test]
    fn runtime_unconfigured_unsafe_route_still_forwards() {
        let event_log_path = unique_temp_path("unconfigured-unsafe-route-events.jsonl");
        let (upstream, upstream_recorder) =
            spawn_recording_upstream([json_response(r#"{"mode":"upstream"}"#)]);
        let runtime = test_runtime_with_m1_controller(
            upstream,
            &event_log_path,
            unique_temp_path("unconfigured-unsafe-route-control.txt"),
        );

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &request_with_cookie("PUT", "/api/v1/imports", &cookie_header(), &[]),
        ));
        let upstream_requests = upstream_recorder.finish();

        assert_eq!(response.status, 200);
        assert_eq!(response.body, br#"{"mode":"upstream"}"#);
        assert_eq!(
            upstream_request_lines(&upstream_requests),
            vec!["PUT /api/v1/imports HTTP/1.1".to_string()]
        );
        assert_event_routing(&event_log_path, "request_seen", "protected_upstream");
        assert_event_type_absent(&event_log_path, "bait_action_observed");
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
            policy_changed["persistence"]["pre_containment_persistence_class"],
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
    fn remote_renderer_success_uses_the_verified_response() {
        let event_log_path = unique_temp_path("remote-renderer-success-events.jsonl");
        let mut runtime = test_runtime(
            closed_upstream(),
            &event_log_path,
            unique_temp_path("remote-renderer-success-control.txt"),
            SurfaceAction::ProtectedUpstream,
        );
        let (backend, server) = start_controlled_reality_backend_once();
        runtime.controlled_reality_backend = Some(backend);
        let session_id = SessionId::new();
        let request_id = RequestId::new();
        let request = SurfaceRequestMeta::new(
            "POST",
            eidolon_proxy::controlled_reality::DECOY_RECONCILE_PATH,
            Vec::new(),
            0,
        );

        let (action, transition, interaction, pending_commit) = controlled_reality_action(
            &runtime,
            session_id,
            request_id,
            &request,
            "test transition".to_string(),
        )
        .expect("remote renderer should serve the action");

        let SurfaceAction::ControlledReality { response, .. } = action else {
            panic!("successful remote render should remain controlled reality");
        };
        assert_eq!(response.status, 202);
        assert!(transition.is_none());
        assert!(interaction.is_some());
        assert!(pending_commit);
        assert_eq!(
            server.join().expect("renderer should finish"),
            ControlledRealityBackendConnectionOutcome::Served {
                request_id,
                status: 202,
            }
        );
    }

    #[test]
    fn remote_renderer_failure_returns_503_and_rolls_back_progress() {
        let event_log_path = unique_temp_path("remote-renderer-failure-events.jsonl");
        let mut runtime = test_runtime(
            closed_upstream(),
            &event_log_path,
            unique_temp_path("remote-renderer-failure-control.txt"),
            SurfaceAction::ProtectedUpstream,
        );
        let listener = TcpListener::bind("127.0.0.1:0").expect("address should bind");
        let address = listener.local_addr().expect("address should exist");
        drop(listener);
        runtime.controlled_reality_backend = Some(Arc::new(ControlledRealityBackendClient::new(
            address,
            test_controlled_reality_backend_secret(),
        )));
        let session_id = SessionId::new();
        let request_id = RequestId::new();
        let request = SurfaceRequestMeta::new(
            "POST",
            eidolon_proxy::controlled_reality::DECOY_RECONCILE_PATH,
            Vec::new(),
            0,
        );

        let (action, transition, interaction, pending_commit) = controlled_reality_action(
            &runtime,
            session_id,
            request_id,
            &request,
            "test transition".to_string(),
        )
        .expect("backend failure should become a direct response");

        let SurfaceAction::EidolonOwned { response } = action else {
            panic!("backend failure must not fall back to local controlled reality");
        };
        assert_eq!(response.status, 503);
        assert!(transition.is_none());
        assert!(interaction.is_none());
        assert!(!pending_commit);
        let record = runtime
            .policy_store
            .lock()
            .expect("policy store should lock")
            .record(session_id);
        assert_eq!(record.controlled_reality_depth, 0);
        assert_eq!(
            record.controlled_reality_workflow_state,
            ControlledRealityWorkflowState::Ready
        );
        assert!(record.controlled_reality_pending_update.is_none());
    }

    #[test]
    fn runtime_remote_renderer_outage_fails_closed_without_protected_upstream_request() {
        let profile_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/m3/bait-profiles/docs-session-minted-probe.json");
        let loaded = load_bait_profile(&profile_path).expect("committed docs profile should load");
        let bait = loaded
            .registry
            .bait_for_surface("/docs/legacy-import")
            .expect("session-minted docs bait should exist")
            .clone();
        let signing_secret: Arc<str> = Arc::from("renderer-outage-mint-secret");
        let event_log_path = unique_temp_path("remote-renderer-outage-events.jsonl");
        let debug_log_path = unique_temp_path("remote-renderer-outage-debug.jsonl");
        let (upstream, upstream_recorder) =
            spawn_recording_upstream([json_response(r#"{"mode":"unexpected_upstream"}"#)]);
        let mut runtime = test_runtime_with_bait_profile(
            upstream,
            &event_log_path,
            unique_temp_path("remote-renderer-outage-control.txt"),
            loaded,
            Some(Arc::clone(&signing_secret)),
        );
        runtime.debug_log = Some(Arc::new(Mutex::new(
            FileDebugLogWriter::open(&debug_log_path).expect("debug log should open"),
        )));
        let listener = TcpListener::bind("127.0.0.1:0").expect("renderer address should bind");
        let renderer_address = listener
            .local_addr()
            .expect("renderer address should exist");
        drop(listener);
        runtime.controlled_reality_backend = Some(Arc::new(ControlledRealityBackendClient::new(
            renderer_address,
            test_controlled_reality_backend_secret(),
        )));

        let session_id = SessionId::new();
        let cookie = format!("eidolon_session={}", minted_cookie_value(session_id));
        let rendered = render_bait_for_session(&bait, session_id, Some(signing_secret.as_ref()))
            .expect("session bait should render")
            .into_owned();
        let header_name = rendered
            .expected_action
            .header_name
            .as_deref()
            .expect("minted action should have a header name");
        let header_value = rendered
            .expected_action
            .header_value
            .as_deref()
            .expect("minted action should have a header value");

        let exposure_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &get_request_with_cookie(&bait.surface, &cookie),
        ));
        assert_eq!(exposure_response.status, 200);
        assert!(
            String::from_utf8(exposure_response.body)
                .expect("exposure body should be utf8")
                .contains(header_value),
            "exposure must publish the same-session minted value"
        );

        let action_response = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &post_request_with_cookie(
                &bait.expected_action.path,
                &cookie,
                &[(header_name, header_value)],
            ),
        ));
        let upstream_requests = upstream_recorder.finish();

        assert_eq!(action_response.status, 503);
        assert_eq!(action_response.reason, "Service Unavailable");
        assert_eq!(
            serde_json::from_slice::<Value>(&action_response.body)
                .expect("outage body should be json"),
            json!({
                "status": "unavailable",
                "synthetic": true,
                "write_committed": false,
                "message": "controlled reality renderer unavailable",
            })
        );
        assert_session_proof_cache_safety(&action_response);
        assert_eq!(
            header_values(&action_response, "content-type"),
            vec!["application/json; charset=utf-8"]
        );
        assert_eq!(
            header_values(&action_response, "x-eidolon-synthetic"),
            vec!["true"]
        );
        assert!(
            upstream_requests.is_empty(),
            "renderer outage action reached protected upstream: {:?}",
            upstream_request_lines(&upstream_requests)
        );

        let record = runtime
            .policy_store
            .lock()
            .expect("policy store should lock")
            .record(session_id);
        assert_eq!(record.policy_state, PolicyState::ControlledReality);
        assert_eq!(record.controlled_reality_depth, 0);
        assert_eq!(
            record.controlled_reality_workflow_state,
            ControlledRealityWorkflowState::Ready
        );
        assert_eq!(record.controlled_reality_origin_request_id, None);
        assert!(record.controlled_reality_pending_update.is_none());

        let events = event_values(&event_log_path);
        let exposure = events
            .iter()
            .find(|event| event["kind"]["type"].as_str() == Some("bait_exposed"))
            .expect("bait exposure should be audited");
        let action = events
            .iter()
            .find(|event| event["kind"]["type"].as_str() == Some("bait_action_observed"))
            .expect("bait action should be audited");
        let action_request_id = action["request_id"]
            .as_str()
            .expect("bait action should have request id");
        assert_eq!(action["session_id"], exposure["session_id"]);
        assert_eq!(
            action["kind"]["exposure_id"],
            exposure["kind"]["exposure_id"]
        );
        assert_eq!(
            action["kind"]["header_value_mint_status"],
            "matched_session_value"
        );
        let request_seen = events
            .iter()
            .find(|event| {
                event["request_id"].as_str() == Some(action_request_id)
                    && event["kind"]["type"].as_str() == Some("request_seen")
            })
            .expect("action request should be audited");
        assert_eq!(request_seen["kind"]["method"], "POST");
        assert_eq!(request_seen["kind"]["path"], "/api/v2/import/reconcile");
        assert_eq!(request_seen["kind"]["routing_decision"], "eidolon_owned");
        let policy_changed = events
            .iter()
            .find(|event| {
                event["request_id"].as_str() == Some(action_request_id)
                    && event["kind"]["type"].as_str() == Some("policy_changed")
            })
            .expect("controlled-reality transition should be audited");
        assert_eq!(policy_changed["kind"]["from"], "observe");
        assert_eq!(policy_changed["kind"]["to"], "controlled_reality");
        let action_responses: Vec<&Value> = events
            .iter()
            .filter(|event| {
                event["request_id"].as_str() == Some(action_request_id)
                    && event["kind"]["type"].as_str() == Some("response_served")
            })
            .collect();
        assert_eq!(action_responses.len(), 1);
        assert_eq!(action_responses[0]["policy_state"], "controlled_reality");
        assert_eq!(action_responses[0]["kind"]["status"], 503);
        assert_eq!(
            action_responses[0]["kind"]["routing_decision"],
            "eidolon_owned"
        );
        assert!(action_responses[0]["kind"]["controlled_reality"].is_null());

        let failures: Vec<Value> =
            debug_events(&debug_log_path, "controlled_reality_backend_failed")
                .into_iter()
                .filter(|event| event["fields"]["request_id"].as_str() == Some(action_request_id))
                .collect();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0]["session_id"], action["session_id"]);
        assert_eq!(failures[0]["fields"]["reason"], "connect_failed");
        assert_eq!(failures[0]["fields"]["response_status"], 503);
        assert_eq!(failures[0]["fields"]["local_fallback"], false);
    }

    #[test]
    fn controlled_reality_workflow_locks_do_not_block_unrelated_shards() {
        let locks = Arc::new(ControlledRealityWorkflowLocks::new());
        let first_session = SessionId(uuid::Uuid::from_u128(1));
        let second_session = SessionId(uuid::Uuid::from_u128(2));
        let first_guard = locks
            .lock(first_session)
            .expect("first session lock should succeed");
        let worker_locks = Arc::clone(&locks);
        let (sender, receiver) = mpsc::channel();
        let worker = thread::spawn(move || {
            let _guard = worker_locks
                .lock(second_session)
                .expect("second session lock should succeed");
            sender.send(()).expect("worker should report lock");
        });

        receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("unrelated lock shard must not wait for the first session");
        drop(first_guard);
        worker.join().expect("lock worker should finish");
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
    fn disabled_interventions_fail_closed_for_configured_unsafe_bait_action() {
        let event_log_path = unique_temp_path("disabled-bait-events.jsonl");
        let control_path = unique_temp_path("disabled-bait-control.txt");
        must_ok(
            fs::write(&control_path, "disabled"),
            "control file should write",
        );
        let (upstream, upstream_recorder) =
            spawn_recording_upstream([json_response(r#"{"mode":"unexpected_upstream"}"#)]);
        let runtime = test_runtime_with_m1_controller(upstream, &event_log_path, control_path);

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &post_request_with_cookie(
                "/api/v2/import/reconcile",
                &cookie_header(),
                &[("X-Migration-Trace", "rel_2025_04_b7f2")],
            ),
        ));
        let upstream_requests = upstream_recorder.finish();

        assert_eq!(response.status, 403);
        assert!(
            upstream_requests.is_empty(),
            "request reached protected upstream"
        );
        assert!(
            must_ok(String::from_utf8(response.body), "body should be utf8")
                .contains("failed closed")
        );
        assert_event_routing(&event_log_path, "request_seen", "eidolon_owned");
        assert_event_type_absent(&event_log_path, "bait_exposed");
        assert_event_type_absent(&event_log_path, "bait_action_observed");
    }

    #[test]
    fn custom_profile_unsafe_methods_missing_and_wrong_proofs_fail_closed() {
        for method in ["POST", "PUT", "PATCH", "DELETE", "CONNECT", "PROPFIND"] {
            let path = write_bait_profile(&custom_unsafe_action_profile_json(method));
            let loaded = load_bait_profile(&path).expect("custom bait profile should load");
            let event_log_path =
                unique_temp_path(&format!("custom-{method}-bait-action-events.jsonl"));
            let (upstream, upstream_recorder) =
                spawn_recording_upstream([json_response(r#"{"mode":"unexpected_upstream"}"#)]);
            let runtime = test_runtime_with_bait_profile(
                upstream,
                &event_log_path,
                unique_temp_path(&format!("custom-{method}-bait-action-control.txt")),
                loaded,
                None,
            );

            let cookie = cookie_header();
            let missing_target = if method == "PATCH" {
                "/eidolon-lab/custom-commit?attempt=1"
            } else {
                "/eidolon-lab/custom-commit"
            };
            let missing_response = parse_downstream_response(&run_runtime_request(
                runtime.clone(),
                &request_with_cookie(method, missing_target, &cookie, &[]),
            ));
            let wrong_response = parse_downstream_response(&run_runtime_request(
                runtime,
                &request_with_cookie(
                    method,
                    "/eidolon-lab/custom-commit",
                    &cookie,
                    &[("X-Eidolon-Custom-Proof", "wrong")],
                ),
            ));
            let upstream_requests = upstream_recorder.finish();

            assert_eq!(missing_response.status, 403, "missing {method} proof");
            assert_eq!(wrong_response.status, 403, "wrong {method} proof");
            assert!(
                upstream_requests.is_empty(),
                "{method} request reached protected upstream"
            );
            let rejected_actions = events_of_type(&event_log_path, "bait_action_observed");
            assert_eq!(rejected_actions.len(), 1);
            let rejected_action = &rejected_actions[0];
            assert_eq!(rejected_action["kind"]["bait_id"], "custom_commit_trace");
            assert!(rejected_action["kind"]["exposure_id"].is_null());
            assert!(events_of_type(&event_log_path, "request_seen")
                .iter()
                .all(|event| event["kind"]["routing_decision"] == "eidolon_owned"));
        }
    }

    #[test]
    fn query_bearing_custom_action_fails_closed_if_validation_is_bypassed() {
        let action_target = "/eidolon-lab/custom-commit?attempt=1";

        for interventions_disabled in [false, true] {
            let loaded = unchecked_custom_unsafe_action_profile(action_target);
            let mode = if interventions_disabled {
                "emergency-disabled"
            } else {
                "enabled"
            };
            let event_log_path = unique_temp_path(&format!("query-action-{mode}-events.jsonl"));
            let control_path = unique_temp_path(&format!("query-action-{mode}-control.txt"));
            if interventions_disabled {
                must_ok(
                    fs::write(&control_path, "disabled"),
                    "control file should write",
                );
            }
            let (upstream, upstream_recorder) =
                spawn_recording_upstream([json_response(r#"{"mode":"unexpected_upstream"}"#)]);
            let runtime = test_runtime_with_bait_profile(
                upstream,
                &event_log_path,
                control_path,
                loaded,
                None,
            );
            let cookie = cookie_header();

            let missing_response = parse_downstream_response(&run_runtime_request(
                runtime.clone(),
                &request_with_cookie("PUT", action_target, &cookie, &[]),
            ));
            let wrong_response = parse_downstream_response(&run_runtime_request(
                runtime,
                &request_with_cookie(
                    "PUT",
                    action_target,
                    &cookie,
                    &[("X-Eidolon-Custom-Proof", "wrong")],
                ),
            ));
            let upstream_requests = upstream_recorder.finish();

            assert_eq!(missing_response.status, 403, "missing proof in {mode} mode");
            assert_eq!(wrong_response.status, 403, "wrong proof in {mode} mode");
            assert!(
                upstream_requests.is_empty(),
                "query-bearing configured action reached protected upstream in {mode} mode"
            );
            assert_eq!(events_of_type(&event_log_path, "request_seen").len(), 2);
            assert!(events_of_type(&event_log_path, "request_seen")
                .iter()
                .all(|event| event["kind"]["routing_decision"] == "eidolon_owned"));
        }
    }

    #[test]
    fn ambiguous_host_authority_never_reaches_policy_or_upstream() {
        let cases = [
            ("missing", "GET /docs HTTP/1.1\r\n\r\n"),
            ("malformed", "GET /docs HTTP/1.1\r\nHost: bad..host\r\n\r\n"),
            (
                "duplicate",
                "GET /docs HTTP/1.1\r\nHost: proxy.local\r\nHost: trusted.local\r\n\r\n",
            ),
            (
                "absolute-conflict",
                "GET http://proxy.local/docs HTTP/1.1\r\nHost: trusted.local\r\n\r\n",
            ),
        ];

        for (case, request) in cases {
            let event_log_path = unique_temp_path(&format!("ambiguous-host-{case}.jsonl"));
            let (upstream, upstream_recorder) =
                spawn_recording_upstream([json_response(r#"{"mode":"unexpected_upstream"}"#)]);
            let runtime = test_runtime(
                upstream,
                &event_log_path,
                unique_temp_path(&format!("ambiguous-host-{case}-control.txt")),
                SurfaceAction::ProtectedUpstream,
            );

            let response =
                parse_downstream_response(&run_runtime_request(runtime, request.as_bytes()));
            let upstream_requests = upstream_recorder.finish();

            assert_eq!(response.status, 400, "{case} Host case should fail");
            assert!(
                upstream_requests.is_empty(),
                "{case} Host case reached protected upstream"
            );
            assert!(events_of_type(&event_log_path, "request_seen")
                .iter()
                .all(|event| event["kind"]["routing_decision"] == "eidolon_owned"));
        }
    }

    #[test]
    fn malformed_host_header_syntax_never_reaches_upstream() {
        let event_log_path = unique_temp_path("malformed-host-syntax-events.jsonl");
        let (upstream, upstream_recorder) =
            spawn_recording_upstream([json_response(r#"{"mode":"unexpected_upstream"}"#)]);
        let runtime = test_runtime(
            upstream,
            &event_log_path,
            unique_temp_path("malformed-host-syntax-control.txt"),
            SurfaceAction::ProtectedUpstream,
        );

        let (result, response) = run_runtime_request_result(
            runtime,
            b"GET /docs HTTP/1.1\r\nHost : trusted.example\r\n\r\n",
        );
        let upstream_requests = upstream_recorder.finish();

        assert!(result.is_err());
        assert!(response.is_empty());
        assert!(upstream_requests.is_empty());
        assert!(events_of_type(&event_log_path, "request_seen").is_empty());
    }

    #[test]
    fn rejected_target_audit_uses_a_fixed_non_secret_placeholder() {
        let event_log_path = unique_temp_path("rejected-target-redaction-events.jsonl");
        let (upstream, upstream_recorder) =
            spawn_recording_upstream([json_response(r#"{"mode":"unexpected_upstream"}"#)]);
        let runtime = test_runtime(
            upstream,
            &event_log_path,
            unique_temp_path("rejected-target-redaction-control.txt"),
            SurfaceAction::ProtectedUpstream,
        );

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            b"GET /docs;token=secret-value HTTP/1.1\r\nHost: proxy.local\r\n\r\n",
        ));
        let upstream_requests = upstream_recorder.finish();
        let raw_events = fs::read_to_string(&event_log_path).expect("event log should read");

        assert_eq!(response.status, 400);
        assert!(upstream_requests.is_empty());
        assert!(!raw_events.contains("secret-value"));
        assert_eq!(
            first_event_of_type(&event_log_path, "request_seen")["kind"]["path"],
            REJECTED_REQUEST_TARGET
        );
    }

    #[test]
    fn ambiguous_custom_action_targets_never_connect_to_upstream_in_any_mode() {
        let cases = [
            (
                "raw-fragment",
                "/eidolon-lab/route-c",
                "/eidolon-lab/route-c#fragment",
                false,
                400_u16,
            ),
            (
                "encoded-incoming-alias",
                "/eidolon-lab/route-c",
                "/eidolon-lab/route-%63",
                false,
                403_u16,
            ),
            (
                "encoded-config-alias",
                "/eidolon-lab/route-%63",
                "/eidolon-lab/route-c",
                true,
                403_u16,
            ),
            (
                "encoded-reserved-alias",
                "/eidolon-lab/route/c",
                "/eidolon-lab/route%2Fc",
                false,
                400_u16,
            ),
            (
                "absolute-form",
                "/eidolon-lab/route-c",
                "http://proxy.local/eidolon-lab/route-c",
                false,
                403_u16,
            ),
        ];

        for interventions_disabled in [false, true] {
            let mode = if interventions_disabled {
                "emergency-disabled"
            } else {
                "enabled"
            };
            for (case, configured_path, incoming_target, bypass_validation, expected_status) in
                cases
            {
                let loaded = if bypass_validation {
                    // Loader rejection is primary; this exercises runtime defense in depth.
                    unchecked_custom_unsafe_action_profile(configured_path)
                } else {
                    let path = write_bait_profile(&custom_unsafe_action_profile_json_with_path(
                        "PUT",
                        configured_path,
                    ));
                    load_bait_profile(&path).expect("canonical custom profile should load")
                };
                let event_log_path =
                    unique_temp_path(&format!("ambiguous-{case}-{mode}-events.jsonl"));
                let control_path =
                    unique_temp_path(&format!("ambiguous-{case}-{mode}-control.txt"));
                if interventions_disabled {
                    must_ok(
                        fs::write(&control_path, "disabled"),
                        "control file should write",
                    );
                }
                let (upstream, upstream_recorder) =
                    spawn_recording_upstream([json_response(r#"{"mode":"unexpected_upstream"}"#)]);
                let runtime = test_runtime_with_bait_profile(
                    upstream,
                    &event_log_path,
                    control_path,
                    loaded,
                    None,
                );
                let cookie = cookie_header();

                let missing_response = parse_downstream_response(&run_runtime_request(
                    runtime.clone(),
                    &request_with_cookie("PUT", incoming_target, &cookie, &[]),
                ));
                let wrong_response = parse_downstream_response(&run_runtime_request(
                    runtime,
                    &request_with_cookie(
                        "PUT",
                        incoming_target,
                        &cookie,
                        &[("X-Eidolon-Custom-Proof", "wrong")],
                    ),
                ));
                let upstream_connections = upstream_recorder.finish();

                assert_eq!(
                    missing_response.status, expected_status,
                    "missing proof: {case} {mode}"
                );
                assert_eq!(
                    wrong_response.status, expected_status,
                    "wrong proof: {case} {mode}"
                );
                assert!(
                    upstream_connections.is_empty(),
                    "{case} target connected to protected upstream in {mode} mode"
                );
                assert_eq!(events_of_type(&event_log_path, "request_seen").len(), 2);
                assert!(events_of_type(&event_log_path, "request_seen")
                    .iter()
                    .all(|event| event["kind"]["routing_decision"] == "eidolon_owned"));
            }
        }
    }

    #[test]
    fn absolute_form_minted_proof_rejections_never_connect_to_upstream() {
        let path = write_bait_profile(session_minted_profile_json());
        let loaded = load_bait_profile(&path).expect("minted profile should load");
        let bait = loaded
            .registry
            .bait_for_surface("/docs/minted-trace")
            .expect("minted bait should exist")
            .clone();
        let secret: Arc<str> = Arc::from("mint-secret");
        let session_a = SessionId::new();
        let session_b = SessionId::new();
        let cookie_a = format!("eidolon_session={}", minted_cookie_value(session_a));
        let cookie_b = format!("eidolon_session={}", minted_cookie_value(session_b));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        let current =
            eidolon_bait::render_bait_for_session_at(&bait, session_a, Some(secret.as_ref()), now)
                .expect("current proof should render")
                .into_owned();
        let expired = eidolon_bait::render_bait_for_session_at(
            &bait,
            session_a,
            Some(secret.as_ref()),
            now.saturating_sub(180),
        )
        .expect("expired proof should render")
        .into_owned();
        let header_name = current
            .expected_action
            .header_name
            .as_deref()
            .expect("minted bait should keep header name")
            .to_string();
        let current_value = current
            .expected_action
            .header_value
            .expect("current proof should have a value");
        let expired_value = expired
            .expected_action
            .header_value
            .expect("expired proof should have a value");
        let absolute_target = format!("http://proxy.local{}", bait.expected_action.path);
        let event_log_path = unique_temp_path("absolute-minted-proof-events.jsonl");
        let (upstream, upstream_recorder) =
            spawn_recording_upstream([json_response(r#"{"mode":"unexpected_upstream"}"#)]);
        let runtime = test_runtime_with_bait_profile(
            upstream,
            &event_log_path,
            unique_temp_path("absolute-minted-proof-control.txt"),
            loaded,
            Some(secret),
        );

        let requests = [
            request_with_cookie("POST", &absolute_target, &cookie_a, &[]),
            request_with_cookie(
                "POST",
                &absolute_target,
                &cookie_a,
                &[(&header_name, "minted.not-a-valid-proof")],
            ),
            request_with_cookie(
                "POST",
                &absolute_target,
                &cookie_a,
                &[(&header_name, &expired_value)],
            ),
            request_with_cookie(
                "POST",
                &absolute_target,
                &cookie_b,
                &[(&header_name, &current_value)],
            ),
            request_with_cookie(
                "POST",
                &absolute_target,
                &cookie_a,
                &[(&header_name, &current_value)],
            ),
            request_with_cookie(
                "POST",
                &absolute_target,
                &cookie_a,
                &[(&header_name, &current_value)],
            ),
        ];
        let responses = requests.map(|request| {
            parse_downstream_response(&run_runtime_request(runtime.clone(), &request))
        });
        let upstream_connections = upstream_recorder.finish();

        assert_eq!(
            responses.map(|response| response.status),
            [403, 403, 403, 403, 202, 403]
        );
        assert!(
            upstream_connections.is_empty(),
            "absolute-form proof requests connected to protected upstream"
        );
        let statuses = events_of_type(&event_log_path, "bait_action_observed")
            .into_iter()
            .map(|event| event["kind"]["header_value_mint_status"].clone())
            .collect::<Vec<_>>();
        assert_eq!(
            statuses,
            [
                "missing_session_value",
                "malformed_session_value",
                "expired_session_value",
                "session_value_mismatch",
                "matched_session_value",
                "replay_seen",
            ]
        );
        assert!(events_of_type(&event_log_path, "request_seen")
            .iter()
            .all(|event| event["kind"]["routing_decision"] == "eidolon_owned"));
    }

    #[test]
    fn encoded_delimiter_custom_actions_fail_closed_without_upstream_requests() {
        for action_path in [
            "/eidolon-lab/custom-commit%3Fattempt=1",
            "/eidolon-lab/custom-commit%23proof",
        ] {
            let loaded = unchecked_custom_unsafe_action_profile(action_path);
            let event_log_path = unique_temp_path("encoded-custom-action-events.jsonl");
            let (upstream, upstream_recorder) =
                spawn_recording_upstream([json_response(r#"{"mode":"unexpected_upstream"}"#)]);
            let runtime = test_runtime_with_bait_profile(
                upstream,
                &event_log_path,
                unique_temp_path("encoded-custom-action-control.txt"),
                loaded,
                None,
            );
            let cookie = cookie_header();

            let missing_response = parse_downstream_response(&run_runtime_request(
                runtime.clone(),
                &request_with_cookie("PUT", action_path, &cookie, &[]),
            ));
            let wrong_response = parse_downstream_response(&run_runtime_request(
                runtime,
                &request_with_cookie(
                    "PUT",
                    action_path,
                    &cookie,
                    &[("X-Eidolon-Custom-Proof", "wrong")],
                ),
            ));
            let upstream_requests = upstream_recorder.finish();

            assert_eq!(missing_response.status, 400);
            assert_eq!(wrong_response.status, 400);
            assert!(
                upstream_requests.is_empty(),
                "encoded configured action reached protected upstream"
            );
        }
    }

    #[test]
    fn custom_profile_valid_put_action_preserves_interception_behavior() {
        let path = write_bait_profile(&custom_unsafe_action_profile_json("PUT"));
        let loaded = load_bait_profile(&path).expect("custom bait profile should load");
        let event_log_path = unique_temp_path("valid-custom-put-action-events.jsonl");
        let (upstream, upstream_recorder) =
            spawn_recording_upstream([json_response(r#"{"mode":"unexpected_upstream"}"#)]);
        let runtime = test_runtime_with_bait_profile(
            upstream,
            &event_log_path,
            unique_temp_path("valid-custom-put-action-control.txt"),
            loaded,
            None,
        );

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &request_with_cookie(
                "PUT",
                "/eidolon-lab/custom-commit",
                &cookie_header(),
                &[("X-Eidolon-Custom-Proof", "custom-proof-value")],
            ),
        ));
        let upstream_requests = upstream_recorder.finish();

        assert_eq!(response.status, 202);
        assert!(upstream_requests.is_empty());
        let action = first_event_of_type(&event_log_path, "bait_action_observed");
        assert_eq!(action["kind"]["bait_id"], "custom_commit_trace");
        assert!(action["kind"]["exposure_id"].is_null());
        assert_event_routing(&event_log_path, "request_seen", "eidolon_owned");
    }

    #[test]
    fn custom_profile_rejected_action_fails_closed_before_rewritten_upstream() {
        let path = write_bait_profile(&custom_unsafe_action_profile_json("PUT"));
        let loaded = load_bait_profile(&path).expect("custom bait profile should load");
        let event_log_path = unique_temp_path("rewritten-custom-put-action-events.jsonl");
        let (upstream, upstream_recorder) =
            spawn_recording_upstream([html_response("<html><body>upstream</body></html>")]);
        let mut runtime = test_runtime_with_bait_profile(
            upstream,
            &event_log_path,
            unique_temp_path("rewritten-custom-put-action-control.txt"),
            loaded,
            None,
        );
        runtime.surface_controller = Arc::new(StaticSurfaceController {
            action: html_rewrite_action("<p>should not rewrite</p>"),
        });

        let response = parse_downstream_response(&run_runtime_request(
            runtime,
            &request_with_cookie(
                "PUT",
                "/eidolon-lab/custom-commit",
                &cookie_header(),
                &[("X-Eidolon-Custom-Proof", "wrong")],
            ),
        ));
        let upstream_requests = upstream_recorder.finish();

        assert_eq!(response.status, 403);
        assert!(upstream_requests.is_empty());
        assert_event_routing(&event_log_path, "request_seen", "eidolon_owned");
    }

    #[test]
    fn disabled_interventions_fail_closed_for_custom_profile_unsafe_bait_action() {
        let path = write_bait_profile(&custom_unsafe_action_profile_json("PUT"));
        let loaded = load_bait_profile(&path).expect("custom bait profile should load");
        let event_log_path = unique_temp_path("disabled-custom-bait-action-events.jsonl");
        let control_path = unique_temp_path("disabled-custom-bait-action-control.txt");
        must_ok(
            fs::write(&control_path, "disabled"),
            "control file should write",
        );
        let (upstream, upstream_recorder) =
            spawn_recording_upstream([json_response(r#"{"mode":"unexpected_upstream"}"#)]);
        let runtime =
            test_runtime_with_bait_profile(upstream, &event_log_path, control_path, loaded, None);

        let cookie = cookie_header();
        let responses = [
            request_with_cookie(
                "PUT",
                "/eidolon-lab/custom-commit",
                &cookie,
                &[("X-Eidolon-Custom-Proof", "custom-proof-value")],
            ),
            request_with_cookie("PUT", "/eidolon-lab/custom-commit", &cookie, &[]),
            request_with_cookie(
                "PUT",
                "/eidolon-lab/custom-commit",
                &cookie,
                &[("X-Eidolon-Custom-Proof", "wrong")],
            ),
        ]
        .map(|request| parse_downstream_response(&run_runtime_request(runtime.clone(), &request)));
        let upstream_requests = upstream_recorder.finish();

        assert!(responses.iter().all(|response| response.status == 403));
        assert!(
            upstream_requests.is_empty(),
            "request reached protected upstream"
        );
        assert_eq!(events_of_type(&event_log_path, "request_seen").len(), 3);
        assert!(events_of_type(&event_log_path, "request_seen")
            .iter()
            .all(|event| event["kind"]["routing_decision"] == "eidolon_owned"));
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
    fn runtime_controlled_reality_job_lifecycle_is_durable_and_never_reaches_upstream() {
        let event_log_path = unique_temp_path("controlled-workflow-events.jsonl");
        let control_path = unique_temp_path("controlled-workflow-control.txt");
        let (upstream, recorder) =
            spawn_recording_upstream([json_response(r#"{"mode":"upstream"}"#)]);
        let runtime =
            test_runtime_with_m1_controller(upstream, &event_log_path, control_path.clone());
        let owner_cookie = cookie_header();
        let other_cookie = cookie_header();
        set_runtime_policy_state(&runtime, &owner_cookie, PolicyState::ControlledReality);

        let submitted = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &request_with_cookie(
                "POST",
                "/api/v2/import/reconcile?source=SENSITIVE_SENTINEL",
                &owner_cookie,
                &[("X-Untrusted-Value", "SENSITIVE_SENTINEL")],
            ),
        ));
        let submitted_json: Value =
            serde_json::from_slice(&submitted.body).expect("submission should be json");
        let job_id = submitted_json["job_id"]
            .as_str()
            .expect("submission should return job id")
            .to_string();
        let status_path = submitted_json["status_path"]
            .as_str()
            .expect("submission should return status path")
            .to_string();

        let status = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &get_request_with_cookie(&status_path, &owner_cookie),
        ));
        let status_json: Value =
            serde_json::from_slice(&status.body).expect("status should be json");
        let artifact_path = status_json["artifact"]["path"]
            .as_str()
            .expect("completed job should return artifact path")
            .to_string();
        let artifact_sha256 = status_json["artifact"]["sha256"]
            .as_str()
            .expect("completed job should return artifact digest")
            .to_string();

        let artifact = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &get_request_with_cookie(&artifact_path, &owner_cookie),
        ));
        let cross_session = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &get_request_with_cookie(&status_path, &other_cookie),
        ));
        fs::write(&control_path, "disabled").expect("control file should write");
        let disabled = parse_downstream_response(&run_runtime_request(
            runtime,
            &get_request_with_cookie(&artifact_path, &owner_cookie),
        ));
        let upstream_requests = recorder.finish();

        assert_eq!(submitted.status, 202);
        assert_eq!(status.status, 200);
        assert_eq!(status_json["status"], "completed");
        assert_eq!(status_json["job_id"], job_id);
        assert_eq!(artifact.status, 200);
        assert_eq!(
            header_values(&artifact, "x-eidolon-artifact-sha256"),
            vec![artifact_sha256.as_str()]
        );
        assert_eq!(cross_session.status, 404);
        assert_eq!(disabled.status, 404);
        assert!(
            upstream_requests.is_empty(),
            "controlled workflow request reached protected upstream"
        );

        let interactions: Vec<Value> = events_of_type(&event_log_path, "response_served")
            .into_iter()
            .filter(|event| event["kind"]["controlled_reality"].is_object())
            .collect();
        assert_eq!(interactions.len(), 3);
        assert_eq!(
            interactions[0]["kind"]["controlled_reality"]["kind"],
            "job_submitted"
        );
        assert_eq!(
            interactions[1]["kind"]["controlled_reality"]["kind"],
            "status_read"
        );
        assert_eq!(
            interactions[2]["kind"]["controlled_reality"]["kind"],
            "artifact_read"
        );
        let origin_request_id = interactions[0]["request_id"].clone();
        assert!(interactions.iter().all(|event| {
            event["kind"]["controlled_reality"]["origin_request_id"] == origin_request_id
                && event["kind"]["controlled_reality"]["job_id"] == job_id
        }));
        let event_log =
            fs::read_to_string(&event_log_path).expect("event log should remain readable");
        assert!(!event_log.contains("SENSITIVE_SENTINEL"));
    }

    #[test]
    fn runtime_controlled_follow_up_namespace_never_reaches_upstream() {
        let event_log_path = unique_temp_path("controlled-follow-up-boundary-events.jsonl");
        let (upstream, recorder) =
            spawn_recording_upstream([json_response(r#"{"mode":"unexpected_upstream"}"#)]);
        let runtime = test_runtime_with_m1_controller(
            upstream,
            &event_log_path,
            unique_temp_path("controlled-follow-up-boundary-control.txt"),
        );
        let owner_cookie = cookie_header();
        let other_cookie = cookie_header();
        set_runtime_policy_state(&runtime, &owner_cookie, PolicyState::ControlledReality);

        let collection_root = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &get_request_with_cookie("/api/v2/import/reconcile/jobs", &other_cookie),
        ));
        let submitted = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &request_with_cookie("POST", "/api/v2/import/reconcile", &owner_cookie, &[]),
        ));
        let submitted_json: Value =
            serde_json::from_slice(&submitted.body).expect("submission should be json");
        let status_path = submitted_json["status_path"]
            .as_str()
            .expect("submission should return status path");
        let unsupported_method = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &request_with_cookie("DELETE", status_path, &owner_cookie, &[]),
        ));
        let unknown_job = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &get_request_with_cookie(
                "/api/v2/import/reconcile/jobs/job_0000000000000000",
                &owner_cookie,
            ),
        ));
        let cross_session = parse_downstream_response(&run_runtime_request(
            runtime,
            &get_request_with_cookie(status_path, &other_cookie),
        ));
        let upstream_requests = recorder.finish();

        assert_eq!(collection_root.status, 404);
        assert_eq!(submitted.status, 202);
        assert_eq!(unsupported_method.status, 405);
        assert_eq!(unknown_job.status, 404);
        assert_eq!(cross_session.status, 404);
        assert!(
            upstream_requests.is_empty(),
            "controlled follow-up namespace reached protected upstream"
        );
    }

    #[test]
    fn event_log_failure_cannot_leave_usable_unproven_workflow_state() {
        let event_log_path = unique_temp_path("controlled-event-failure-events.jsonl");
        let recovered_event_log_path =
            unique_temp_path("controlled-event-failure-recovered-events.jsonl");
        let mut runtime = test_runtime(
            closed_upstream(),
            &event_log_path,
            unique_temp_path("controlled-event-failure-control.txt"),
            SurfaceAction::ProtectedUpstream,
        );
        let cookie = cookie_header();
        let session_id = session_id_from_cookie(&cookie).expect("cookie should contain session");
        set_runtime_policy_state(&runtime, &cookie, PolicyState::ControlledReality);
        let event_log = Arc::clone(&runtime.event_log);
        assert!(thread::spawn(move || {
            let _guard = event_log.lock().expect("event log should lock");
            panic!("poison event log for failure-path coverage");
        })
        .join()
        .is_err());

        let (failed, failed_response) = run_runtime_request_result(
            runtime.clone(),
            &request_with_cookie("POST", "/api/v2/import/reconcile", &cookie, &[]),
        );

        assert!(failed.is_err());
        assert!(failed_response.is_empty());
        let pending = runtime
            .policy_store
            .lock()
            .expect("policy store should lock")
            .record(session_id);
        assert_eq!(
            pending.controlled_reality_workflow_state,
            ControlledRealityWorkflowState::Queued
        );
        assert!(pending.controlled_reality_pending_update.is_some());

        runtime.event_log = Arc::new(Mutex::new(
            FileEventLogWriter::open(&recovered_event_log_path)
                .expect("replacement event log should open"),
        ));
        let retry = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &request_with_cookie("POST", "/api/v2/import/reconcile", &cookie, &[]),
        ));

        assert_eq!(retry.status, 202);
        let recovered = runtime
            .policy_store
            .lock()
            .expect("policy store should lock")
            .record(session_id);
        assert_eq!(
            recovered.controlled_reality_workflow_state,
            ControlledRealityWorkflowState::Queued
        );
        assert_eq!(recovered.controlled_reality_depth, 1);
        assert_eq!(recovered.controlled_reality_pending_update, None);
        let interactions: Vec<Value> = events_of_type(&recovered_event_log_path, "response_served")
            .into_iter()
            .filter(|event| event["kind"]["controlled_reality"].is_object())
            .collect();
        assert_eq!(interactions.len(), 1);
        assert_eq!(
            interactions[0]["request_id"],
            interactions[0]["kind"]["controlled_reality"]["origin_request_id"]
        );
    }

    #[test]
    fn missing_block_response_leaves_only_precommit_request_audit() {
        let event_log_path = unique_temp_path("controlled-missing-block-response-events.jsonl");
        let runtime = test_runtime(
            closed_upstream(),
            &event_log_path,
            unique_temp_path("controlled-missing-block-response-control.txt"),
            SurfaceAction::ProtectedUpstream,
        );
        let request_id = RequestId::new();
        let request = parse_http_request_head(
            b"GET /api/v2/import/reconcile/jobs/job_0123456789abcdef HTTP/1.1\r\nHost: proxy.local\r\n\r\n",
        )
        .expect("request should parse");
        let surface_request = surface_request_meta(&request, &request.target);
        let session = effective_session_context(
            &runtime,
            &request,
            &surface_request,
            Some("127.0.0.1".parse().expect("loopback IP should parse")),
            request_id,
        )
        .expect("session should resolve");
        {
            let mut store = runtime
                .policy_store
                .lock()
                .expect("policy store should lock");
            store
                .set_policy_state(session.session_id, PolicyState::ControlledReality)
                .expect("controlled state should persist");
            store
                .note_controlled_reality_interaction(
                    session.session_id,
                    request_id,
                    eidolon_proxy::policy_store::ControlledRealityRequestAction::BranchRead,
                    MAX_CONTROLLED_REALITY_ACTION_DEPTH,
                )
                .expect("pending request should persist");
        }
        let transition = policy::PolicyTransition::new(
            PolicyState::ControlledReality,
            PolicyState::Blocked,
            "test staged block",
        );
        stage_controlled_reality_policy_transition(
            &runtime,
            session.session_id,
            request_id,
            &transition,
        )
        .expect("block should stage");
        let blocked_decision = transition.decision(RoutingDecision::EidolonOwned);

        write_direct_response_request_audit(
            &runtime,
            &session,
            &request,
            &request.target,
            request_id,
            &blocked_decision,
            policy::DiscoveryReconAggregationScore::default(),
            policy::discovery_recon_aggregation_score_threshold(),
            true,
            InterventionMode::Enabled,
            true,
        )
        .expect("pre-response request audit should write");
        reconcile_pending_controlled_reality_interaction(&runtime, session.session_id)
            .expect("missing response should roll back");

        let request_events = events_of_type(&event_log_path, "request_seen");
        assert_eq!(request_events.len(), 1);
        assert_eq!(request_events[0]["policy_state"], "controlled_reality");
        assert_eq!(
            request_events[0]["kind"]["routing_decision"],
            "controlled_reality"
        );
        assert!(events_of_type(&event_log_path, "policy_decision").is_empty());
        assert!(events_of_type(&event_log_path, "policy_changed").is_empty());
        assert!(events_of_type(&event_log_path, "response_served").is_empty());
        let record = runtime
            .policy_store
            .lock()
            .expect("policy store should lock")
            .record(session.session_id);
        assert_eq!(record.policy_state, PolicyState::ControlledReality);
        assert_eq!(record.controlled_reality_pending_update, None);
    }

    #[test]
    fn crash_after_response_fsync_rolls_pending_workflow_forward() {
        let event_log_path = unique_temp_path("controlled-fsync-recovery-events.jsonl");
        let policy_store_path = unique_temp_path("controlled-fsync-recovery-policy.json");
        let mut runtime = test_runtime(
            closed_upstream(),
            &event_log_path,
            unique_temp_path("controlled-fsync-recovery-control.txt"),
            SurfaceAction::ProtectedUpstream,
        );
        runtime.policy_store = Arc::new(Mutex::new(
            PolicyStateStore::open(&policy_store_path).expect("policy store should open"),
        ));
        let session_id = SessionId::new();
        let request_id = RequestId::new();
        let progress = {
            let mut store = runtime
                .policy_store
                .lock()
                .expect("policy store should lock");
            store
                .set_policy_state(session_id, PolicyState::ControlledReality)
                .expect("controlled state should persist");
            store
                .note_controlled_reality_interaction(
                    session_id,
                    request_id,
                    eidolon_proxy::policy_store::ControlledRealityRequestAction::JobSubmitted,
                    MAX_CONTROLLED_REALITY_ACTION_DEPTH,
                )
                .expect("pending workflow should persist")
        };
        let expected = runtime.controlled_reality.expected_response(
            session_id,
            progress,
            eidolon_proxy::policy_store::ControlledRealityRequestAction::JobSubmitted,
            MAX_CONTROLLED_REALITY_ACTION_DEPTH,
        );
        let response_event = Event::new(
            session_id,
            EventSource::Proxy,
            PolicyState::ControlledReality,
            EventKind::ResponseServed {
                status: expected.status,
                routing_decision: expected.routing_decision,
                controlled_reality: expected.interaction,
            },
        )
        .with_request_id(request_id);
        write_controlled_reality_response_event(&runtime, &response_event, true)
            .expect("response event should fsync");

        runtime.policy_store = Arc::new(Mutex::new(
            PolicyStateStore::open(&policy_store_path)
                .expect("pending policy store should reopen after crash"),
        ));
        runtime.event_log = Arc::new(Mutex::new(
            FileEventLogWriter::open(&event_log_path).expect("event log should reopen after crash"),
        ));
        reconcile_all_pending_controlled_reality_interactions(&runtime)
            .expect("startup should reconcile the durable pending transition");

        let record = runtime
            .policy_store
            .lock()
            .expect("policy store should lock")
            .record(session_id);
        assert_eq!(record.controlled_reality_depth, 1);
        assert_eq!(
            record.controlled_reality_workflow_state,
            ControlledRealityWorkflowState::Queued
        );
        assert_eq!(
            record.controlled_reality_origin_request_id,
            Some(request_id)
        );
        assert_eq!(record.controlled_reality_pending_update, None);
        drop(runtime);
        fs::remove_file(event_log_path).expect("event log should remove");
        fs::remove_file(policy_store_path).expect("policy store should remove");
    }

    #[test]
    fn crash_after_block_response_fsync_rolls_staged_policy_state_forward() {
        let event_log_path = unique_temp_path("controlled-block-fsync-events.jsonl");
        let policy_store_path = unique_temp_path("controlled-block-fsync-policy.json");
        let mut runtime = test_runtime(
            closed_upstream(),
            &event_log_path,
            unique_temp_path("controlled-block-fsync-control.txt"),
            SurfaceAction::ProtectedUpstream,
        );
        runtime.policy_store = Arc::new(Mutex::new(
            PolicyStateStore::open(&policy_store_path).expect("policy store should open"),
        ));
        let session_id = SessionId::new();
        let request_id = RequestId::new();
        {
            let mut store = runtime
                .policy_store
                .lock()
                .expect("policy store should lock");
            store
                .set_policy_state(session_id, PolicyState::ControlledReality)
                .expect("controlled state should persist");
            for _ in 0..=MAX_CONTROLLED_REALITY_ACTION_DEPTH {
                store
                    .increment_controlled_reality_depth(session_id)
                    .expect("depth should persist");
            }
            store
                .note_controlled_reality_interaction(
                    session_id,
                    request_id,
                    eidolon_proxy::policy_store::ControlledRealityRequestAction::BranchRead,
                    MAX_CONTROLLED_REALITY_ACTION_DEPTH,
                )
                .expect("pending over-limit action should persist");
        }
        let transition = request_evaluation::controlled_reality_depth_transition(
            PolicyState::ControlledReality,
            "/api/v2/import/reconcile",
            MAX_CONTROLLED_REALITY_ACTION_DEPTH + 2,
            MAX_CONTROLLED_REALITY_ACTION_DEPTH,
        )
        .expect("repeated over-limit action should block");
        stage_controlled_reality_policy_transition(&runtime, session_id, request_id, &transition)
            .expect("blocked state should stage");
        let response_event = Event::new(
            session_id,
            EventSource::Proxy,
            PolicyState::Blocked,
            EventKind::ResponseServed {
                status: 403,
                routing_decision: RoutingDecision::EidolonOwned,
                controlled_reality: None,
            },
        )
        .with_request_id(request_id);
        let expected_policy_changed = {
            let mut store = runtime
                .policy_store
                .lock()
                .expect("policy store should lock");
            let expected_policy_changed = store
                .record(session_id)
                .controlled_reality_pending_update
                .and_then(|pending| pending.expected_policy_changed)
                .expect("blocked transition should persist its policy event");
            store
                .set_pending_controlled_reality_response(
                    session_id,
                    request_id,
                    ControlledRealityPendingResponse {
                        event_id: response_event.id,
                        policy_state: PolicyState::Blocked,
                        status: 403,
                        routing_decision: RoutingDecision::EidolonOwned,
                        interaction_kind: None,
                        controlled_reality_sha256: controlled_reality_semantics_sha256(&None)
                            .expect("empty interaction should serialize"),
                    },
                )
                .expect("blocked response contract should persist");
            expected_policy_changed
        };
        runtime
            .event_log
            .lock()
            .expect("event log should lock")
            .write_durable_response(&response_event)
            .expect("response should fsync before the simulated crash");

        runtime.policy_store = Arc::new(Mutex::new(
            PolicyStateStore::open(&policy_store_path)
                .expect("pending policy store should reopen after crash"),
        ));
        runtime.event_log = Arc::new(Mutex::new(
            FileEventLogWriter::open(&event_log_path).expect("event log should reopen after crash"),
        ));
        reconcile_all_pending_controlled_reality_interactions(&runtime)
            .expect("startup should roll the blocked state forward");

        let record = runtime
            .policy_store
            .lock()
            .expect("policy store should lock")
            .record(session_id);
        assert_eq!(record.policy_state, PolicyState::Blocked);
        assert_eq!(record.controlled_reality_depth, 0);
        assert_eq!(record.controlled_reality_pending_update, None);
        let policy_events = events_of_type(&event_log_path, "policy_changed");
        assert_eq!(policy_events.len(), 1);
        assert_eq!(
            policy_events[0]["id"],
            expected_policy_changed.id.to_string()
        );
        drop(runtime);
        fs::remove_file(event_log_path).expect("event log should remove");
        fs::remove_file(policy_store_path).expect("policy store should remove");
    }

    #[test]
    fn durable_response_recovery_uses_stored_semantics_after_depth_config_change() {
        let event_log_path = unique_temp_path("controlled-config-recovery-events.jsonl");
        let policy_store_path = unique_temp_path("controlled-config-recovery-policy.json");
        let mut runtime = test_runtime(
            closed_upstream(),
            &event_log_path,
            unique_temp_path("controlled-config-recovery-control.txt"),
            SurfaceAction::ProtectedUpstream,
        );
        runtime.controlled_reality_config.max_action_depth = 1;
        runtime.policy_store = Arc::new(Mutex::new(
            PolicyStateStore::open(&policy_store_path).expect("policy store should open"),
        ));
        let session_id = SessionId::new();
        let request_id = RequestId::new();
        let progress = {
            let mut store = runtime
                .policy_store
                .lock()
                .expect("policy store should lock");
            store
                .set_policy_state(session_id, PolicyState::ControlledReality)
                .expect("controlled state should persist");
            store
                .increment_controlled_reality_depth(session_id)
                .expect("prior depth should persist");
            store
                .note_controlled_reality_interaction(
                    session_id,
                    request_id,
                    eidolon_proxy::policy_store::ControlledRealityRequestAction::BranchRead,
                    1,
                )
                .expect("pending over-limit action should persist")
        };
        let expected = runtime.controlled_reality.expected_response(
            session_id,
            progress,
            eidolon_proxy::policy_store::ControlledRealityRequestAction::BranchRead,
            1,
        );
        let response_event = Event::new(
            session_id,
            EventSource::Proxy,
            PolicyState::ControlledReality,
            EventKind::ResponseServed {
                status: expected.status,
                routing_decision: expected.routing_decision,
                controlled_reality: expected.interaction,
            },
        )
        .with_request_id(request_id);
        write_controlled_reality_response_event(&runtime, &response_event, true)
            .expect("rate-limited response should fsync");

        runtime.controlled_reality_config.max_action_depth = 4;
        runtime.policy_store = Arc::new(Mutex::new(
            PolicyStateStore::open(&policy_store_path)
                .expect("pending policy store should reopen after config change"),
        ));
        runtime.event_log = Arc::new(Mutex::new(
            FileEventLogWriter::open(&event_log_path).expect("event log should reopen after crash"),
        ));
        reconcile_all_pending_controlled_reality_interactions(&runtime)
            .expect("stored response semantics should survive config changes");

        let record = runtime
            .policy_store
            .lock()
            .expect("policy store should lock")
            .record(session_id);
        assert_eq!(record.policy_state, PolicyState::ControlledReality);
        assert_eq!(record.controlled_reality_depth, 2);
        assert_eq!(record.controlled_reality_pending_update, None);
        drop(runtime);
        fs::remove_file(event_log_path).expect("event log should remove");
        fs::remove_file(policy_store_path).expect("policy store should remove");
    }

    #[test]
    fn conflicting_durable_response_keeps_workflow_pending() {
        let event_log_path = unique_temp_path("controlled-conflicting-response-events.jsonl");
        let runtime = test_runtime(
            closed_upstream(),
            &event_log_path,
            unique_temp_path("controlled-conflicting-response-control.txt"),
            SurfaceAction::ProtectedUpstream,
        );
        let session_id = SessionId::new();
        let request_id = RequestId::new();
        let progress = {
            let mut store = runtime
                .policy_store
                .lock()
                .expect("policy store should lock");
            store
                .set_policy_state(session_id, PolicyState::ControlledReality)
                .expect("controlled state should persist");
            store
                .note_controlled_reality_interaction(
                    session_id,
                    request_id,
                    eidolon_proxy::policy_store::ControlledRealityRequestAction::JobSubmitted,
                    MAX_CONTROLLED_REALITY_ACTION_DEPTH,
                )
                .expect("pending workflow should persist")
        };
        let expected = runtime.controlled_reality.expected_response(
            session_id,
            progress,
            eidolon_proxy::policy_store::ControlledRealityRequestAction::JobSubmitted,
            MAX_CONTROLLED_REALITY_ACTION_DEPTH,
        );
        let response_event = Event::new(
            session_id,
            EventSource::Proxy,
            PolicyState::ControlledReality,
            EventKind::ResponseServed {
                status: expected.status,
                routing_decision: expected.routing_decision,
                controlled_reality: Some(ControlledRealityInteraction {
                    branch: eidolon_core::ControlledRealityBranch::ImportReconcile,
                    origin_request_id: request_id,
                    from_state: progress.from_state,
                    to_state: progress.to_state,
                    job_id: eidolon_core::ControlledRealityJobId::new("job_ffffffffffffffff")
                        .expect("wrong job id should still satisfy the type"),
                    action: eidolon_core::ControlledRealityInteractionAction::JobSubmitted,
                }),
            },
        )
        .with_request_id(request_id);
        runtime
            .policy_store
            .lock()
            .expect("policy store should lock")
            .set_pending_controlled_reality_response(
                session_id,
                request_id,
                ControlledRealityPendingResponse {
                    event_id: response_event.id,
                    policy_state: PolicyState::ControlledReality,
                    status: expected.status,
                    routing_decision: expected.routing_decision,
                    interaction_kind: Some(ControlledRealityPendingInteractionKind::JobSubmitted),
                    controlled_reality_sha256: controlled_reality_semantics_sha256(
                        &expected.interaction,
                    )
                    .expect("expected interaction should serialize"),
                },
            )
            .expect("pending response contract should persist");
        runtime
            .event_log
            .lock()
            .expect("event log should lock")
            .write_durable_response(&response_event)
            .expect("conflicting response should fsync");

        let error = reconcile_pending_controlled_reality_interaction(&runtime, session_id)
            .expect_err("conflicting durable response must fail closed");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let record = runtime
            .policy_store
            .lock()
            .expect("policy store should lock")
            .record(session_id);
        assert_eq!(
            record.controlled_reality_workflow_state,
            ControlledRealityWorkflowState::Queued
        );
        assert!(record.controlled_reality_pending_update.is_some());
        drop(runtime);
        fs::remove_file(event_log_path).expect("event log should remove");
    }

    #[test]
    fn wrong_response_routing_is_rejected_before_workflow_fsync() {
        let event_log_path = unique_temp_path("controlled-wrong-routing-events.jsonl");
        let runtime = test_runtime(
            closed_upstream(),
            &event_log_path,
            unique_temp_path("controlled-wrong-routing-control.txt"),
            SurfaceAction::ProtectedUpstream,
        );
        let session_id = SessionId::new();
        let request_id = RequestId::new();
        let progress = {
            let mut store = runtime
                .policy_store
                .lock()
                .expect("policy store should lock");
            store
                .set_policy_state(session_id, PolicyState::ControlledReality)
                .expect("controlled state should persist");
            store
                .note_controlled_reality_interaction(
                    session_id,
                    request_id,
                    eidolon_proxy::policy_store::ControlledRealityRequestAction::JobSubmitted,
                    MAX_CONTROLLED_REALITY_ACTION_DEPTH,
                )
                .expect("pending workflow should persist")
        };
        let expected = runtime.controlled_reality.expected_response(
            session_id,
            progress,
            eidolon_proxy::policy_store::ControlledRealityRequestAction::JobSubmitted,
            MAX_CONTROLLED_REALITY_ACTION_DEPTH,
        );
        let response_event = Event::new(
            session_id,
            EventSource::Proxy,
            PolicyState::ControlledReality,
            EventKind::ResponseServed {
                status: expected.status,
                routing_decision: RoutingDecision::ProtectedUpstream,
                controlled_reality: expected.interaction,
            },
        )
        .with_request_id(request_id);

        let error = write_controlled_reality_response_event(&runtime, &response_event, true)
            .expect_err("wrong response routing must fail before fsync");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(events_of_type(&event_log_path, "response_served").is_empty());
        let pending = runtime
            .policy_store
            .lock()
            .expect("policy store should lock")
            .record(session_id)
            .controlled_reality_pending_update
            .expect("workflow should remain pending");
        assert_eq!(pending.expected_response, None);
        drop(runtime);
        fs::remove_file(event_log_path).expect("event log should remove");
    }

    #[test]
    fn concurrent_controlled_submissions_serialize_one_coherent_job() {
        let event_log_path = unique_temp_path("controlled-concurrent-events.jsonl");
        let runtime = test_runtime(
            closed_upstream(),
            &event_log_path,
            unique_temp_path("controlled-concurrent-control.txt"),
            SurfaceAction::ProtectedUpstream,
        );
        let cookie = cookie_header();
        let session_id = session_id_from_cookie(&cookie).expect("cookie should contain session");
        set_runtime_policy_state(&runtime, &cookie, PolicyState::ControlledReality);
        let request = request_with_cookie("POST", "/api/v2/import/reconcile", &cookie, &[]);
        let first_runtime = runtime.clone();
        let second_runtime = runtime.clone();
        let first_request = request.clone();
        let first = thread::spawn(move || run_runtime_request(first_runtime, &first_request));
        let second = thread::spawn(move || run_runtime_request(second_runtime, &request));
        let first =
            parse_downstream_response(&first.join().expect("first controlled request should join"));
        let second = parse_downstream_response(
            &second
                .join()
                .expect("second controlled request should join"),
        );
        let first_json: Value =
            serde_json::from_slice(&first.body).expect("first response should be json");
        let second_json: Value =
            serde_json::from_slice(&second.body).expect("second response should be json");

        assert_eq!(first.status, 202);
        assert_eq!(second.status, 202);
        assert_eq!(first_json["job_id"], second_json["job_id"]);
        let interactions: Vec<Value> = events_of_type(&event_log_path, "response_served")
            .into_iter()
            .filter(|event| event["kind"]["controlled_reality"].is_object())
            .collect();
        assert_eq!(interactions.len(), 2);
        assert_eq!(
            interactions[0]["kind"]["controlled_reality"]["origin_request_id"],
            interactions[1]["kind"]["controlled_reality"]["origin_request_id"]
        );
        let record = runtime
            .policy_store
            .lock()
            .expect("policy store should lock")
            .record(session_id);
        assert_eq!(
            record.controlled_reality_workflow_state,
            ControlledRealityWorkflowState::Queued
        );
        assert_eq!(record.controlled_reality_depth, 2);
        assert_eq!(record.controlled_reality_pending_update, None);
    }

    #[test]
    fn failed_status_audit_restores_queued_state_before_retry() {
        let event_log_path = unique_temp_path("controlled-status-event-failure.jsonl");
        let mut runtime = test_runtime(
            closed_upstream(),
            &event_log_path,
            unique_temp_path("controlled-status-event-failure-control.txt"),
            SurfaceAction::ProtectedUpstream,
        );
        let cookie = cookie_header();
        let session_id = session_id_from_cookie(&cookie).expect("cookie should contain session");
        set_runtime_policy_state(&runtime, &cookie, PolicyState::ControlledReality);
        let submitted = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &request_with_cookie("POST", "/api/v2/import/reconcile", &cookie, &[]),
        ));
        let submitted_json: Value =
            serde_json::from_slice(&submitted.body).expect("submission should be json");
        let status_path = submitted_json["status_path"]
            .as_str()
            .expect("submission should return status path")
            .to_string();
        let event_log = Arc::clone(&runtime.event_log);
        assert!(thread::spawn(move || {
            let _guard = event_log.lock().expect("event log should lock");
            panic!("poison event log before status audit");
        })
        .join()
        .is_err());

        let (failed, failed_response) = run_runtime_request_result(
            runtime.clone(),
            &get_request_with_cookie(&status_path, &cookie),
        );

        assert!(failed.is_err());
        assert!(failed_response.is_empty());
        let pending = runtime
            .policy_store
            .lock()
            .expect("policy store should lock")
            .record(session_id);
        assert_eq!(
            pending.controlled_reality_workflow_state,
            ControlledRealityWorkflowState::Completed
        );
        let pending_update = pending
            .controlled_reality_pending_update
            .expect("failed status should remain pending");
        assert_eq!(
            pending_update.previous_state,
            ControlledRealityWorkflowState::Queued
        );
        assert_eq!(pending_update.previous_depth, 1);

        runtime.event_log = Arc::new(Mutex::new(
            FileEventLogWriter::open(&event_log_path).expect("replacement event log should reopen"),
        ));
        let retried = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &get_request_with_cookie(&status_path, &cookie),
        ));

        assert_eq!(retried.status, 200);
        let recovered = runtime
            .policy_store
            .lock()
            .expect("policy store should lock")
            .record(session_id);
        assert_eq!(
            recovered.controlled_reality_workflow_state,
            ControlledRealityWorkflowState::Completed
        );
        assert_eq!(recovered.controlled_reality_depth, 2);
        assert_eq!(recovered.controlled_reality_pending_update, None);
        let interactions: Vec<Value> = events_of_type(&event_log_path, "response_served")
            .into_iter()
            .filter(|event| event["kind"]["controlled_reality"].is_object())
            .collect();
        assert_eq!(interactions.len(), 2);
        assert_eq!(
            interactions[0]["kind"]["controlled_reality"]["kind"],
            "job_submitted"
        );
        assert_eq!(
            interactions[1]["kind"]["controlled_reality"]["kind"],
            "status_read"
        );
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
            blocked_change["persistence"]["post_containment_persistence_kind"],
            "controlled_reality_depth_limit"
        );

        let precommit_request = events_of_type(&event_log_path, "request_seen")
            .into_iter()
            .rfind(|event| event["kind"]["path"].as_str() == Some("/api/v2/import/reconcile"))
            .unwrap_or_else(|| panic!("pre-commit request_seen should exist"));
        assert_eq!(precommit_request["policy_state"], "controlled_reality");
        assert_eq!(
            precommit_request["kind"]["routing_decision"],
            "controlled_reality"
        );

        let blocked_response = events_of_type(&event_log_path, "response_served")
            .into_iter()
            .rfind(|event| event["policy_state"].as_str() == Some("blocked"))
            .unwrap_or_else(|| panic!("blocked response should exist"));
        assert_eq!(blocked_response["kind"]["status"], 403);
        assert_eq!(
            blocked_response["kind"]["routing_decision"],
            "eidolon_owned"
        );
        assert_eq!(
            precommit_request["request_id"],
            blocked_response["request_id"]
        );
        assert_eq!(blocked_change["request_id"], blocked_response["request_id"]);

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
            blocked_change["persistence"]["post_containment_persistence_kind"],
            "controlled_reality_branch_escape"
        );

        let precommit_request = events_of_type(&event_log_path, "request_seen")
            .into_iter()
            .rfind(|event| event["kind"]["path"].as_str() == Some("/api/v1/projects"))
            .unwrap_or_else(|| panic!("pre-commit request_seen should exist"));
        assert_eq!(precommit_request["policy_state"], "controlled_reality");
        assert_eq!(
            precommit_request["kind"]["routing_decision"],
            "controlled_reality"
        );

        let blocked_response = events_of_type(&event_log_path, "response_served")
            .into_iter()
            .rfind(|event| event["policy_state"].as_str() == Some("blocked"))
            .unwrap_or_else(|| panic!("blocked response should exist"));
        assert_eq!(blocked_response["kind"]["status"], 403);
        assert_eq!(
            blocked_response["kind"]["routing_decision"],
            "eidolon_owned"
        );
        assert_eq!(
            precommit_request["request_id"],
            blocked_response["request_id"]
        );
        assert_eq!(blocked_change["request_id"], blocked_response["request_id"]);

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
    fn runtime_policy_transition_immediately_protects_against_valid_cookie_swap() {
        let event_log_path = unique_temp_path("alternate-cookie-floor-events.jsonl");
        let debug_log_path = unique_temp_path("alternate-cookie-floor-debug.jsonl");
        let (upstream, recorder) =
            spawn_recording_upstream([html_response("<html><body>unexpected</body></html>")]);
        let mut runtime = test_runtime_with_m1_controller_and_debug_log(
            upstream,
            &event_log_path,
            &debug_log_path,
            unique_temp_path("alternate-cookie-floor-control.txt"),
        );
        runtime.ingress_transport_auth_secret = Some(Arc::from("edge-secret"));
        let continuity_headers = [
            (session::INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
            (
                session::INGRESS_CONTINUITY_HEADER_NAME,
                TEST_INGRESS_CONTINUITY_ID,
            ),
        ];
        let original_cookie = cookie_header();
        let original_session =
            session_id_from_cookie(&original_cookie).expect("original cookie should parse");
        set_runtime_policy_state(&runtime, &original_cookie, PolicyState::Suspicious);

        let exposure = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &request_with_cookie(
                "GET",
                "/docs/legacy-import",
                &original_cookie,
                &continuity_headers,
            ),
        ));
        let transition = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &request_with_cookie(
                "POST",
                "/api/v2/import/reconcile",
                &original_cookie,
                &[
                    continuity_headers[0],
                    continuity_headers[1],
                    ("X-Migration-Trace", "wrong"),
                ],
            ),
        ));
        let alternate_cookie = cookie_header();
        let alternate_session =
            session_id_from_cookie(&alternate_cookie).expect("alternate cookie should parse");
        let after_swap = parse_downstream_response(&run_runtime_request(
            runtime.clone(),
            &request_with_cookie(
                "GET",
                "/docs/legacy-import",
                &alternate_cookie,
                &continuity_headers,
            ),
        ));

        assert_eq!(exposure.status, 200);
        assert_eq!(transition.status, 429);
        assert_eq!(after_swap.status, 429);
        assert_eq!(
            policy_state_for_session(&runtime, original_session)
                .expect("original policy state should load"),
            PolicyState::RateLimited
        );
        assert_ne!(alternate_session, original_session);
        assert!(
            recorder.finish().is_empty(),
            "alternate valid cookie reached protected upstream"
        );
        let resolved = debug_events(&debug_log_path, "session_resolved")
            .into_iter()
            .last()
            .expect("cookie-swap session resolution should be logged");
        assert_eq!(
            resolved["fields"]["continuity_outcome"],
            "continuity_session_preserved"
        );
        assert_eq!(resolved["fields"]["enforcement_floor"], "rate_limited");
        assert_eq!(
            resolved["session_id"],
            original_session.0.to_string(),
            "stable continuity identity must win over the alternate cookie"
        );
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
            "/docs?<redacted>#<redacted>"
        );
        assert_eq!(
            redacted_event_target("/docs?flag&=secret"),
            "/docs?<redacted>"
        );
        assert_eq!(
            redacted_event_target("/docs?sk_live_secret"),
            "/docs?<redacted>"
        );
        assert_eq!(
            redacted_event_target("/docs?sk_live_secret=x"),
            "/docs?<redacted>"
        );
        assert_eq!(redacted_event_target("/docs?"), "/docs?<redacted>");
        assert_eq!(redacted_event_target("/docs"), "/docs");
    }

    #[test]
    fn rejected_bait_action_preserves_transition_persistence_metadata() {
        let transition_decision = policy::PolicyDecision::new(
            PolicyState::RateLimited,
            RoutingDecision::RateLimited,
            "suspicious write recon persistence moved session to rate limited",
        )
        .with_persistence(PersistenceMetadata::pre_containment(
            eidolon_core::PreContainmentPersistenceClass::WriteRecon,
        ));

        let intercepted =
            request_evaluation::bait_action_interception_decision(&transition_decision, false);

        assert_eq!(intercepted.policy_state, PolicyState::RateLimited);
        assert_eq!(intercepted.routing_decision, RoutingDecision::EidolonOwned);
        assert_eq!(intercepted.persistence, transition_decision.persistence);
        assert!(intercepted.reason.contains("rejected bait proof"));
    }

    #[test]
    fn control_file_values_disable_interventions() {
        assert!(intervention_control_disables("disabled"));
        assert!(intervention_control_disables("off\n"));
        assert!(intervention_control_disables("0"));
        assert!(!intervention_control_disables("enabled"));
    }
}
