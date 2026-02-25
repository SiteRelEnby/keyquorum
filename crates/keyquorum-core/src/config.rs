use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub daemon: DaemonConfig,
    pub session: SessionConfig,
    pub action: ActionConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DaemonConfig {
    #[serde(default = "default_socket_path")]
    pub socket_path: PathBuf,
    pub tcp_port: Option<u16>,
    pub pid_file: Option<PathBuf>,
    #[serde(default)]
    pub lockdown: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SessionConfig {
    pub threshold: u8,
    pub total_shares: u8,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub on_failure: OnFailure,
    #[serde(default = "default_max_retries")]
    pub max_retries: u8,
}

/// What to do when reconstruction fails after reaching quorum.
#[derive(Debug, Default, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OnFailure {
    /// Immediately wipe all shares and reset (default).
    #[default]
    Wipe,
    /// Keep shares, return to Collecting, accept more and retry.
    Retry,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum ActionConfig {
    #[serde(rename = "luks")]
    Luks { device: String, name: String },
    #[serde(rename = "stdout")]
    Stdout,
    #[serde(rename = "command")]
    Command {
        program: String,
        #[serde(default)]
        args: Vec<String>,
    },
}

#[derive(Debug, Deserialize, Clone)]
pub struct LoggingConfig {
    #[serde(default)]
    pub log_participation: bool,
    #[serde(default = "default_log_level")]
    pub level: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            log_participation: false,
            level: default_log_level(),
        }
    }
}

fn default_socket_path() -> PathBuf {
    PathBuf::from("/run/keyquorum/keyquorum.sock")
}

fn default_timeout() -> u64 {
    1800
}

fn default_max_retries() -> u8 {
    3
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Config {
    pub fn from_file(
        path: &std::path::Path,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let contents = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        config.validate()?;
        Ok(config)
    }

    pub fn parse(s: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let config: Config = toml::from_str(s)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.session.threshold < 2 {
            return Err("threshold must be at least 2".into());
        }
        if self.session.threshold > self.session.total_shares {
            return Err("threshold must be <= total_shares".into());
        }
        if self.session.timeout_secs == 0 {
            return Err("timeout_secs must be > 0".into());
        }
        if self.session.on_failure == OnFailure::Retry && self.session.max_retries == 0 {
            return Err("max_retries must be > 0 when on_failure is retry".into());
        }
        Ok(())
    }

    /// Apply lockdown mode overrides. Call after loading config,
    /// passing true if CLI --lockdown flag was set.
    pub fn apply_lockdown(&mut self, cli_lockdown: bool) {
        if !cli_lockdown && !self.daemon.lockdown {
            return;
        }
        self.daemon.lockdown = true;
        self.session.on_failure = OnFailure::Wipe;
    }

    /// Validate lockdown mode constraints. Returns Err if lockdown is enabled
    /// but the config uses options that lockdown forbids.
    pub fn validate_lockdown(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.daemon.lockdown {
            return Ok(());
        }
        if matches!(self.action, ActionConfig::Stdout) {
            return Err(
                "lockdown mode rejects action type 'stdout': secrets must not be written to stdout"
                    .into(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_luks_config() {
        let toml = r#"
[daemon]
socket_path = "/tmp/test.sock"
tcp_port = 35000

[session]
threshold = 3
total_shares = 5
timeout_secs = 600

[action]
type = "luks"
device = "/dev/sda2"
name = "cryptdata"

[logging]
log_participation = true
level = "debug"
"#;
        let config = Config::parse(toml).unwrap();
        assert_eq!(config.session.threshold, 3);
        assert_eq!(config.session.total_shares, 5);
        assert_eq!(config.session.timeout_secs, 600);
        assert!(matches!(config.action, ActionConfig::Luks { .. }));
        assert!(config.logging.log_participation);
        assert_eq!(config.daemon.tcp_port, Some(35000));
    }

    #[test]
    fn parse_stdout_config() {
        let toml = r#"
[daemon]

[session]
threshold = 2
total_shares = 3

[action]
type = "stdout"
"#;
        let config = Config::parse(toml).unwrap();
        assert!(matches!(config.action, ActionConfig::Stdout));
        assert_eq!(config.session.timeout_secs, 1800); // default
        assert!(!config.logging.log_participation); // default
    }

    #[test]
    fn parse_command_config() {
        let toml = r#"
[daemon]

[session]
threshold = 2
total_shares = 4

[action]
type = "command"
program = "/usr/local/bin/unseal"
args = ["--cluster", "prod"]
"#;
        let config = Config::parse(toml).unwrap();
        if let ActionConfig::Command { program, args } = &config.action {
            assert_eq!(program, "/usr/local/bin/unseal");
            assert_eq!(args, &["--cluster", "prod"]);
        } else {
            panic!("expected Command action");
        }
    }

    #[test]
    fn reject_threshold_below_2() {
        let toml = r#"
[daemon]
[session]
threshold = 1
total_shares = 3
[action]
type = "stdout"
"#;
        assert!(Config::parse(toml).is_err());
    }

    #[test]
    fn reject_threshold_above_total() {
        let toml = r#"
[daemon]
[session]
threshold = 5
total_shares = 3
[action]
type = "stdout"
"#;
        assert!(Config::parse(toml).is_err());
    }

    #[test]
    fn parse_retry_config() {
        let toml = r#"
[daemon]
[session]
threshold = 3
total_shares = 5
on_failure = "retry"
max_retries = 5
[action]
type = "stdout"
"#;
        let config = Config::parse(toml).unwrap();
        assert_eq!(config.session.on_failure, OnFailure::Retry);
        assert_eq!(config.session.max_retries, 5);
    }

    #[test]
    fn on_failure_defaults_to_wipe() {
        let toml = r#"
[daemon]
[session]
threshold = 2
total_shares = 3
[action]
type = "stdout"
"#;
        let config = Config::parse(toml).unwrap();
        assert_eq!(config.session.on_failure, OnFailure::Wipe);
        assert_eq!(config.session.max_retries, 3);
    }

    #[test]
    fn reject_retry_with_zero_max_retries() {
        let toml = r#"
[daemon]
[session]
threshold = 2
total_shares = 3
on_failure = "retry"
max_retries = 0
[action]
type = "stdout"
"#;
        assert!(Config::parse(toml).is_err());
    }

    #[test]
    fn lockdown_rejects_stdout_action() {
        let toml = r#"
[daemon]
lockdown = true
[session]
threshold = 2
total_shares = 3
[action]
type = "stdout"
"#;
        let mut config = Config::parse(toml).unwrap();
        config.apply_lockdown(false);
        assert!(config.validate_lockdown().is_err());
    }

    #[test]
    fn lockdown_allows_luks_action() {
        let toml = r#"
[daemon]
lockdown = true
[session]
threshold = 2
total_shares = 3
[action]
type = "luks"
device = "/dev/sda2"
name = "cryptdata"
"#;
        let mut config = Config::parse(toml).unwrap();
        config.apply_lockdown(false);
        assert!(config.validate_lockdown().is_ok());
    }

    #[test]
    fn lockdown_overrides_retry_to_wipe() {
        let toml = r#"
[daemon]
lockdown = true
[session]
threshold = 2
total_shares = 3
on_failure = "retry"
[action]
type = "luks"
device = "/dev/sda2"
name = "cryptdata"
"#;
        let mut config = Config::parse(toml).unwrap();
        assert_eq!(config.session.on_failure, OnFailure::Retry);
        config.apply_lockdown(false);
        assert_eq!(config.session.on_failure, OnFailure::Wipe);
    }

    #[test]
    fn cli_lockdown_overrides_config() {
        let toml = r#"
[daemon]
[session]
threshold = 2
total_shares = 3
on_failure = "retry"
[action]
type = "luks"
device = "/dev/sda2"
name = "cryptdata"
"#;
        let mut config = Config::parse(toml).unwrap();
        assert_eq!(config.session.on_failure, OnFailure::Retry);
        assert!(!config.daemon.lockdown);
        config.apply_lockdown(true); // CLI flag
        assert_eq!(config.session.on_failure, OnFailure::Wipe);
        assert!(config.daemon.lockdown);
    }

    #[test]
    fn non_lockdown_does_not_override() {
        let toml = r#"
[daemon]
[session]
threshold = 2
total_shares = 3
on_failure = "retry"
[action]
type = "stdout"
"#;
        let mut config = Config::parse(toml).unwrap();
        config.apply_lockdown(false);
        assert_eq!(config.session.on_failure, OnFailure::Retry);
        assert!(config.validate_lockdown().is_ok());
    }
}
