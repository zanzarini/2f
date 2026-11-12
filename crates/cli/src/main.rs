//! `twof`: runs the server and administers it.
//!
//! Administration works directly on the database file. Whoever can run this
//! on the machine is the administrator; there is no admin API on the network.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use twof_core::keys::ServerKey;
use twof_core::ApproverKind;
use twof_server::http::now;
use twof_server::{Config, Service};

#[derive(Parser)]
#[command(
    name = "twof",
    version,
    about = "2F: second factor for API transactions"
)]
struct Cli {
    /// Database file.
    #[arg(long, env = "TWOF_DB", default_value = "twof.db", global = true)]
    db: PathBuf,
    /// File holding the server signing key. Keep it out of backups of the database.
    #[arg(long, env = "TWOF_KEY_FILE", default_value = "twof.key", global = true)]
    key_file: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create the database and the server signing key.
    Init,
    /// Run the HTTP API.
    Serve {
        #[arg(long, env = "TWOF_LISTEN", default_value = "127.0.0.1:8722")]
        listen: SocketAddr,
        /// Address approvers use to reach this server.
        #[arg(long, env = "TWOF_PUBLIC_URL", default_value = "http://localhost:8722")]
        public_url: String,
        /// Seconds approvers have to act.
        #[arg(long, default_value_t = 300)]
        challenge_ttl: u64,
        /// Seconds a receipt stays valid.
        #[arg(long, default_value_t = 300)]
        receipt_ttl: u64,
        /// Requests allowed per client address per minute (0 disables).
        #[arg(long, env = "TWOF_RATE_PER_MINUTE", default_value_t = 600)]
        rate_per_minute: u32,
        /// Read the client address from X-Forwarded-For. Only behind your own reverse proxy.
        #[arg(long, env = "TWOF_TRUST_PROXY")]
        trust_proxy: bool,
        /// Create the database (and the key, if none is configured) when missing.
        #[arg(long, env = "TWOF_AUTO_INIT")]
        auto_init: bool,
    },
    /// Print the server public key clients use to verify receipts.
    Pubkey,
    #[command(subcommand)]
    Project(ProjectCmd),
    #[command(subcommand)]
    Apikey(ApikeyCmd),
    #[command(subcommand)]
    Policy(PolicyCmd),
    #[command(subcommand)]
    Approver(ApproverCmd),
    #[command(subcommand)]
    Credential(CredentialCmd),
    #[command(subcommand)]
    Audit(AuditCmd),
    #[command(subcommand)]
    Device(DeviceCmd),
    /// Send signed event notifications of a project to a URL. Omit the URL to stop.
    Webhook {
        project: String,
        url: Option<String>,
    },
    /// Tell a Telegram chat about pending approvals. Omit the chat to stop.
    /// The bot token is read from TWOF_TELEGRAM_BOT_TOKEN by `serve`.
    Telegram {
        project: String,
        chat: Option<String>,
    },
    /// Run an independent co-signer. Use a different machine from the server.
    Cosign {
        /// The co-signer's own key, created with `twof device keygen`.
        #[arg(long)]
        device_key: PathBuf,
        /// Credential id printed by `twof credential add --cosigner`.
        #[arg(long)]
        credential: String,
        /// The co-signer's own policy file: allow signs, deny vetoes, require abstains.
        #[arg(long)]
        policy: PathBuf,
        /// Address of the 2F server.
        #[arg(long)]
        server_url: String,
        /// The 2F server public key (hex), as printed by `twof pubkey`.
        #[arg(long)]
        server_public_key: String,
        #[arg(long, default_value = "127.0.0.1:8723")]
        listen: SocketAddr,
    },
}

#[derive(Subcommand)]
enum ProjectCmd {
    Create { name: String },
    List,
}

#[derive(Subcommand)]
enum ApikeyCmd {
    /// Create an API key. It is printed once and cannot be recovered.
    Create {
        project: String,
        #[arg(long, default_value = "default")]
        label: String,
    },
    /// Revoke every API key of a project.
    RevokeAll { project: String },
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Replace the policy of a project with the contents of a JSON file.
    Set {
        project: String,
        file: PathBuf,
    },
    Show {
        project: String,
    },
}

#[derive(Subcommand)]
enum ApproverCmd {
    Add {
        project: String,
        /// Short identifier, for example "alice".
        id: String,
        #[arg(long)]
        name: Option<String>,
    },
}

#[derive(Subcommand)]
enum CredentialCmd {
    /// Enroll an Ed25519 public key for an approver.
    Add {
        project: String,
        approver: String,
        /// Public key in hex, as printed by `twof device keygen`.
        public_key: String,
        /// Enroll as an independent co-signer machine instead of a person's device.
        #[arg(long)]
        cosigner: bool,
    },
    Revoke {
        project: String,
        credential: String,
    },
    /// Print a one time link (valid 15 minutes) for an approver to register a passkey.
    Invite {
        project: String,
        approver: String,
        /// Address approvers use to reach this server.
        #[arg(long, env = "TWOF_PUBLIC_URL", default_value = "http://localhost:8722")]
        public_url: String,
    },
}

#[derive(Subcommand)]
enum AuditCmd {
    /// Check the whole audit log for tampering.
    Verify,
    /// Sign the current state of the log. Store the output somewhere else.
    Checkpoint,
}

#[derive(Subcommand)]
enum DeviceCmd {
    /// Create an approver device key and print its public key.
    Keygen { file: PathBuf },
    /// Sign a binding hash (base64url, from the approval view) with a device key.
    Sign { file: PathBuf, hash: String },
}

type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Writes a secret to a new file. Refuses to overwrite: replacing a key by
/// accident would invalidate everything signed with it.
fn write_secret(path: &Path, contents: &str) -> AnyResult<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    file.write_all(contents.as_bytes())?;
    Ok(())
}

/// The server key comes from TWOF_KEY (hex seed) when set, otherwise from the key file.
fn server_key(cli: &Cli) -> AnyResult<ServerKey> {
    match std::env::var("TWOF_KEY") {
        Ok(seed) if !seed.trim().is_empty() => {
            Ok(ServerKey::from_seed_hex(&seed).map_err(|_| "TWOF_KEY is not a valid key")?)
        }
        _ => read_key(&cli.key_file),
    }
}

fn read_key(path: &Path) -> AnyResult<ServerKey> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read key file {}: {e}", path.display()))?;
    Ok(ServerKey::from_seed_hex(&text)
        .map_err(|_| format!("{} is not a valid key file", path.display()))?)
}

fn open(cli: &Cli, config: Config) -> AnyResult<Service> {
    if !cli.db.exists() {
        return Err(format!("{} does not exist; run `twof init` first", cli.db.display()).into());
    }
    Ok(Service::open(&cli.db, server_key(cli)?, config)?)
}

fn run(cli: Cli) -> AnyResult<()> {
    match &cli.command {
        Command::Init => {
            if cli.db.exists() {
                return Err(format!("{} already exists", cli.db.display()).into());
            }
            let key = ServerKey::generate();
            write_secret(&cli.key_file, &key.seed_hex())?;
            let public = key.public_hex();
            Service::open(&cli.db, key, Config::default())?;
            println!("database:   {}", cli.db.display());
            println!(
                "key file:   {}  (secret, back it up separately)",
                cli.key_file.display()
            );
            println!("public key: {public}");
        }
        Command::Serve {
            listen,
            public_url,
            challenge_ttl,
            receipt_ttl,
            rate_per_minute,
            trust_proxy,
            auto_init,
        } => {
            let config = Config {
                challenge_ttl: *challenge_ttl,
                receipt_ttl: *receipt_ttl,
                public_url: public_url.clone(),
                rate_per_minute: *rate_per_minute,
                trust_proxy: *trust_proxy,
            };
            if *auto_init && !cli.db.exists() {
                let from_env = std::env::var("TWOF_KEY").is_ok_and(|k| !k.trim().is_empty());
                if !from_env && !cli.key_file.exists() {
                    write_secret(&cli.key_file, &ServerKey::generate().seed_hex())?;
                }
                Service::open(&cli.db, server_key(&cli)?, Config::default())?;
                println!("created {}", cli.db.display());
            }
            let service = Arc::new(open(&cli, config)?);
            if !listen.ip().is_loopback() {
                eprintln!(
                    "warning: listening on {listen} without TLS; put an HTTPS proxy in front"
                );
            }
            let telegram = std::env::var("TWOF_TELEGRAM_BOT_TOKEN")
                .ok()
                .filter(|t| !t.is_empty());
            twof_server::delivery::spawn(service.clone(), telegram);
            println!("2F listening on http://{listen}");
            tokio::runtime::Runtime::new()?.block_on(twof_server::http::serve(service, *listen))?;
        }
        Command::Webhook { project, url } => {
            open(&cli, Config::default())?.set_webhook(project, url.as_deref(), now())?;
            println!("webhook {}", if url.is_some() { "set" } else { "removed" });
        }
        Command::Telegram { project, chat } => {
            open(&cli, Config::default())?.set_telegram(project, chat.as_deref(), now())?;
            println!(
                "telegram {}",
                if chat.is_some() { "set" } else { "removed" }
            );
        }
        Command::Cosign {
            device_key,
            credential,
            policy,
            server_url,
            server_public_key,
            listen,
        } => {
            let text = std::fs::read_to_string(policy)
                .map_err(|e| format!("cannot read {}: {e}", policy.display()))?;
            let cosigner = Arc::new(twof_server::cosigner::Cosigner {
                key: read_key(device_key)?,
                credential: credential.clone(),
                policy: twof_core::Policy::parse(&text)?,
                server_url: server_url.clone(),
                server_key: twof_core::keys::public_from_hex(server_public_key)
                    .map_err(|_| "server public key must be 32 bytes of hex")?,
            });
            println!("2F co-signer listening on http://{listen}/webhook");
            tokio::runtime::Runtime::new()?
                .block_on(twof_server::cosigner::serve(cosigner, *listen))?;
        }
        Command::Pubkey => {
            let key = server_key(&cli)?;
            println!("kid:        {}", key.kid());
            println!("public key: {}", key.public_hex());
        }
        Command::Project(ProjectCmd::Create { name }) => {
            println!(
                "{}",
                open(&cli, Config::default())?.create_project(name, now())?
            );
        }
        Command::Project(ProjectCmd::List) => {
            for (id, name) in open(&cli, Config::default())?.list_projects()? {
                println!("{id}  {name}");
            }
        }
        Command::Apikey(ApikeyCmd::Create { project, label }) => {
            let token = open(&cli, Config::default())?.create_api_key(project, label, now())?;
            println!("{token}");
            eprintln!("store it now: it is not saved anywhere and cannot be shown again");
        }
        Command::Apikey(ApikeyCmd::RevokeAll { project }) => {
            let n = open(&cli, Config::default())?.revoke_api_keys(project, now())?;
            println!("revoked {n} key(s)");
        }
        Command::Policy(PolicyCmd::Set { project, file }) => {
            let text = std::fs::read_to_string(file)
                .map_err(|e| format!("cannot read {}: {e}", file.display()))?;
            open(&cli, Config::default())?.set_policy(project, &text, now())?;
            println!("policy updated");
        }
        Command::Policy(PolicyCmd::Show { project }) => {
            println!("{}", open(&cli, Config::default())?.get_policy(project)?);
        }
        Command::Approver(ApproverCmd::Add { project, id, name }) => {
            let name = name.as_deref().unwrap_or(id);
            open(&cli, Config::default())?.add_approver(project, id, name, now())?;
            println!("approver {id} added");
        }
        Command::Credential(CredentialCmd::Add {
            project,
            approver,
            public_key,
            cosigner,
        }) => {
            let kind = if *cosigner {
                ApproverKind::Cosigner
            } else {
                ApproverKind::Ed25519
            };
            let id = open(&cli, Config::default())?.add_credential(
                project,
                approver,
                kind,
                public_key,
                now(),
            )?;
            println!("{id}");
        }
        Command::Credential(CredentialCmd::Revoke {
            project,
            credential,
        }) => {
            open(&cli, Config::default())?.revoke_credential(project, credential, now())?;
            println!("credential revoked");
        }
        Command::Credential(CredentialCmd::Invite {
            project,
            approver,
            public_url,
        }) => {
            let config = Config {
                public_url: public_url.clone(),
                ..Config::default()
            };
            let service = open(&cli, config)?;
            let token = service.create_enrollment(project, approver, now())?;
            println!("{}", service.enrollment_url(&token));
        }
        Command::Audit(AuditCmd::Verify) => match open(&cli, Config::default())?.audit_verify()? {
            Some((seq, hash)) => println!("audit log intact: {seq} entries, head {hash}"),
            None => println!("audit log is empty"),
        },
        Command::Audit(AuditCmd::Checkpoint) => {
            match open(&cli, Config::default())?.checkpoint(now())? {
                Some(c) => println!(
                    "{{\"seq\":{},\"hash\":\"{}\",\"ts\":{},\"kid\":\"{}\",\"sig\":\"{}\"}}",
                    c.seq, c.hash, c.ts, c.kid, c.sig
                ),
                None => println!("audit log is empty"),
            }
        }
        Command::Device(DeviceCmd::Keygen { file }) => {
            let key = ServerKey::generate();
            write_secret(file, &key.seed_hex())?;
            println!("{}", key.public_hex());
        }
        Command::Device(DeviceCmd::Sign { file, hash }) => {
            let bytes = B64
                .decode(hash.trim())
                .map_err(|_| "hash must be base64url")?;
            if bytes.len() != 32 {
                return Err("hash must be 32 bytes".into());
            }
            println!("{}", B64.encode(read_key(file)?.sign(&bytes)));
        }
    }
    Ok(())
}
