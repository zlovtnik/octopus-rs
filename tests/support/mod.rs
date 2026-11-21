//! Canonical schema-executor fixture shared by native integration suites.
#![allow(dead_code)]

use octopus::{config::PostgresConfig, postgres::PgRuntime};
use std::{
    path::PathBuf,
    process::{Command, Output},
    sync::Arc,
    time::Duration,
};

const IMAGE:&str="pgvector/pgvector:0.8.6-pg16-bookworm@sha256:ccc6e83d6e35e931dc7c5def2022729d5a6c370318d099181995567ff1fb4d6b";

pub fn checked(command: &mut Command) -> Output {
    let output = command.output().expect("test fixture command must start");
    assert!(
        output.status.success(),
        "test fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

pub struct Fixture {
    pub name: String,
    network: String,
    directory: tempfile::TempDir,
    pub runtime: Arc<PgRuntime>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.runtime.close();
        let _ = Command::new("docker")
            .args(["rm", "-f", "-v", &self.name])
            .output();
        let _ = Command::new("docker")
            .args(["network", "rm", &self.network])
            .output();
    }
}

impl Fixture {
    pub async fn start() -> Option<Self> {
        if !Command::new("docker")
            .arg("info")
            .output()
            .is_ok_and(|out| out.status.success())
        {
            assert_ne!(
                std::env::var("OCTOPUS_REQUIRE_DOCKER").as_deref(),
                Ok("true"),
                "required Docker is unavailable"
            );
            eprintln!("Docker unavailable; canonical PostgreSQL integration was not exercised");
            return None;
        }
        let name = format!("native-runtime-{}", uuid::Uuid::new_v4());
        let network = format!("{name}-net");
        let directory = tempfile::tempdir().unwrap();
        checked(Command::new("docker").args(["network", "create", &network]));
        // The cleanup guard exists before connectivity/provisioning assertions.
        struct Cleanup {
            name: String,
            network: String,
            armed: bool,
        }
        impl Drop for Cleanup {
            fn drop(&mut self) {
                if self.armed {
                    let _ = Command::new("docker")
                        .args(["rm", "-f", "-v", &self.name])
                        .output();
                    let _ = Command::new("docker")
                        .args(["network", "rm", &self.network])
                        .output();
                }
            }
        }
        let mut cleanup = Cleanup {
            name: name.clone(),
            network: network.clone(),
            armed: true,
        };
        checked(Command::new("docker").args([
            "run",
            "-d",
            "--name",
            &name,
            "--network",
            &network,
            "-e",
            "POSTGRES_PASSWORD=integration-admin",
            "-e",
            "POSTGRES_DB=sync",
            "-p",
            "127.0.0.1::5432",
            IMAGE,
        ]));
        let mut ready = false;
        for _ in 0..120 {
            if Command::new("docker")
                .args([
                    "exec",
                    &name,
                    "pg_isready",
                    "-h",
                    "127.0.0.1",
                    "-U",
                    "postgres",
                    "-d",
                    "sync",
                ])
                .output()
                .is_ok_and(|out| out.status.success())
            {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        assert!(ready, "scratch database did not start");
        let admin = |sql: &str| {
            checked(Command::new("docker").args([
                "exec",
                &name,
                "psql",
                "-U",
                "postgres",
                "-d",
                "sync",
                "--set=ON_ERROR_STOP=1",
                "--command",
                sql,
            ]));
        };
        admin("CREATE EXTENSION pgcrypto; CREATE EXTENSION vector; CREATE EXTENSION pg_stat_statements; CREATE ROLE schema_owner LOGIN PASSWORD 'integration-schema-owner'; CREATE ROLE octopus_runtime LOGIN PASSWORD 'integration-runtime'; CREATE ROLE atheros_search_runtime LOGIN; CREATE ROLE schema_migrator_runtime LOGIN; CREATE ROLE keycloak_runtime LOGIN; GRANT CREATE ON DATABASE sync TO schema_owner;");
        admin("ALTER ROLE octopus_runtime IN DATABASE sync SET search_path TO octopus_core, atheros_search; ALTER ROLE atheros_search_runtime IN DATABASE sync SET search_path TO atheros_search; ALTER ROLE schema_migrator_runtime IN DATABASE sync SET search_path TO schema_migrator; ALTER ROLE keycloak_runtime IN DATABASE sync SET search_path TO keycloak;");
        provision(&name, &network, &directory);
        let output = checked(Command::new("docker").args(["port", &name, "5432/tcp"]));
        let port = String::from_utf8(output.stdout)
            .unwrap()
            .trim()
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let root = repository_root();
        let manifest =
            std::fs::read_to_string(root.join("sql/postgres/octopus_core/manifest.yaml")).unwrap();
        let checksum = manifest
            .lines()
            .find_map(|line| line.strip_prefix("manifest_sha256: "))
            .unwrap()
            .to_string();
        let cfg = PostgresConfig {
            enabled: true,
            host: "127.0.0.1".into(),
            port,
            user: "octopus_runtime".into(),
            password: "integration-runtime".into(),
            database: "sync".into(),
            ssl_mode: "disable".into(),
            manifest_sha256: checksum,
            pool_size: 6,
            healthcheck_reserve: 1,
            ..PostgresConfig::default()
        };
        let runtime = Arc::new(
            PgRuntime::connect(&cfg)
                .await
                .expect("canonical executor must satisfy native preflight"),
        );
        cleanup.armed = false;
        Some(Self {
            name,
            network,
            directory,
            runtime,
        })
    }
    pub fn admin(&self, sql: &str) -> Output {
        checked(Command::new("docker").args([
            "exec",
            &self.name,
            "psql",
            "-U",
            "postgres",
            "-d",
            "sync",
            "--set=ON_ERROR_STOP=1",
            "--command",
            sql,
        ]))
    }
    pub fn directory(&self) -> &std::path::Path {
        self.directory.path()
    }
}

pub fn repository_root() -> PathBuf {
    if let Some(root) = std::env::var_os("OCTOPUS_TEST_ROOT") {
        return PathBuf::from(root);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn provision(name: &str, network: &str, directory: &tempfile::TempDir) {
    use std::os::unix::fs::PermissionsExt;
    let root = repository_root();
    let path = directory.path();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let bin = path.join("bin");
    std::fs::create_dir(&bin).unwrap();
    let wrapper = bin.join("psql");
    std::fs::write(
        &wrapper,
        "#!/bin/sh\nPGSSLMODE=disable exec /usr/bin/psql \"$@\"\n",
    )
    .unwrap();
    std::fs::set_permissions(wrapper, std::fs::Permissions::from_mode(0o555)).unwrap();
    let ca = path.join("ca.crt");
    std::fs::write(&ca, "integration-test-placeholder\n").unwrap();
    std::fs::set_permissions(ca, std::fs::Permissions::from_mode(0o444)).unwrap();
    // The Docker daemon may be outside the test runner's mount namespace.
    // Send just the executor inputs over stdin, never daemon-host bind paths.
    let archive = path.join("schema.tar");
    checked(
        Command::new("tar")
            .arg("-cf")
            .arg(&archive)
            .arg("-C")
            .arg(&root)
            .args(["sql/postgres", "k8s/postgres-schema-executor/entrypoint.sh"])
            .arg("-C")
            .arg(path)
            .args(["bin/psql", "ca.crt"]),
    );
    let mut command = Command::new("docker");
    command.args([
        "run",
        "-i",
        "--rm",
        "--network",
        network,
        "--user",
        "65532:65532",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=67108864",
    ]);
    for (key, value) in [
        (
            "PATH",
            "/workspace/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        ),
        ("POSTGRES_HOST", name),
        ("POSTGRES_PORT", "5432"),
        ("POSTGRES_DATABASE", "sync"),
        ("POSTGRES_SCHEMA_OWNER_USER", "schema_owner"),
        ("POSTGRES_SCHEMA_OWNER_PASSWORD", "integration-schema-owner"),
        ("POSTGRES_OCTOPUS_ACCOUNT", "octopus_runtime"),
        ("POSTGRES_ATHEROS_SEARCH_ACCOUNT", "atheros_search_runtime"),
        (
            "POSTGRES_SCHEMA_MIGRATOR_ACCOUNT",
            "schema_migrator_runtime",
        ),
        ("POSTGRES_KEYCLOAK_ACCOUNT", "keycloak_runtime"),
        ("PGSSLMODE", "verify-full"),
        ("POSTGRES_SSL_SERVER_NAME", name),
        ("PGSSLROOTCERT", "/workspace/ca.crt"),
    ] {
        command.args(["--env", &format!("{key}={value}")]);
    }
    command.args([
        "--tmpfs",
        "/workspace:rw,exec,nosuid,uid=65532,gid=65532,size=67108864",
        "--entrypoint",
        "/bin/sh",
        IMAGE,
        "-ec",
        "cd /workspace && tar --no-same-owner -xf - && exec sh k8s/postgres-schema-executor/entrypoint.sh",
    ]);
    command.stdin(std::fs::File::open(archive).unwrap());
    checked(&mut command);
}
