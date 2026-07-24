use std::{
    env, fs,
    io::Read,
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use eidolon_core::{ControlledRealityWorkflowState, RequestId};
use eidolon_proxy::{
    controlled_reality::ControlledRealityRequestKind,
    controlled_reality_backend::{
        current_unix_secs, read_render_response, verify_render_response, write_render_request,
        ControlledRealityBackendAuthSecret, SignedControlledRealityRenderRequest,
    },
    policy_store::ControlledRealityProgress,
};

const TEST_SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";
const TEST_SECRET_HEX: &str = "3031323334353637383961626364656630313233343536373839616263646566";

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct SecretFile(PathBuf);

impl Drop for SecretFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[test]
fn packaged_binary_serves_an_authenticated_round_trip() {
    let secret_path = SecretFile(unique_temp_path());
    fs::write(&secret_path.0, format!("{TEST_SECRET_HEX}\n")).expect("secret fixture should write");
    let probe = TcpListener::bind("127.0.0.1:0").expect("port probe should bind");
    let address = probe.local_addr().expect("probe address should exist");
    drop(probe);

    let child = Command::new(env!("CARGO_BIN_EXE_eidolon-controlled-reality"))
        .args([
            "--auth-secret-file",
            &secret_path.0.to_string_lossy(),
            "--listen-addr",
            &address.to_string(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("packaged binary should start");
    let mut child = ChildGuard(child);
    wait_until_listening(&mut child.0, address);

    let now = current_unix_secs().expect("clock should be available");
    let secret = ControlledRealityBackendAuthSecret::new(TEST_SECRET.to_vec())
        .expect("test secret should be accepted");
    let request = SignedControlledRealityRenderRequest::new(
        &secret,
        RequestId::new(),
        now,
        ControlledRealityRequestKind::BranchRead,
        ControlledRealityProgress {
            depth: 0,
            from_state: ControlledRealityWorkflowState::Ready,
            to_state: ControlledRealityWorkflowState::Ready,
            origin_request_id: None,
        },
        None,
    )
    .expect("request should sign");
    let mut stream = TcpStream::connect(address).expect("client should connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("read deadline should set");
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .expect("write deadline should set");
    write_render_request(&mut stream, &request).expect("request should write");
    stream
        .shutdown(Shutdown::Write)
        .expect("request side should close");
    let response = read_render_response(&mut stream).expect("response should parse");
    let verified =
        verify_render_response(&secret, &response, &request, now).expect("response should verify");

    assert_eq!(verified.status, 200);
    assert_eq!(
        String::from_utf8(verified.body).expect("response should be UTF-8"),
        r#"{"action_depth":0,"path":"/api/v2/import/reconcile","status":"ready","synthetic":true,"write_committed":false}"#
    );
}

fn unique_temp_path() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be available")
        .as_nanos();
    env::temp_dir().join(format!(
        "eidolon-controlled-reality-integration-secret-{}-{nanos}",
        std::process::id()
    ))
}

fn wait_until_listening(child: &mut Child, address: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("child status should be readable") {
            panic!("packaged binary exited before listening: {status}");
        }
        match TcpStream::connect_timeout(&address, Duration::from_millis(50)) {
            Ok(mut stream) => {
                let _ = stream.shutdown(Shutdown::Write);
                let mut ignored = Vec::new();
                let _ = stream.read_to_end(&mut ignored);
                return;
            }
            Err(_) => thread::sleep(Duration::from_millis(20)),
        }
    }
    panic!("packaged binary did not start before deadline");
}
