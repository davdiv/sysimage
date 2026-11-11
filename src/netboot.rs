//! Network boot server: proxy DHCP + TFTP + HTTP, serving built artifacts
//! from a manifest.
//!
//! `sysimage netboot` resolves a manifest (through the config, like `install`)
//! and starts any of the three servers configured in the manifest's optional
//! `netboot` section (each is independently optional). TFTP and HTTP serve the
//! content-addressed `.bin` files referenced by the manifest; the DHCP server
//! operates as a **PXE proxy DHCP** — it does not assign IP addresses (another
//! DHCP server on the network handles that) but only provides netboot-related
//! options so PXE/UEFI/Raspberry Pi clients can discover where to download boot
//! files. The servers run until the process is interrupted (Ctrl-C).
//!
//! All three servers are implemented in pure Rust over `std::net` — no external
//! DHCP/TFTP/HTTP crate or subprocess is used.
//!
//! # `${NETBOOT_IP}` and interface binding
//!
//! The manifest must not contain a literal IP address; anything that depends
//! on the running host's address uses the `${NETBOOT_IP}` variable, resolved
//! here from the network interface the server is bound to. The IP is chosen
//! from, in priority order:
//!
//! 1. `--bind-ip <ip>` — an explicit IPv4 passed on the command line;
//! 2. `--interface <name>` — the first non-loopback IPv4 of that interface
//!    (enumerated via the `if-addrs` crate);
//! 3. otherwise — the default-route source IPv4 (auto-detected by connecting a
//!    UDP socket to a public address and reading the kernel-chosen local
//!    address; no packets are actually sent).
//!
//! After the IP is known, `${NETBOOT_IP}` is substituted throughout the
//! `netboot` section (DHCP options, `siaddr`, `bootFile`, `listen`, …) before
//! the sockets are bound.
//!
//! The DHCP server binds to `0.0.0.0:67` (INADDR_ANY) by default so it receives
//! broadcast DHCPDISCOVER/REQUEST packets from PXE clients — a socket bound to
//! a specific unicast IP would miss those broadcasts. TFTP and HTTP bind to
//! the resolved `${NETBOOT_IP}` since clients reach them via unicast after
//! learning the server address from DHCP options. An explicit `listen:
//! "host:port"` in the config is always honored as-is for any server.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::manifest::ManifestWithDirectory;
use crate::model::netboot::{
    ConfigNetboot, ConfigNetbootDhcp, ConfigNetbootDhcpProfile, DhcpOptionValue,
};
use crate::variables::replace_vars;

/// Options for `sysimage netboot`.
pub struct NetbootConfig {
    /// The resolved manifest (with its directory and `file` map).
    pub manifest: ManifestWithDirectory,
    /// Explicit IPv4 to use as `${NETBOOT_IP}` and the default bind address.
    pub bind_ip: Option<String>,
    /// Network interface name whose IPv4 is used as `${NETBOOT_IP}`.
    pub interface: Option<String>,
}

/// Run the network-boot servers from a manifest's `netboot` section until
/// interrupted.
pub fn run_netboot(opts: NetbootConfig) -> Result<()> {
    let manifest = opts.manifest;
    let netboot = manifest.manifest.netboot.clone().ok_or_else(|| {
        Error::msg("Manifest has no netboot section; add a `netboot` entry to the config")
    })?;

    // Resolve the server IP and build the runtime variable environment. Only
    // `NETBOOT_IP` is exposed for now.
    let ip = resolve_netboot_ip(opts.interface.as_deref(), opts.bind_ip.as_deref())?;
    let get_var = |name: &str| -> Option<String> {
        if name == "NETBOOT_IP" {
            Some(ip.to_string())
        } else {
            None
        }
    };

    // Substitute ${NETBOOT_IP} everywhere in the netboot section (DHCP options
    // values, siaddr, bootFile, listen, …) by round-tripping through JSON so
    // the typed DhcpOptionValue structure is preserved.
    let mut value = serde_json::to_value(&netboot)
        .map_err(|e| Error::msg(format!("serialize netboot section: {e}")))?;
    value = replace_vars(&value, &get_var)?;
    let netboot: ConfigNetboot = serde_json::from_value(value).map_err(|e| {
        Error::msg(format!(
            "deserialize netboot section after substitution: {e}"
        ))
    })?;

    // Validate that every TFTP/HTTP file referenced by the netboot section is
    // present in the manifest's `file` map and exists on disk.
    let file_dir = manifest.manifest_directory.clone();
    validate_netboot_files(&netboot, &manifest.manifest.file, &file_dir)?;

    let running = Arc::new(AtomicBool::new(true));
    let mut handles = Vec::new();
    let mut started = Vec::new();

    // DHCP server (proxy mode — no lease management). Bind to INADDR_ANY so
    // broadcast DHCPDISCOVER/REQUEST packets from PXE clients are received; a
    // socket bound to a specific unicast IP would miss those broadcasts.
    if let Some(dhcp) = netboot.dhcp.as_ref() {
        let listen = resolve_listen(dhcp.listen.as_deref(), ip, 67, true)?;
        let dhcp_sock = UdpSocket::bind(&listen)
            .map_err(|e| Error::msg(format!("Failed to bind DHCP server to {listen}: {e}")))?;
        dhcp_sock
            .set_broadcast(true)
            .map_err(|e| Error::msg(format!("set_broadcast failed: {e}")))?;
        // PXE Boot Server port (4011). After the initial DORA, EDK2's PXE
        // client unicasts a DHCPDISCOVER to the proxy server's siaddr on port
        // 4011 (PXEBC_BS_DISCOVER_PORT) to retrieve the bootfile name (the
        // "BINL retry"). If we don't listen on 4011 the retry times out and
        // PXE boot silently fails with no TFTP. Replies go to the client's
        // source address (unicast), not the broadcast.
        let pxe_listen = resolve_listen(dhcp.listen.as_deref(), ip, 4011, false)?;
        let pxe_sock = UdpSocket::bind(&pxe_listen);
        let dhcp_owned = dhcp.clone();
        let running_dhcp = running.clone();
        handles.push(thread::spawn(move || {
            if let Err(e) = run_dhcp_server(dhcp_sock, &dhcp_owned, ip, running_dhcp.clone(), false)
            {
                eprintln!("dhcp server error: {e}");
                running_dhcp.store(false, Ordering::SeqCst);
            }
        }));
        started.push(format!("dhcp={listen}"));

        match pxe_sock {
            Ok(pxe_sock) => {
                let dhcp_pxe = dhcp.clone();
                let running_pxe = running.clone();
                handles.push(thread::spawn(move || {
                    if let Err(e) =
                        run_dhcp_server(pxe_sock, &dhcp_pxe, ip, running_pxe.clone(), true)
                    {
                        eprintln!("dhcp/pxe-bs error: {e}");
                        running_pxe.store(false, Ordering::SeqCst);
                    }
                }));
                started.push(format!("dhcp-pxe-bs={pxe_listen}"));
            }
            Err(e) => {
                eprintln!(
                    "warning: failed to bind PXE boot server port {pxe_listen}: {e} \
                     — PXE BINL retry will not be served"
                );
            }
        }
    }
    // TFTP server.
    if let Some(tftp) = netboot.tftp.as_ref() {
        let listen = resolve_listen(tftp.listen.as_deref(), ip, 69, false)?;
        let tftp_sock = UdpSocket::bind(&listen)
            .map_err(|e| Error::msg(format!("Failed to bind TFTP server to {listen}: {e}")))?;
        let tftp = tftp.clone();
        let file_dir = file_dir.clone();
        let running = running.clone();
        handles.push(thread::spawn(move || {
            if let Err(e) = run_tftp_server(tftp_sock, &tftp, &file_dir, running.clone()) {
                eprintln!("tftp server error: {e}");
                running.store(false, Ordering::SeqCst);
            }
        }));
        started.push(format!("tftp={listen}"));
    }
    // HTTP server.
    if let Some(http) = netboot.http.as_ref() {
        let listen = resolve_listen(http.listen.as_deref(), ip, 80, false)?;
        let http_listener = TcpListener::bind(&listen)
            .map_err(|e| Error::msg(format!("Failed to bind HTTP server to {listen}: {e}")))?;
        http_listener
            .set_nonblocking(true)
            .map_err(|e| Error::msg(format!("http set_nonblocking: {e}")))?;
        let http = http.clone();
        let file_dir = file_dir.clone();
        let running = running.clone();
        handles.push(thread::spawn(move || {
            if let Err(e) = run_http_server(http_listener, &http, &file_dir, running.clone()) {
                eprintln!("http server error: {e}");
                running.store(false, Ordering::SeqCst);
            }
        }));
        started.push(format!("http={listen}"));
    }

    if started.is_empty() {
        return Err(Error::msg(
            "netboot section configured no servers (set at least one of dhcp/tftp/http)",
        ));
    }

    eprintln!(
        "netboot serving {} (netboot IP {} — Ctrl-C to stop)",
        started.join(", "),
        ip,
    );

    // Block until one of the servers stops (error) or all threads finish. The
    // process is normally terminated by SIGINT (Ctrl-C); the OS-default handler
    // tears down the threads.
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}

/// Resolve the `${NETBOOT_IP}` value from CLI options or auto-detection.
fn resolve_netboot_ip(interface: Option<&str>, bind_ip: Option<&str>) -> Result<Ipv4Addr> {
    if let Some(ip) = bind_ip {
        return parse_ipv4(ip, "--bind-ip");
    }
    if let Some(iface) = interface {
        return iface_ipv4(iface);
    }
    // Auto-detect the default-route source IPv4 by connecting a UDP socket to
    // a public address and reading the local address the kernel chose. No
    // packets are sent (UDP connect only sets up the routing decision).
    let sock = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| Error::msg(format!("auto-detect: bind socket failed: {e}")))?;
    sock.connect("1.1.1.1:53")
        .map_err(|e| Error::msg(format!("auto-detect: connect failed: {e}")))?;
    let local = sock
        .local_addr()
        .map_err(|e| Error::msg(format!("auto-detect: local_addr failed: {e}")))?;
    match local.ip() {
        std::net::IpAddr::V4(v4) if !v4.is_loopback() => Ok(v4),
        std::net::IpAddr::V4(_) => Err(Error::msg(
            "auto-detected a loopback address; pass --interface <name> or --bind-ip <ip>",
        )),
        std::net::IpAddr::V6(_) => Err(Error::msg(
            "auto-detected an IPv6 default-route address; pass --interface <name> or --bind-ip <ip>",
        )),
    }
}

/// Look up the first non-loopback IPv4 of a named interface.
fn iface_ipv4(iface: &str) -> Result<Ipv4Addr> {
    let addrs = if_addrs::get_if_addrs()
        .map_err(|e| Error::msg(format!("enumerate network interfaces: {e}")))?;
    for a in addrs {
        if a.name == iface
            && let std::net::IpAddr::V4(v4) = a.ip()
            && !v4.is_loopback()
        {
            return Ok(v4);
        }
    }
    Err(Error::msg(format!(
        "no non-loopback IPv4 address found on interface {iface:?}"
    )))
}

/// Compute the socket bind address for a server from its (already-substituted)
/// `listen` field. A `None`/empty `listen` binds to `ip:default_port`; a bare
/// port (`"69"`) binds to `ip:port`; a full `host:port` is used as-is.
///
/// When `bind_all` is true (used for the DHCP server), the default/bare-port
/// forms bind to `0.0.0.0` instead of `ip` so broadcast packets are received.
/// An explicit `host:port` is always honored as-is.
fn resolve_listen(
    listen: Option<&str>,
    ip: Ipv4Addr,
    default_port: u16,
    bind_all: bool,
) -> Result<String> {
    let s = listen.unwrap_or("");
    let bind_ip = if bind_all { Ipv4Addr::UNSPECIFIED } else { ip };
    if s.is_empty() {
        return Ok(format!("{bind_ip}:{default_port}"));
    }
    if s.chars().all(|c| c.is_ascii_digit()) {
        let port: u16 = s
            .parse()
            .map_err(|e| Error::msg(format!("invalid port {s:?} in listen: {e}")))?;
        return Ok(format!("{bind_ip}:{port}"));
    }
    // Full "host:port" — validate it parses as a socket address.
    s.parse::<SocketAddr>()
        .map_err(|e| Error::msg(format!("invalid listen address {s:?}: {e}")))?;
    Ok(s.to_string())
}

/// Resolve a file referenced by the netboot section to its on-disk path in the
/// manifest directory, validating it is recorded in the manifest `file` map.
fn resolve_netboot_file(
    hash_name: &str,
    file_map: &BTreeMap<String, crate::model::manifest::ManifestFile>,
    dir: &Path,
) -> Result<std::path::PathBuf> {
    if !file_map.contains_key(hash_name) {
        return Err(Error::msg(format!(
            "Manifest has no file entry for netboot file \"{hash_name}\""
        )));
    }
    let path = dir.join(hash_name);
    if !path.exists() {
        return Err(Error::msg(format!(
            "netboot file \"{hash_name}\" is missing from the manifest directory ({})",
            dir.display()
        )));
    }
    Ok(path)
}

fn validate_netboot_files(
    netboot: &ConfigNetboot,
    file_map: &BTreeMap<String, crate::model::manifest::ManifestFile>,
    dir: &Path,
) -> Result<()> {
    if let Some(tftp) = netboot.tftp.as_ref() {
        for name in tftp.files.values() {
            resolve_netboot_file(name, file_map, dir)?;
        }
    }
    if let Some(http) = netboot.http.as_ref() {
        for name in http.files.values() {
            resolve_netboot_file(name, file_map, dir)?;
        }
    }
    Ok(())
}

fn parse_ipv4(s: &str, field: &str) -> Result<Ipv4Addr> {
    s.parse::<Ipv4Addr>()
        .map_err(|e| Error::msg(format!("Invalid IP for {field} \"{s}\": {e}")))
}

// ---------------------------------------------------------------------------
// DHCP proxy server (RFC 2131 / RFC 2132 / RFC 5071)
// ---------------------------------------------------------------------------

/// DHCP message types.
const MSG_DISCOVER: u8 = 1;
const MSG_OFFER: u8 = 2;
const MSG_REQUEST: u8 = 3;
const MSG_ACK: u8 = 5;

fn run_dhcp_server(
    sock: UdpSocket,
    dhcp: &ConfigNetbootDhcp,
    server_ip: Ipv4Addr,
    running: Arc<AtomicBool>,
    reply_to_src: bool,
) -> Result<()> {
    let broadcast = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::BROADCAST), 68);

    // Pre-resolve the configured server identifier (option 54), if any, so the
    // REQUEST filter can compare against it. Option 54 identifies *this* proxy
    // server and must be consistent across profiles; the first profile that
    // sets it explicitly is used. When no profile sets option 54, it defaults
    // to server_ip (matching build_proxy_dhcp_reply's default injection).
    let server_id: Ipv4Addr = dhcp
        .profiles
        .iter()
        .find_map(|p| p.options.get("54"))
        .and_then(|v| match v {
            DhcpOptionValue::Ipv4 { value } => Some(value.clone()),
            _ => None,
        })
        .and_then(|s| parse_ipv4(&s, "option 54 (server identifier)").ok())
        .unwrap_or(server_ip);

    let mut buf = [0u8; 1024];
    while running.load(Ordering::SeqCst) {
        let (n, src) = match sock.recv_from(&mut buf) {
            Ok(x) => x,
            Err(_) if !running.load(Ordering::SeqCst) => break,
            Err(e) => {
                eprintln!("dhcp recv error: {e}");
                continue;
            }
        };
        if n < 240 {
            continue; // too small to be a DHCP packet
        }
        let pkt = &buf[..n];
        let msg_type = dhcp_option(pkt, 53).and_then(|v| v.first().copied());
        let client_hw = {
            let mut hw = [0u8; 6];
            hw.copy_from_slice(&pkt[28..34]);
            hw
        };
        let xid = u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
        let mac = format_mac(&client_hw);
        let msg_name = dhcp_msg_name(msg_type);

        // Select the first profile whose `match` filter passes (a profile
        // with no `match` is a catch-all). If none matches, ignore the
        // request — we have nothing to offer that client.
        let Some(profile) = select_profile(dhcp, pkt) else {
            eprintln!(
                "dhcp: {msg_name} from {src} (xid={xid:#010x}, mac={mac}) — \
                 ignored (no matching profile)"
            );
            continue;
        };
        let label = profile.name.as_deref().unwrap_or("default");
        eprintln!(
            "dhcp: received {msg_name} from {src} (xid={xid:#010x}, mac={mac}) — \
             profile {label:?}"
        );

        match msg_type {
            Some(MSG_DISCOVER) => {
                let dst = if reply_to_src { src } else { broadcast };
                match build_proxy_dhcp_reply(MSG_OFFER, xid, client_hw, server_ip, profile) {
                    Ok(reply) => {
                        eprintln!(
                            "dhcp: sending OFFER to {mac} (xid={xid:#010x}, {} bytes) \
                             via {dst}",
                            reply.len()
                        );
                        let _ = sock.send_to(&reply, dst);
                    }
                    Err(e) => eprintln!("dhcp: failed to build OFFER: {e}"),
                }
            }
            Some(MSG_REQUEST) => {
                // Only respond to REQUESTs directed at us (option 54 = our
                // server identifier). If option 54 is set to another server,
                // ignore — that REQUEST is for the main DHCP server.
                if let Some(their) = dhcp_option(pkt, 54).filter(|v| v.len() == 4) {
                    let their_sid = Ipv4Addr::new(their[0], their[1], their[2], their[3]);
                    if their_sid != server_id {
                        eprintln!(
                            "dhcp: REQUEST from {mac} (xid={xid:#010x}) — \
                             ignored (directed at server {their_sid}, not us)"
                        );
                        continue;
                    }
                }
                let dst = if reply_to_src { src } else { broadcast };
                match build_proxy_dhcp_reply(MSG_ACK, xid, client_hw, server_ip, profile) {
                    Ok(reply) => {
                        eprintln!(
                            "dhcp: sending ACK to {mac} (xid={xid:#010x}, {} bytes) \
                             via {dst}",
                            reply.len()
                        );
                        let _ = sock.send_to(&reply, dst);
                    }
                    Err(e) => eprintln!("dhcp: failed to build ACK: {e}"),
                }
            }
            _ => {
                // Ignore other message types (RELEASE/DECLINE/INFORM).
                eprintln!(
                    "dhcp: {msg_name} from {src} (xid={xid:#010x}, mac={mac}) — \
                     ignored (unsupported message type)"
                );
            }
        }
    }
    Ok(())
}

/// Select the first DHCP profile whose `match` filter passes for the received
/// packet. A profile with no `match` (or all-empty lists) is a catch-all and
/// matches every client. Returns `None` if no profile matches.
fn select_profile<'a>(
    dhcp: &'a ConfigNetbootDhcp,
    pkt: &[u8],
) -> Option<&'a ConfigNetbootDhcpProfile> {
    for p in &dhcp.profiles {
        if let Some(m) = p.r#match.as_ref()
            && !client_matches(m, pkt)
        {
            continue;
        }
        return Some(p);
    }
    None
}

/// Format a 6-byte hardware address as `aa:bb:cc:dd:ee:ff`.
fn format_mac(hw: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        hw[0], hw[1], hw[2], hw[3], hw[4], hw[5]
    )
}

/// Human-readable name for a DHCP message type (option 53 value).
fn dhcp_msg_name(msg_type: Option<u8>) -> &'static str {
    match msg_type {
        Some(1) => "DISCOVER",
        Some(2) => "OFFER",
        Some(3) => "REQUEST",
        Some(4) => "DECLINE",
        Some(5) => "ACK",
        Some(6) => "NAK",
        Some(7) => "RELEASE",
        Some(8) => "INFORM",
        Some(_) => "UNKNOWN",
        None => "NO-TYPE",
    }
}

/// Build a proxy DHCPv4 reply packet (OFFER or ACK).
///
/// `yiaddr` is set to `0.0.0.0` — this is a proxy DHCP server that does not
/// assign IP addresses. Defaults (applied when the profile leaves the field
/// unset):
///
/// - **`siaddr`** (next-server header) defaults to `server_ip`.
/// - **Option 54** (Server Identifier) defaults to `server_ip`, independently
///   of `siaddr`. These are semantically distinct: option 54 identifies *this*
///   DHCP server, while `siaddr` tells the client where to download boot files.
///   They can differ when the boot server is on another host. EDK2's Dhcp4Dxe
///   silently drops any OFFER whose option 54 is absent (DhcpHandleSelect
///   treats ServerId == 0 as invalid), so the default is mandatory.
///
/// Option 53 (message type) is injected automatically and must not be set
/// explicitly. Every entry of [`ConfigNetbootDhcpProfile::options`] is encoded
/// in numeric option-code order.
fn build_proxy_dhcp_reply(
    msg_type: u8,
    xid: u32,
    client_hw: [u8; 6],
    server_ip: Ipv4Addr,
    profile: &ConfigNetbootDhcpProfile,
) -> Result<Vec<u8>> {
    let mut pkt = vec![0u8; 240];
    pkt[0] = 2; // BOOTREPLY
    pkt[1] = 1; // Ethernet
    pkt[2] = 6; // hw addr len
    pkt[4..8].copy_from_slice(&xid.to_be_bytes());
    // yiaddr = 0.0.0.0 (proxy DHCP — no IP offered).
    // siaddr (next-server) — default to server_ip when not configured.
    let siaddr_ip = profile
        .siaddr
        .as_deref()
        .map(|s| parse_ipv4(s, "dhcp profile siaddr"))
        .transpose()?
        .unwrap_or(server_ip);
    pkt[20..24].copy_from_slice(&siaddr_ip.octets());
    pkt[28..34].copy_from_slice(&client_hw);
    // Boot file name (file field, 128 bytes at offset 108).
    if let Some(boot_file) = profile.boot_file.as_deref() {
        let file_bytes = boot_file.as_bytes();
        let file_len = file_bytes.len().min(127);
        pkt[108..108 + file_len].copy_from_slice(&file_bytes[..file_len]);
    }
    // Magic cookie at offset 236.
    pkt[236] = 99;
    pkt[237] = 130;
    pkt[238] = 83;
    pkt[239] = 99;

    // Options, sorted by numeric option code. Option 53 (message type) is
    // always injected first. Option 54 (Server Identifier) defaults to
    // server_ip when not set explicitly — independent of siaddr.
    let mut entries: Vec<(u8, Vec<u8>)> = Vec::with_capacity(profile.options.len() + 2);
    let mut has_server_id = false;
    for (code_str, value) in &profile.options {
        let code: u8 = code_str
            .parse()
            .map_err(|e| Error::msg(format!("invalid DHCP option code {code_str:?}: {e}")))?;
        if code == 53 {
            // Managed automatically; ignore any explicit setting.
            continue;
        }
        if code == 54 {
            has_server_id = true;
        }
        let bytes = encode_option_value(value)?;
        entries.push((code, bytes));
    }
    if !has_server_id {
        entries.push((54, server_ip.octets().to_vec()));
    }
    entries.sort_by_key(|(c, _)| *c);

    let mut opts = Vec::new();
    push_opt(&mut opts, 53, &[msg_type]);
    for (code, bytes) in &entries {
        if bytes.len() > 255 {
            return Err(Error::msg(format!(
                "DHCP option {code} value is too long ({} bytes; max 255)",
                bytes.len()
            )));
        }
        push_opt(&mut opts, *code, bytes);
    }
    opts.push(255); // end

    pkt.extend_from_slice(&opts);
    Ok(pkt)
}

/// Encode a typed [`DhcpOptionValue`] to its DHCP wire bytes.
fn encode_option_value(v: &DhcpOptionValue) -> Result<Vec<u8>> {
    Ok(match v {
        DhcpOptionValue::String { value } => value.as_bytes().to_vec(),
        DhcpOptionValue::Ipv4 { value } => parse_ipv4(value, "ipv4 DHCP option value")?
            .octets()
            .to_vec(),
        DhcpOptionValue::U8 { value } => vec![*value],
        DhcpOptionValue::U16 { value } => value.to_be_bytes().to_vec(),
        DhcpOptionValue::U32 { value } => value.to_be_bytes().to_vec(),
        DhcpOptionValue::Bytes { value } => parse_hex_bytes(value, "bytes DHCP option value")?,
        DhcpOptionValue::Array { value } => {
            let mut out = Vec::new();
            for item in value {
                out.extend_from_slice(&encode_option_value(item)?);
            }
            out
        }
        DhcpOptionValue::VendorOptions { value } => {
            let mut blob = Vec::new();
            for (code_str, val) in value {
                let code: u8 = code_str.parse().map_err(|e| {
                    Error::msg(format!("invalid vendor suboption code {code_str:?}: {e}"))
                })?;
                let val_bytes = val.as_bytes();
                if val_bytes.len() > 255 {
                    return Err(Error::msg(format!(
                        "vendor suboption {code} value is too long ({} bytes; max 255)",
                        val_bytes.len()
                    )));
                }
                blob.push(code);
                blob.push(val_bytes.len() as u8);
                blob.extend_from_slice(val_bytes);
            }
            blob
        }
    })
}

/// Parse a colon-separated hex string (e.g. `"01:02:03"`) into bytes. A bare
/// hex string without colons is also accepted.
fn parse_hex_bytes(s: &str, field: &str) -> Result<Vec<u8>> {
    let cleaned: String = s.chars().filter(|c| *c != ':').collect();
    hex::decode(&cleaned).map_err(|e| Error::msg(format!("invalid hex for {field} \"{s}\": {e}")))
}

fn push_opt(out: &mut Vec<u8>, code: u8, val: &[u8]) {
    out.push(code);
    out.push(val.len() as u8);
    out.extend_from_slice(val);
}

/// Look up a DHCP option by code. Returns the option value bytes (without
/// code/length), or `None` if absent or the options block is malformed.
fn dhcp_option(pkt: &[u8], code: u8) -> Option<&[u8]> {
    if pkt.len() < 240 {
        return None;
    }
    // Verify magic cookie.
    if pkt[236..240] != [99, 130, 83, 99] {
        return None;
    }
    let mut i = 240;
    while i < pkt.len() {
        let c = pkt[i];
        if c == 0 {
            // PAD
            i += 1;
            continue;
        }
        if c == 255 {
            break; // END
        }
        if i + 1 >= pkt.len() {
            break;
        }
        let len = pkt[i + 1] as usize;
        if i + 2 + len > pkt.len() {
            break;
        }
        if c == code {
            return Some(&pkt[i + 2..i + 2 + len]);
        }
        i += 2 + len;
    }
    None
}

/// Normalize a hex string by lowercasing and stripping `:` separators.
fn normalize_hex(s: &str) -> String {
    s.to_ascii_lowercase().replace(':', "")
}

/// Normalize a MAC string by lowercasing and stripping `:`/`-` separators.
fn normalize_mac(s: &str) -> String {
    s.to_ascii_lowercase().replace([':', '-'], "")
}

/// Test a received DHCP packet against the configured client allowlist. A
/// request matches only if it passes every set (non-empty) filter.
fn client_matches(m: &crate::model::netboot::ConfigNetbootDhcpMatch, pkt: &[u8]) -> bool {
    // MAC (chaddr, 6 bytes at offset 28).
    if !m.mac.is_empty() {
        let client_mac = normalize_mac(&hex::encode(&pkt[28..34]));
        let ok = m.mac.iter().any(|entry| {
            let e = normalize_mac(entry);
            // Full match, or OUI prefix (entry shorter than the client MAC).
            e.len() <= 12 && client_mac.starts_with(&e)
        });
        if !ok {
            return false;
        }
    }
    // Option 60 (vendor class identifier) — prefix match.
    if !m.vendor_class.is_empty() {
        let client_vc = dhcp_option(pkt, 60).map(|v| String::from_utf8_lossy(v).to_string());
        let Some(vc) = client_vc else {
            return false;
        };
        let ok = m.vendor_class.iter().any(|entry| vc.starts_with(entry));
        if !ok {
            return false;
        }
    }
    // Option 93 (client system architecture) — list of big-endian u16.
    if !m.architecture.is_empty() {
        let Some(raw) = dhcp_option(pkt, 93) else {
            return false;
        };
        if raw.len() % 2 != 0 {
            return false;
        }
        let client_archs: Vec<u16> = raw
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_be_bytes(*c))
            .collect();
        let ok = client_archs.iter().any(|a| m.architecture.contains(a));
        if !ok {
            return false;
        }
    }
    // Option 97 (client machine GUID) — raw bytes, hex-compare.
    if !m.guid.is_empty() {
        let Some(raw) = dhcp_option(pkt, 97) else {
            return false;
        };
        let client_guid = normalize_hex(&hex::encode(raw));
        let ok = m.guid.iter().any(|e| normalize_hex(e) == client_guid);
        if !ok {
            return false;
        }
    }
    // Option 77 (user class) — raw bytes, exact string compare.
    if !m.user_class.is_empty() {
        let client_uc = dhcp_option(pkt, 77).map(|v| String::from_utf8_lossy(v).to_string());
        let Some(uc) = client_uc else {
            return false;
        };
        if !m.user_class.contains(&uc) {
            return false;
        }
    }
    // Option 61 (client identifier) — raw bytes, hex-compare.
    if !m.client_id.is_empty() {
        let Some(raw) = dhcp_option(pkt, 61) else {
            return false;
        };
        let client_id = normalize_hex(&hex::encode(raw));
        let ok = m.client_id.iter().any(|e| normalize_hex(e) == client_id);
        if !ok {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// TFTP server (RFC 1350)
// ---------------------------------------------------------------------------

const TFTP_RRQ: u16 = 1;
const TFTP_DATA: u16 = 3;
const TFTP_ACK: u16 = 4;
const TFTP_ERROR: u16 = 5;
const TFTP_OACK: u16 = 6;

fn run_tftp_server(
    sock: UdpSocket,
    tftp: &crate::model::netboot::ConfigNetbootTftp,
    file_dir: &Path,
    running: Arc<AtomicBool>,
) -> Result<()> {
    let files = tftp.files.clone();
    let file_dir = file_dir.to_path_buf();
    let mut buf = [0u8; 2048];
    while running.load(Ordering::SeqCst) {
        let (n, peer) = match sock.recv_from(&mut buf) {
            Ok(x) => x,
            Err(_) if !running.load(Ordering::SeqCst) => break,
            Err(e) => {
                eprintln!("tftp recv error: {e}");
                continue;
            }
        };
        if n < 2 {
            continue;
        }
        let opcode = u16::from_be_bytes([buf[0], buf[1]]);
        if opcode != TFTP_RRQ {
            eprintln!("tftp: ignoring non-RRQ opcode {opcode} from {peer}");
            continue; // only RRQ is supported (read-only server)
        }
        // Parse filename + mode from the RRQ payload (null-terminated strings).
        let payload = &buf[2..n];
        let (filename, rest) = match split_cstr(payload) {
            Some(x) => x,
            None => continue,
        };
        let (mode, rest_after_mode) = split_cstr(rest).unwrap_or(("", &[]));
        if !mode.eq_ignore_ascii_case("octet") {
            // Only octet mode is supported.
            let err = tftp_error(0, "only octet mode supported");
            let _ = sock.send_to(&err, peer);
            eprintln!(
                "tftp: RRQ for \"{filename}\" from {peer} rejected \
                 (unsupported mode \"{mode}\")"
            );
            continue;
        }
        // Parse TFTP option extensions (RFC 2347–2349) after filename + mode.
        // PXE clients (EDK2) send `tsize` and `blksize` options and expect an
        // OACK response — if the server sends DATA without an OACK first, the
        // client aborts with a TFTP ERROR.
        let rrq_options = parse_tftp_options(rest_after_mode);
        if !rrq_options.is_empty() {
            let opt_summary: Vec<String> = rrq_options
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            eprintln!(
                "tftp: RRQ for \"{filename}\" (mode {mode}) from {peer} \
                 with options: {}",
                opt_summary.join(", ")
            );
        } else {
            eprintln!("tftp: RRQ for \"{filename}\" (mode {mode}) from {peer}");
        }
        let Some(hash_name) = files.get(filename) else {
            let err = tftp_error(1, "file not found");
            let _ = sock.send_to(&err, peer);
            eprintln!("tftp: unknown file \"{filename}\" requested by {peer}");
            continue;
        };
        let filename = filename.to_string();
        let path = file_dir.join(hash_name);
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) => {
                let err = tftp_error(0, &format!("read error: {e}"));
                let _ = sock.send_to(&err, peer);
                eprintln!("tftp: read error for \"{filename}\" ({hash_name}): {e}");
                continue;
            }
        };
        eprintln!(
            "tftp: serving \"{filename}\" ({} bytes) to {peer}",
            data.len()
        );
        // Negotiate options (may produce an OACK packet + negotiated block size).
        let (oack, blksize) = negotiate_tftp_options(&rrq_options, data.len());
        if oack.is_some() {
            eprintln!("tftp: negotiated blksize={blksize} for \"{filename}\" to {peer}");
        }
        // Serve the transfer from a fresh ephemeral socket (new TID), in a
        // dedicated thread so the main socket stays free for new RRQs.
        let running = running.clone();
        thread::spawn(move || {
            if let Err(e) = tftp_transfer(&data, peer, running, oack, blksize) {
                eprintln!("tftp transfer of \"{filename}\" to {peer} failed: {e}");
            } else {
                eprintln!(
                    "tftp: transfer of \"{filename}\" to {peer} complete ({} bytes)",
                    data.len()
                );
            }
        });
    }
    Ok(())
}

/// Send a file to a TFTP client over a fresh ephemeral socket, one block at a
/// time, waiting for each ACK (with a retransmit timeout). If `oack` is
/// `Some`, an OACK is sent first and the transfer waits for ACK block 0 before
/// sending DATA. The block counter wraps modulo 65536 (see
/// [`tftp_transfer_blocks`]), so files larger than 65535 * `blksize` bytes are
/// supported.
fn tftp_transfer(
    data: &[u8],
    peer: SocketAddr,
    running: Arc<AtomicBool>,
    oack: Option<Vec<u8>>,
    blksize: usize,
) -> Result<()> {
    tftp_transfer_blocks(data, peer, blksize, running, oack)
}

/// Same as [`tftp_transfer`] but with a configurable block size. Used by the
/// regression test to exercise the 16-bit block-number wraparound without
/// having to shuffle 32 MiB through the loop.
fn tftp_transfer_blocks(
    data: &[u8],
    peer: SocketAddr,
    block_size: usize,
    running: Arc<AtomicBool>,
    oack: Option<Vec<u8>>,
) -> Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| Error::msg(format!("tftp bind: {e}")))?;
    sock.set_read_timeout(Some(Duration::from_millis(2000)))
        .ok();
    let total_blocks = data.len().div_ceil(block_size).max(1);
    let mut buf = [0u8; 512]; // large enough for ERROR packets with messages

    // If option negotiation produced an OACK, send it first and wait for the
    // client's ACK of block 0 (RFC 2347: "the client sends an ACK with a block
    // number of 0 to confirm the OACK").
    if let Some(oack_pkt) = &oack {
        let mut attempts = 0;
        loop {
            sock.send_to(oack_pkt, peer)
                .map_err(|e| Error::msg(format!("tftp oack send: {e}")))?;
            if !running.load(Ordering::SeqCst) {
                return Ok(());
            }
            match sock.recv_from(&mut buf) {
                Ok((n, _)) => {
                    if n >= 4 {
                        let opcode = u16::from_be_bytes([buf[0], buf[1]]);
                        if opcode == TFTP_ACK {
                            let ack_block = u16::from_be_bytes([buf[2], buf[3]]);
                            if ack_block == 0 {
                                break; // OACK acknowledged
                            }
                            // Stale ACK — retransmit OACK.
                        } else if opcode == TFTP_ERROR {
                            let code = u16::from_be_bytes([buf[2], buf[3]]);
                            let msg = split_cstr(&buf[4..n])
                                .map(|(m, _)| m.to_string())
                                .unwrap_or_default();
                            return Err(Error::msg(format!(
                                "tftp: client sent error {code} after OACK: {msg}"
                            )));
                        }
                    }
                }
                Err(_) if !running.load(Ordering::SeqCst) => return Ok(()),
                Err(_) => {}
            }
            attempts += 1;
            if attempts > 5 {
                return Err(Error::msg("tftp: OACK ACK timeout"));
            }
        }
    }

    for block in 1..=total_blocks {
        let offset = (block - 1) * block_size;
        let end = (offset + block_size).min(data.len());
        let chunk = &data[offset..end];
        let mut pkt = Vec::with_capacity(4 + chunk.len());
        pkt.extend_from_slice(&TFTP_DATA.to_be_bytes());
        pkt.extend_from_slice(&(block as u16).to_be_bytes());
        pkt.extend_from_slice(chunk);

        // Retransmit up to a few times while waiting for the matching ACK.
        let mut attempts = 0;
        loop {
            sock.send_to(&pkt, peer)
                .map_err(|e| Error::msg(format!("tftp send: {e}")))?;
            if !running.load(Ordering::SeqCst) {
                return Ok(());
            }
            match sock.recv_from(&mut buf) {
                Ok((n, _)) => {
                    let opcode = u16::from_be_bytes([buf[0], buf[1]]);
                    if opcode == TFTP_ACK {
                        let ack_block = u16::from_be_bytes([buf[2], buf[3]]);
                        // TFTP block numbers are a 16-bit counter that wraps
                        // modulo 65536 (RFC 1350 wire format is u16). The DATA
                        // packet above is sent with `block as u16`, so a file
                        // larger than 65535 * block_size bytes makes `block`
                        // exceed u16::MAX and the on-wire number wraps to 0,
                        // 1, 2, … The client ACKs that wrapped u16, so we must
                        // compare against the wrapped value, not the raw
                        // `usize` block index — otherwise every ACK after the
                        // wrap is misread as "stale" and the transfer aborts.
                        if ack_block == block as u16 {
                            break; // ACK matches, send next block
                        }
                        // Stale ACK for an older block — retransmit current.
                    } else if opcode == TFTP_ERROR {
                        let code = u16::from_be_bytes([buf[2], buf[3]]);
                        let msg = split_cstr(&buf[4..n])
                            .map(|(m, _)| m.to_string())
                            .unwrap_or_default();
                        return Err(Error::msg(format!("tftp: client sent error {code}: {msg}")));
                    }
                }
                Err(_) if !running.load(Ordering::SeqCst) => return Ok(()),
                Err(_) => {
                    attempts += 1;
                    if attempts > 5 {
                        return Err(Error::msg("tftp: ACK timeout"));
                    }
                    continue;
                }
            }
            attempts += 1;
            if attempts > 5 {
                return Err(Error::msg("tftp: too many stale ACKs"));
            }
        }
    }
    // If the file is an exact multiple of the block size, send a final
    // zero-length DATA block so the client knows the transfer is complete.
    if data.len().is_multiple_of(block_size) && !data.is_empty() {
        let pkt = [
            (TFTP_DATA >> 8) as u8,
            TFTP_DATA as u8,
            (total_blocks >> 8) as u8,
            total_blocks as u8,
        ];
        let _ = sock.send_to(&pkt, peer);
        // Wait briefly for the final ACK (best effort).
        let _ = sock.recv_from(&mut buf);
    }
    Ok(())
}

fn tftp_error(code: u16, msg: &str) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(4 + msg.len() + 1);
    pkt.extend_from_slice(&TFTP_ERROR.to_be_bytes());
    pkt.extend_from_slice(&code.to_be_bytes());
    pkt.extend_from_slice(msg.as_bytes());
    pkt.push(0);
    pkt
}

/// Parse TFTP option extensions (RFC 2347–2349) from an RRQ payload after the
/// filename and mode strings. Returns a map of option name → value (both
/// lowercase, as TFTP option names are case-insensitive).
fn parse_tftp_options(payload: &[u8]) -> Vec<(String, String)> {
    let mut opts = Vec::new();
    let mut rest = payload;
    while let Some((key, r1)) = split_cstr(rest) {
        if key.is_empty() {
            break;
        }
        if let Some((val, r2)) = split_cstr(r1) {
            opts.push((key.to_ascii_lowercase(), val.to_string()));
            rest = r2;
        } else {
            break;
        }
    }
    opts
}

/// Negotiate TFTP options and build an OACK packet if any recognized options
/// were requested. Returns `(oack_packet, negotiated_blksize)`. If no
/// recognized options are present, returns `(None, 512)`.
fn negotiate_tftp_options(opts: &[(String, String)], file_size: usize) -> (Option<Vec<u8>>, usize) {
    let mut oack = Vec::new();
    let mut blksize = 512usize;

    for (key, val) in opts {
        match key.as_str() {
            "blksize" => {
                // RFC 2348: negotiate block size. Cap at 65464 (max safe UDP
                // payload) and accept the client's requested value if reasonable.
                if let Ok(requested) = val.parse::<usize>()
                    && (8..=65464).contains(&requested)
                {
                    blksize = requested;
                    oack.extend_from_slice(b"blksize\0");
                    oack.extend_from_slice(blksize.to_string().as_bytes());
                    oack.push(0);
                }
            }
            "tsize" => {
                // RFC 2349: return the actual file size.
                oack.extend_from_slice(b"tsize\0");
                oack.extend_from_slice(file_size.to_string().as_bytes());
                oack.push(0);
            }
            "timeout" => {
                // RFC 2349: echo back the requested timeout (we accept any
                // reasonable value; our retransmit timeout is fixed at 2s but
                // we acknowledge the option).
                if let Ok(t) = val.parse::<u32>()
                    && (1..=255).contains(&t)
                {
                    oack.extend_from_slice(b"timeout\0");
                    oack.extend_from_slice(t.to_string().as_bytes());
                    oack.push(0);
                }
            }
            _ => {} // ignore unknown options
        }
    }

    if oack.is_empty() {
        (None, 512)
    } else {
        let mut pkt = Vec::with_capacity(2 + oack.len());
        pkt.extend_from_slice(&TFTP_OACK.to_be_bytes());
        pkt.extend_from_slice(&oack);
        (Some(pkt), blksize)
    }
}

/// Split a null-terminated C string from the front of `buf`, returning the
/// string and the remaining bytes.
fn split_cstr(buf: &[u8]) -> Option<(&str, &[u8])> {
    let end = buf.iter().position(|&b| b == 0)?;
    let s = std::str::from_utf8(&buf[..end]).ok()?;
    Some((s, &buf[end + 1..]))
}

// ---------------------------------------------------------------------------
// HTTP server (minimal HTTP/1.1)
// ---------------------------------------------------------------------------

fn run_http_server(
    listener: TcpListener,
    http: &crate::model::netboot::ConfigNetbootHttp,
    file_dir: &Path,
    running: Arc<AtomicBool>,
) -> Result<()> {
    let files = http.files.clone();
    let file_dir = file_dir.to_path_buf();
    while running.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, peer)) => {
                let files = files.clone();
                let file_dir = file_dir.clone();
                let running = running.clone();
                thread::spawn(move || {
                    if let Err(e) = handle_http_connection(stream, &files, &file_dir, running, peer)
                    {
                        eprintln!("http connection error: {e}");
                    }
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No connection yet; sleep briefly and re-check the running flag.
                thread::sleep(Duration::from_millis(100));
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::Interrupted
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => {
                eprintln!("http accept error: {e}");
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
    Ok(())
}

/// Handle a single HTTP/1.1 connection: read the request, serve the matching
/// file (or a 404), then close the connection.
fn handle_http_connection(
    stream: std::net::TcpStream,
    files: &BTreeMap<String, String>,
    file_dir: &Path,
    _running: Arc<AtomicBool>,
    peer: SocketAddr,
) -> Result<()> {
    use std::io::Read;
    stream.set_nonblocking(false).ok();
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let mut stream = stream;
    let mut buf = [0u8; 4096];
    // Read until the end of the request headers (\r\n\r\n) or the buffer fills.
    let mut total = 0;
    while total < buf.len() {
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let req = std::str::from_utf8(&buf[..total]).unwrap_or("");
    let request_line = req.lines().next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("/");

    eprintln!("http: {method} {path} from {peer}");

    if (method != "GET" && method != "HEAD") || path.is_empty() {
        eprintln!("http: -> 405 Method Not Allowed ({method} {path} from {peer})");
        write_http_response(
            &mut stream,
            405,
            "Method Not Allowed",
            &[],
            method == "HEAD",
        )?;
        return Ok(());
    }
    // Drop any query string.
    let path_only = path.split('?').next().unwrap_or(path);
    let Some(hash_name) = files.get(path_only) else {
        eprintln!("http: -> 404 Not Found ({method} {path_only} from {peer})");
        write_http_response(
            &mut stream,
            404,
            "Not Found",
            b"Not Found\n",
            method == "HEAD",
        )?;
        return Ok(());
    };
    let file_path = file_dir.join(hash_name);
    let body = match std::fs::read(&file_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("http: -> 500 Internal Server Error ({method} {path_only} from {peer}): {e}");
            write_http_response(
                &mut stream,
                500,
                "Internal Server Error",
                format!("{e}\n").as_bytes(),
                method == "HEAD",
            )?;
            return Ok(());
        }
    };
    eprintln!(
        "http: -> 200 OK ({method} {path_only} from {peer}, {} bytes)",
        body.len()
    );
    write_http_response(&mut stream, 200, "OK", &body, method == "HEAD")?;
    Ok(())
}

fn write_http_response(
    stream: &mut std::net::TcpStream,
    status: u16,
    reason: &str,
    body: &[u8],
    head_only: bool,
) -> Result<()> {
    use std::io::Write;
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {len}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
        len = body.len()
    );
    stream
        .write_all(header.as_bytes())
        .map_err(|e| Error::msg(format!("http write header: {e}")))?;
    if !head_only {
        stream
            .write_all(body)
            .map_err(|e| Error::msg(format!("http write body: {e}")))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::netboot::{ConfigNetbootDhcpMatch, ConfigNetbootHttp, ConfigNetbootTftp};
    use std::net::UdpSocket;
    use std::path::PathBuf;

    /// Build a minimal DHCPDISCOVER packet with the given client hardware
    /// address and an optional set of (code, value) options.
    fn build_dhcp_discover(client_hw: [u8; 6], opts: &[(u8, &[u8])]) -> Vec<u8> {
        let mut pkt = vec![0u8; 240];
        pkt[0] = 1; // BOOTREQUEST
        pkt[1] = 1; // Ethernet
        pkt[2] = 6; // hw addr len
        pkt[4..8].copy_from_slice(&0x1234_5678u32.to_be_bytes()); // xid
        pkt[28..34].copy_from_slice(&client_hw);
        pkt[236] = 99;
        pkt[237] = 130;
        pkt[238] = 83;
        pkt[239] = 99;
        let mut blob = Vec::new();
        push_opt(&mut blob, 53, &[MSG_DISCOVER]);
        for (code, val) in opts {
            push_opt(&mut blob, *code, val);
        }
        blob.push(255);
        pkt.extend_from_slice(&blob);
        pkt
    }

    #[test]
    fn proxy_dhcp_reply_encodes_generic_options() {
        let mut options = BTreeMap::new();
        options.insert(
            "54".to_string(),
            DhcpOptionValue::Ipv4 {
                value: "192.168.1.1".to_string(),
            },
        );
        options.insert(
            "60".to_string(),
            DhcpOptionValue::String {
                value: "PXEClient".to_string(),
            },
        );
        options.insert(
            "66".to_string(),
            DhcpOptionValue::String {
                value: "192.168.1.1".to_string(),
            },
        );
        options.insert(
            "67".to_string(),
            DhcpOptionValue::String {
                value: "BOOTX64.EFI".to_string(),
            },
        );
        let mut vopts = BTreeMap::new();
        vopts.insert("5".to_string(), "/".to_string());
        options.insert(
            "43".to_string(),
            DhcpOptionValue::VendorOptions { value: vopts },
        );
        let dhcp = ConfigNetbootDhcpProfile {
            name: None,
            r#match: None,
            siaddr: Some("192.168.1.1".to_string()),
            boot_file: Some("BOOTX64.EFI".to_string()),
            options,
            pxe_boot: None,
            http_boot: None,
        };
        let pkt = build_proxy_dhcp_reply(
            MSG_OFFER,
            0x1234_5678,
            [0xAA; 6],
            Ipv4Addr::new(192, 168, 1, 32),
            &dhcp,
        )
        .unwrap();

        // Op = BOOTREPLY, hardware addr echoed back.
        assert_eq!(pkt[0], 2);
        assert_eq!(&pkt[28..34], &[0xAA; 6]);
        // yiaddr = 0.0.0.0 (proxy DHCP — no IP offered).
        assert_eq!(&pkt[16..20], &[0, 0, 0, 0]);
        assert_eq!(&pkt[20..24], &[192, 168, 1, 1]); // siaddr = next server
        // Magic cookie.
        assert_eq!(&pkt[236..240], &[99, 130, 83, 99]);
        // Boot file in the `file` field.
        let file_field = &pkt[108..108 + 16];
        assert_eq!(&file_field[..11], b"BOOTX64.EFI");
        // Options.
        assert_eq!(dhcp_option(&pkt, 53), Some(&[MSG_OFFER][..]));
        // Option 54 is explicitly set in the profile (192.168.1.1), so it
        // is used as-is — the server_ip default does not override it.
        assert_eq!(dhcp_option(&pkt, 54), Some(&[192, 168, 1, 1][..]));
        assert_eq!(dhcp_option(&pkt, 60), Some(&b"PXEClient"[..]));
        assert_eq!(dhcp_option(&pkt, 66), Some(&b"192.168.1.1"[..]));
        assert_eq!(dhcp_option(&pkt, 67), Some(&b"BOOTX64.EFI"[..]));
        // Option 43: suboption 5, length 1, value "/".
        let opt43 = dhcp_option(&pkt, 43).expect("option 43 should be present");
        assert_eq!(opt43, &[5u8, 1, b'/']);
        // No IP-related options beyond what we set.
        assert_eq!(dhcp_option(&pkt, 1), None); // subnet mask
        assert_eq!(dhcp_option(&pkt, 51), None); // lease time
    }

    #[test]
    fn numeric_option_values_encode_correctly() {
        let mut options = BTreeMap::new();
        options.insert(
            "1".to_string(),
            DhcpOptionValue::Ipv4 {
                value: "255.255.255.0".into(),
            },
        );
        options.insert("51".to_string(), DhcpOptionValue::U32 { value: 86400 });
        options.insert("57".to_string(), DhcpOptionValue::U16 { value: 1500 });
        options.insert("44".to_string(), DhcpOptionValue::U8 { value: 7 });
        options.insert(
            "12".to_string(),
            DhcpOptionValue::Bytes {
                value: "DE:AD:BE:EF".into(),
            },
        );
        let dhcp = ConfigNetbootDhcpProfile {
            name: None,
            r#match: None,
            siaddr: None,
            boot_file: None,
            options,
            pxe_boot: None,
            http_boot: None,
        };
        let pkt = build_proxy_dhcp_reply(MSG_ACK, 1, [0; 6], Ipv4Addr::new(192, 168, 1, 32), &dhcp)
            .unwrap();
        assert_eq!(dhcp_option(&pkt, 1), Some(&[255, 255, 255, 0][..]));
        assert_eq!(dhcp_option(&pkt, 51), Some(&86400u32.to_be_bytes()[..]));
        assert_eq!(dhcp_option(&pkt, 57), Some(&1500u16.to_be_bytes()[..]));
        assert_eq!(dhcp_option(&pkt, 44), Some(&[7][..]));
        assert_eq!(dhcp_option(&pkt, 12), Some(&[0xDE, 0xAD, 0xBE, 0xEF][..]));
    }

    #[test]
    fn option_53_is_managed_automatically() {
        let mut options = BTreeMap::new();
        options.insert(
            "53".to_string(),
            DhcpOptionValue::U8 { value: 99 }, // should be ignored
        );
        let dhcp = ConfigNetbootDhcpProfile {
            name: None,
            r#match: None,
            siaddr: None,
            boot_file: None,
            options,
            pxe_boot: None,
            http_boot: None,
        };
        let pkt =
            build_proxy_dhcp_reply(MSG_OFFER, 0, [0; 6], Ipv4Addr::new(192, 168, 1, 32), &dhcp)
                .unwrap();
        // The injected message type wins.
        assert_eq!(dhcp_option(&pkt, 53), Some(&[MSG_OFFER][..]));
    }

    #[test]
    fn proxy_offer_auto_injects_option_54_from_server_ip() {
        // EDK2's Dhcp4Dxe silently drops any DHCP OFFER lacking option 54
        // (Server Identifier). When a profile does not explicitly configure
        // option 54, build_proxy_dhcp_reply must inject it from server_ip.
        // Option 54 (Server-ID) and siaddr (next-server) are independent: the
        // former identifies the DHCP server, the latter tells the client where
        // to download boot files. They may differ.
        let mut options = BTreeMap::new();
        options.insert(
            "60".to_string(),
            DhcpOptionValue::String {
                value: "PXEClient".to_string(),
            },
        );
        options.insert(
            "66".to_string(),
            DhcpOptionValue::String {
                value: "192.168.1.32".to_string(),
            },
        );
        options.insert(
            "67".to_string(),
            DhcpOptionValue::String {
                value: "BOOT.EFI".to_string(),
            },
        );
        let dhcp = ConfigNetbootDhcpProfile {
            name: None,
            r#match: None,
            siaddr: Some("192.168.1.32".to_string()),
            boot_file: Some("BOOT.EFI".to_string()),
            options,
            pxe_boot: None,
            http_boot: None,
        };
        // server_ip (10.0.0.1) differs from siaddr (192.168.1.32) to verify
        // option 54 tracks server_ip, not siaddr.
        let pkt = build_proxy_dhcp_reply(
            MSG_OFFER,
            0xB768_25A7,
            [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
            Ipv4Addr::new(10, 0, 0, 1),
            &dhcp,
        )
        .unwrap();
        assert_eq!(dhcp_option(&pkt, 54), Some(&[10, 0, 0, 1][..]));
        // siaddr header field comes from the profile, not server_ip.
        assert_eq!(&pkt[20..24], &[192, 168, 1, 32]);
    }

    #[test]
    fn proxy_offer_explicit_option_54_not_overridden() {
        let mut options = BTreeMap::new();
        options.insert(
            "54".to_string(),
            DhcpOptionValue::Ipv4 {
                value: "10.0.0.1".to_string(),
            },
        );
        let dhcp = ConfigNetbootDhcpProfile {
            name: None,
            r#match: None,
            siaddr: Some("192.168.1.32".to_string()),
            boot_file: None,
            options,
            pxe_boot: None,
            http_boot: None,
        };
        let pkt =
            build_proxy_dhcp_reply(MSG_OFFER, 0, [0; 6], Ipv4Addr::new(192, 168, 1, 32), &dhcp)
                .unwrap();
        // Explicit option 54 wins over the server_ip default.
        assert_eq!(dhcp_option(&pkt, 54), Some(&[10, 0, 0, 1][..]));
    }

    #[test]
    fn proxy_offer_no_siaddr_defaults_to_server_ip() {
        // When neither siaddr nor option 54 are configured, both default to
        // server_ip.
        let dhcp = ConfigNetbootDhcpProfile {
            name: None,
            r#match: None,
            siaddr: None,
            boot_file: None,
            options: BTreeMap::new(),
            pxe_boot: None,
            http_boot: None,
        };
        let pkt =
            build_proxy_dhcp_reply(MSG_OFFER, 0, [0; 6], Ipv4Addr::new(192, 168, 1, 32), &dhcp)
                .unwrap();
        assert_eq!(dhcp_option(&pkt, 54), Some(&[192, 168, 1, 32][..]));
        assert_eq!(&pkt[20..24], &[192, 168, 1, 32]); // siaddr header
    }

    #[test]
    fn mac_match_full_and_prefix() {
        let client_hw = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let pkt = build_dhcp_discover(client_hw, &[]);
        let m_full = ConfigNetbootDhcpMatch {
            mac: vec!["aa:bb:cc:dd:ee:ff".to_string()],
            ..Default::default()
        };
        assert!(client_matches(&m_full, &pkt));
        let m_prefix = ConfigNetbootDhcpMatch {
            mac: vec!["aa:bb:cc".to_string()],
            ..Default::default()
        };
        assert!(client_matches(&m_prefix, &pkt));
        let m_nomatch = ConfigNetbootDhcpMatch {
            mac: vec!["11:22:33".to_string()],
            ..Default::default()
        };
        assert!(!client_matches(&m_nomatch, &pkt));
    }

    #[test]
    fn vendor_class_prefix_match() {
        let client_hw = [0; 6];
        let pkt = build_dhcp_discover(client_hw, &[(60, b"PXEClient:Arch:00007:UNDI:003016")]);
        let m = ConfigNetbootDhcpMatch {
            vendor_class: vec!["PXEClient".to_string()],
            ..Default::default()
        };
        assert!(client_matches(&m, &pkt));
        let m_http = ConfigNetbootDhcpMatch {
            vendor_class: vec!["HTTPClient".to_string()],
            ..Default::default()
        };
        assert!(!client_matches(&m_http, &pkt));
    }

    #[test]
    fn architecture_match() {
        let client_hw = [0; 6];
        let arch: [u8; 2] = 8u16.to_be_bytes(); // EFI x86-64
        let pkt = build_dhcp_discover(client_hw, &[(93, &arch)]);
        let m_ok = ConfigNetbootDhcpMatch {
            architecture: vec![8],
            ..Default::default()
        };
        assert!(client_matches(&m_ok, &pkt));
        let m_no = ConfigNetbootDhcpMatch {
            architecture: vec![16],
            ..Default::default()
        };
        assert!(!client_matches(&m_no, &pkt));
    }

    #[test]
    fn guid_match_hex_variants() {
        let client_hw = [0; 6];
        let guid = [0x01, 0x23, 0x45, 0x67];
        let pkt = build_dhcp_discover(client_hw, &[(97, &guid)]);
        let m = ConfigNetbootDhcpMatch {
            guid: vec!["01:23:45:67".to_string()],
            ..Default::default()
        };
        assert!(client_matches(&m, &pkt));
        let m2 = ConfigNetbootDhcpMatch {
            guid: vec!["01234567".to_string()],
            ..Default::default()
        };
        assert!(client_matches(&m2, &pkt));
        let m3 = ConfigNetbootDhcpMatch {
            guid: vec!["DE:AD:BE:EF".to_string()],
            ..Default::default()
        };
        assert!(!client_matches(&m3, &pkt));
    }

    #[test]
    fn empty_match_allows_everyone() {
        let client_hw = [0x12; 6];
        let pkt = build_dhcp_discover(client_hw, &[]);
        let m = ConfigNetbootDhcpMatch::default();
        assert!(client_matches(&m, &pkt));
    }

    #[test]
    fn select_profile_picks_by_architecture() {
        // Profile 0: PXE x64 (arch 8). Profile 1: HTTP x64 (arch 16).
        // Profile 2: catch-all (no match).
        let dhcp = ConfigNetbootDhcp {
            listen: None,
            profiles: vec![
                ConfigNetbootDhcpProfile {
                    name: Some("pxe-x64".into()),
                    r#match: Some(ConfigNetbootDhcpMatch {
                        architecture: vec![8],
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                ConfigNetbootDhcpProfile {
                    name: Some("http-x64".into()),
                    r#match: Some(ConfigNetbootDhcpMatch {
                        architecture: vec![16],
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                ConfigNetbootDhcpProfile {
                    name: Some("catch-all".into()),
                    ..Default::default()
                },
            ],
        };

        // An x64 PXE client (arch 8) selects the first profile.
        let arch8: [u8; 2] = 8u16.to_be_bytes();
        let pkt = build_dhcp_discover([0; 6], &[(93, &arch8)]);
        let p = select_profile(&dhcp, &pkt).expect("pxe profile matches");
        assert_eq!(p.name.as_deref(), Some("pxe-x64"));

        // An x64 HTTP client (arch 16) selects the second profile.
        let arch16: [u8; 2] = 16u16.to_be_bytes();
        let pkt = build_dhcp_discover([0; 6], &[(93, &arch16)]);
        let p = select_profile(&dhcp, &pkt).expect("http profile matches");
        assert_eq!(p.name.as_deref(), Some("http-x64"));
    }

    #[test]
    fn select_profile_falls_through_to_catch_all() {
        // A client whose architecture matches no specific profile falls through
        // to the catch-all (no `match`) listed last.
        let dhcp = ConfigNetbootDhcp {
            listen: None,
            profiles: vec![
                ConfigNetbootDhcpProfile {
                    name: Some("pxe-x64".into()),
                    r#match: Some(ConfigNetbootDhcpMatch {
                        architecture: vec![8],
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                ConfigNetbootDhcpProfile {
                    name: Some("catch-all".into()),
                    ..Default::default()
                },
            ],
        };
        // Architecture 7 (EFI x86) matches neither specific profile.
        let arch7: [u8; 2] = 7u16.to_be_bytes();
        let pkt = build_dhcp_discover([0; 6], &[(93, &arch7)]);
        let p = select_profile(&dhcp, &pkt).expect("catch-all matches");
        assert_eq!(p.name.as_deref(), Some("catch-all"));
    }

    #[test]
    fn select_profile_returns_none_when_no_profile_matches() {
        // No catch-all: an unmatched client gets no reply.
        let dhcp = ConfigNetbootDhcp {
            listen: None,
            profiles: vec![ConfigNetbootDhcpProfile {
                name: Some("pxe-x64".into()),
                r#match: Some(ConfigNetbootDhcpMatch {
                    architecture: vec![8],
                    ..Default::default()
                }),
                ..Default::default()
            }],
        };
        let arch16: [u8; 2] = 16u16.to_be_bytes();
        let pkt = build_dhcp_discover([0; 6], &[(93, &arch16)]);
        assert!(select_profile(&dhcp, &pkt).is_none());
    }

    #[test]
    fn split_cstr_parses_null_terminated() {
        assert_eq!(
            split_cstr(b"octet\0rest"),
            Some(("octet", b"rest".as_slice()))
        );
        assert_eq!(split_cstr(b"octet\0"), Some(("octet", b"".as_slice())));
        assert_eq!(split_cstr(b"nonull"), None);
    }

    #[test]
    fn tftp_error_packet_format() {
        let p = tftp_error(1, "file not found");
        assert_eq!(&p[..2], &TFTP_ERROR.to_be_bytes());
        assert_eq!(&p[2..4], &1u16.to_be_bytes());
        assert_eq!(&p[4..p.len() - 1], b"file not found");
        assert_eq!(*p.last().unwrap(), 0);
    }

    #[test]
    fn resolve_listen_bare_port_and_default() {
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        // bind_all = false (TFTP/HTTP): bind to the specific IP.
        assert_eq!(resolve_listen(None, ip, 67, false).unwrap(), "10.0.0.1:67");
        assert_eq!(
            resolve_listen(Some("69"), ip, 69, false).unwrap(),
            "10.0.0.1:69"
        );
        assert_eq!(
            resolve_listen(Some("10.0.0.1:8080"), ip, 80, false).unwrap(),
            "10.0.0.1:8080"
        );
        // bind_all = true (DHCP): default/bare-port bind to 0.0.0.0 to receive
        // broadcast DHCPDISCOVER/REQUEST packets.
        assert_eq!(resolve_listen(None, ip, 67, true).unwrap(), "0.0.0.0:67");
        assert_eq!(
            resolve_listen(Some("67"), ip, 67, true).unwrap(),
            "0.0.0.0:67"
        );
        // An explicit host:port is always honored as-is, even with bind_all.
        assert_eq!(
            resolve_listen(Some("10.0.0.1:8080"), ip, 80, true).unwrap(),
            "10.0.0.1:8080"
        );
    }

    /// End-to-end TFTP round-trip: bind a server socket, send an RRQ, receive
    /// the file contents back over the per-transfer ephemeral socket.
    #[test]
    fn tftp_server_serves_file() {
        let dir = tempdir();
        let payload = b"hello-tftp-payload-1234567890".to_vec();
        let hash_name = "tftpfile.bin";
        std::fs::write(dir.join(hash_name), &payload).unwrap();

        let server_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let running = Arc::new(AtomicBool::new(true));
        let tftp = ConfigNetbootTftp {
            listen: None,
            files: {
                let mut m = BTreeMap::new();
                m.insert("boot.img".to_string(), hash_name.to_string());
                m
            },
        };
        let dir = dir.clone();
        let running2 = running.clone();
        let handle = thread::spawn(move || {
            run_tftp_server(server_sock, &tftp, &dir, running2).unwrap();
        });

        // Client: send an RRQ for "boot.img" in octet mode.
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut rrq = Vec::new();
        rrq.extend_from_slice(&TFTP_RRQ.to_be_bytes());
        rrq.extend_from_slice(b"boot.img\0octet\0");
        client.send_to(&rrq, server_addr).unwrap();

        // Receive DATA blocks until a short block terminates the transfer.
        let mut received = Vec::new();
        let mut block = 1u16;
        let mut buf = [0u8; 600];
        loop {
            let (n, _) = client.recv_from(&mut buf).unwrap();
            let opcode = u16::from_be_bytes([buf[0], buf[1]]);
            assert_eq!(opcode, TFTP_DATA, "expected DATA, got opcode {opcode}");
            let blk = u16::from_be_bytes([buf[2], buf[3]]);
            assert_eq!(blk, block);
            received.extend_from_slice(&buf[4..n]);
            // ACK this block.
            let ack = [
                (TFTP_ACK >> 8) as u8,
                TFTP_ACK as u8,
                (blk >> 8) as u8,
                blk as u8,
            ];
            client.send_to(&ack, server_addr).unwrap();
            block += 1;
            if n - 4 < 512 {
                break; // final block
            }
        }
        assert_eq!(received, payload);

        running.store(false, Ordering::SeqCst);
        drop(client);
        drop(handle);
    }

    /// Regression test for the 16-bit TFTP block-number wraparound: a file
    /// larger than 65535 blocks must transfer correctly. Uses a tiny block
    /// size so the wrap happens at ~256 KiB instead of ~32 MiB.
    #[test]
    fn tftp_transfer_wraps_block_number_past_65535() {
        let block_size: usize = 4;
        // 65536 full blocks + a 2-byte trailing block → 65537 blocks total,
        // crossing the u16 boundary (block 65536 is sent as seq 0).
        let payload = vec![0xA5u8; 65536 * block_size + 2];
        let expected = payload.clone();

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_addr = client.local_addr().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let running = Arc::new(AtomicBool::new(true));
        let running2 = running.clone();
        let handle = thread::spawn(move || {
            tftp_transfer_blocks(&payload, client_addr, block_size, running2, None).unwrap();
        });

        let mut received = Vec::new();
        let mut block: u16 = 1;
        let mut buf = [0u8; 600];
        loop {
            let (n, peer) = client.recv_from(&mut buf).unwrap();
            let opcode = u16::from_be_bytes([buf[0], buf[1]]);
            assert_eq!(opcode, TFTP_DATA, "expected DATA, got opcode {opcode}");
            let blk = u16::from_be_bytes([buf[2], buf[3]]);
            assert_eq!(blk, block, "block seq mismatch at counter {block}");
            received.extend_from_slice(&buf[4..n]);
            let ack = [
                (TFTP_ACK >> 8) as u8,
                TFTP_ACK as u8,
                (blk >> 8) as u8,
                blk as u8,
            ];
            client.send_to(&ack, peer).unwrap();
            block = block.wrapping_add(1);
            if n - 4 < block_size {
                break; // final (short) block
            }
        }
        assert_eq!(received, expected);
        // Let the transfer thread observe the final ACK before we stop it.
        std::thread::sleep(Duration::from_millis(50));

        running.store(false, Ordering::SeqCst);
        drop(client);
        drop(handle);
    }

    /// End-to-end TFTP with option negotiation (OACK): a client that sends
    /// `tsize` and `blksize` options in the RRQ. The server must respond with
    /// an OACK, the client ACKs block 0, then DATA blocks flow with the
    /// negotiated block size.
    #[test]
    fn tftp_transfer_with_oack_options() {
        let block_size: usize = 32;
        let payload = vec![0x42u8; 100]; // 4 blocks of 32 + 1 trailing block of 4

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_addr = client.local_addr().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        // Build OACK + start transfer in a background thread.
        let (oack, neg_blksize) = negotiate_tftp_options(
            &[
                ("tsize".into(), "0".into()),
                ("blksize".into(), "32".into()),
            ],
            payload.len(),
        );
        assert_eq!(neg_blksize, 32);
        let oack = oack.expect("OACK should be produced for tsize+blksize");

        let running = Arc::new(AtomicBool::new(true));
        let running2 = running.clone();
        let value = payload.clone();
        let handle = thread::spawn(move || {
            tftp_transfer_blocks(&value, client_addr, neg_blksize, running2, Some(oack)).unwrap();
        });

        // Client: receive OACK, verify tsize, ACK block 0, then receive DATA.
        let mut buf = [0u8; 600];
        let (n, peer) = client.recv_from(&mut buf).unwrap();
        let opcode = u16::from_be_bytes([buf[0], buf[1]]);
        assert_eq!(opcode, TFTP_OACK, "expected OACK, got opcode {opcode}");
        let oack_str = String::from_utf8_lossy(&buf[2..n]);
        assert!(oack_str.contains("tsize"), "OACK should contain tsize");
        assert!(oack_str.contains("blksize"), "OACK should contain blksize");

        // ACK block 0 to confirm OACK.
        let ack0 = [(TFTP_ACK >> 8) as u8, TFTP_ACK as u8, 0, 0];
        client.send_to(&ack0, peer).unwrap();

        // Receive DATA blocks with negotiated block size.
        let mut received = Vec::new();
        let mut block: u16 = 1;
        loop {
            let (n, _) = client.recv_from(&mut buf).unwrap();
            let opcode = u16::from_be_bytes([buf[0], buf[1]]);
            assert_eq!(opcode, TFTP_DATA, "expected DATA, got opcode {opcode}");
            let blk = u16::from_be_bytes([buf[2], buf[3]]);
            assert_eq!(blk, block);
            received.extend_from_slice(&buf[4..n]);
            let ack = [
                (TFTP_ACK >> 8) as u8,
                TFTP_ACK as u8,
                (blk >> 8) as u8,
                blk as u8,
            ];
            client.send_to(&ack, peer).unwrap();
            block = block.wrapping_add(1);
            if n - 4 < block_size {
                break;
            }
        }
        assert_eq!(received, payload);

        running.store(false, Ordering::SeqCst);
        drop(client);
        drop(handle);
    }

    #[test]
    fn parse_tftp_options_extracts_pairs() {
        // "tsize\00\0blksize\01468\0"
        let payload = b"tsize\x000\x00blksize\x001468\x00";
        let opts = parse_tftp_options(payload);
        assert_eq!(opts.len(), 2);
        assert_eq!(opts[0].0, "tsize");
        assert_eq!(opts[0].1, "0");
        assert_eq!(opts[1].0, "blksize");
        assert_eq!(opts[1].1, "1468");
    }

    #[test]
    fn negotiate_tftp_options_caps_blksize() {
        // blksize above 65464 should be ignored.
        let (oack, bs) = negotiate_tftp_options(&[("blksize".into(), "99999".into())], 12345);
        assert!(
            oack.is_none(),
            "out-of-range blksize should produce no OACK"
        );
        assert_eq!(bs, 512);
    }

    /// End-to-end HTTP round-trip: bind a listener, issue a GET, read the body.
    #[test]
    fn http_server_serves_file() {
        use std::io::{Read, Write};
        let dir = tempdir();
        let payload = b"http-payload-body-abcdef".to_vec();
        let hash_name = "httpfile.bin";
        std::fs::write(dir.join(hash_name), &payload).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let running = Arc::new(AtomicBool::new(true));
        let http = ConfigNetbootHttp {
            listen: None,
            files: {
                let mut m = BTreeMap::new();
                m.insert("/rootfs".to_string(), hash_name.to_string());
                m
            },
        };
        let dir = dir.clone();
        let running2 = running.clone();
        let handle = thread::spawn(move || {
            run_http_server(listener, &http, &dir, running2).unwrap();
        });

        // Client: GET /rootfs.
        let mut conn = std::net::TcpStream::connect(addr).unwrap();
        conn.write_all(b"GET /rootfs HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let mut resp = Vec::new();
        conn.read_to_end(&mut resp).unwrap();
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(resp_str.contains("Content-Length: 24\r\n"));
        assert!(resp_str.ends_with("http-payload-body-abcdef"));

        // 404 for unknown path.
        let mut conn2 = std::net::TcpStream::connect(addr).unwrap();
        conn2
            .write_all(b"GET /nope HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let mut resp2 = Vec::new();
        conn2.read_to_end(&mut resp2).unwrap();
        assert!(String::from_utf8_lossy(&resp2).starts_with("HTTP/1.1 404 Not Found\r\n"));

        running.store(false, Ordering::SeqCst);
        drop(handle);
    }

    #[test]
    fn dhcp_pxe_bs_replies_unicast_to_source() {
        // On the PXE Boot Server port (4011), EDK2's BINL retry sends a unicast
        // DHCPDISCOVER and listens on its own source port for the reply. The
        // server must reply to the client's source address (not broadcast:68).
        let srv = UdpSocket::bind("127.0.0.1:0").unwrap();
        let srv_addr = srv.local_addr().unwrap();
        let mut options = BTreeMap::new();
        options.insert(
            "60".to_string(),
            DhcpOptionValue::String {
                value: "PXEClient".to_string(),
            },
        );
        let profile = ConfigNetbootDhcpProfile {
            name: Some("pxe-bs".to_string()),
            r#match: None,
            siaddr: Some("192.168.1.32".to_string()),
            boot_file: Some("BOOT.EFI".to_string()),
            options,
            pxe_boot: None,
            http_boot: None,
        };
        let dhcp_cfg = ConfigNetbootDhcp {
            listen: None,
            profiles: vec![profile],
        };
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();
        let handle = thread::spawn(move || {
            let _ = run_dhcp_server(
                srv,
                &dhcp_cfg,
                Ipv4Addr::new(192, 168, 1, 32),
                running_clone,
                true,
            );
        });

        // Client sends a DISCOVER from its own ephemeral port.
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let discover = build_dhcp_discover([0x52, 0x54, 0x00, 0x12, 0x34, 0x56], &[]);
        client.send_to(&discover, srv_addr).unwrap();

        let mut buf = [0u8; 1024];
        let (n, from) = client.recv_from(&mut buf).unwrap();
        let reply = &buf[..n];

        // The reply must come from the server address, not broadcast.
        assert_eq!(from, srv_addr);
        // It must be an OFFER with the bootfile in the `file` header field.
        assert_eq!(dhcp_option(reply, 53), Some(&[MSG_OFFER][..]));
        let file_field = &reply[108..108 + 8];
        assert_eq!(file_field, b"BOOT.EFI");

        running.store(false, Ordering::SeqCst);
        // Unblock the server's recv_from by sending a dummy packet.
        let _ = UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .send_to(&[0u8; 240], srv_addr);
        let _ = handle.join();
    }

    /// Minimal temp dir helper for unit tests.
    fn tempdir() -> PathBuf {
        static C: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = C.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("sysimg-netboot-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
