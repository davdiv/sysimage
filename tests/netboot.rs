//! Netboot: config parsing/expansion, preset expansion, build manifest, and
//! schema validation for the new optional-server / generic-option model.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use sysimage::build::build_from_file;
use sysimage::config::{read_config, validate_and_expand_config};
use sysimage::model::schema::{config_schema, manifest_schema};
use sysimage::validate::validate;

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("sysimg-netboot-{}-{n}", std::process::id()));
        fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
static COUNTER: AtomicU64 = AtomicU64::new(0);

fn write_temp_config(contents: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let n = std::process::id();
    static C: AtomicU64 = AtomicU64::new(0);
    let c = C.fetch_add(1, Ordering::SeqCst);
    path.push(format!("sysimg-netboot-cfg-{n}-{c}.yml"));
    fs::write(&path, contents).unwrap();
    path
}

/// The new model: each of dhcp/tftp/http is optional, DHCP options are a
/// generic typed map, and `match` filters clients.
#[test]
fn parses_and_expands_netboot_config() {
    let path = write_temp_config(
        r#"
name: nbimg
arch: x86_64
netboot:
  dhcp:
    listen: "${NETBOOT_IP}:67"
    profiles:
      - siaddr: "${NETBOOT_IP}"
        bootFile: "BOOTX64.EFI"
        options:
          "54": { type: ipv4, value: "${NETBOOT_IP}" }
          "60": { type: string, value: "PXEClient" }
          "67": { type: string, value: "BOOTX64.EFI" }
          "43":
            type: vendorOptions
            value:
              "5": "/"
        match:
          vendorClass: ["PXEClient"]
          architecture: [8]
  tftp:
    listen: "69"
    files:
      "BOOTX64.EFI": "build:uki:bootimage"
  http:
    files:
      "/rootfs.erofs": "build:erofs:rootfs"
"#,
    );
    let with_dir = read_config(&path).expect("read netboot config");
    let expanded = validate_and_expand_config(&with_dir).expect("expand netboot config");
    let nb = expanded.config.netboot.as_ref().expect("netboot present");

    // Each server is independently optional; http has no `listen` (defaults at
    // runtime to ${NETBOOT_IP}:80).
    assert!(nb.dhcp.is_some());
    assert!(nb.tftp.is_some());
    assert!(nb.http.is_some());
    assert!(nb.http.as_ref().unwrap().listen.is_none());

    let dhcp = nb.dhcp.as_ref().unwrap();
    assert_eq!(dhcp.listen.as_deref(), Some("${NETBOOT_IP}:67"));
    assert_eq!(dhcp.profiles.len(), 1);
    let p = &dhcp.profiles[0];
    assert_eq!(p.siaddr.as_deref(), Some("${NETBOOT_IP}"));
    assert_eq!(p.boot_file.as_deref(), Some("BOOTX64.EFI"));
    // Generic options map.
    assert!(p.options.contains_key("54"));
    assert!(p.options.contains_key("60"));
    assert!(p.options.contains_key("67"));
    assert!(p.options.contains_key("43"));
    // Match filter.
    let m = p.r#match.as_ref().expect("match present");
    assert_eq!(m.vendor_class, vec!["PXEClient".to_string()]);
    assert_eq!(m.architecture, vec![8]);

    // No IP literal anywhere — only ${NETBOOT_IP}.
    let json = serde_json::to_string(nb).unwrap();
    assert!(!json.contains("192.168."));
    assert!(json.contains("${NETBOOT_IP}"));

    let _ = std::fs::remove_file(&path);
}

/// A netboot section with only an HTTP server (no dhcp, no tftp) is valid.
#[test]
fn parses_netboot_with_only_http() {
    let path = write_temp_config(
        r#"
name: nbimg
arch: x86_64
netboot:
  http:
    files:
      "/boot.efi": "file:boot.efi"
"#,
    );
    let with_dir = read_config(&path).expect("read config");
    let expanded = validate_and_expand_config(&with_dir).expect("expand");
    let nb = expanded.config.netboot.as_ref().expect("netboot present");
    assert!(nb.dhcp.is_none());
    assert!(nb.tftp.is_none());
    assert!(nb.http.is_some());
    let _ = std::fs::remove_file(&path);
}

/// The `httpBoot` preset (inside a `dhcp.profiles[]` entry) is carried through
/// parse/expand and expands into the generic DHCP options map at build time.
#[test]
fn http_boot_preset_expands_into_options() {
    let path = write_temp_config(
        r#"
name: nbimg
arch: x86_64
netboot:
  dhcp:
    profiles:
      - httpBoot:
          bootUrl: "http://${NETBOOT_IP}/boot.efi"
          architectures: [16]
  http:
    files:
      "/boot.efi": "file:boot.efi"
"#,
    );
    let with_dir = read_config(&path).expect("read config");
    let expanded = validate_and_expand_config(&with_dir).expect("expand");
    let nb = expanded.config.netboot.as_ref().expect("netboot present");
    // Preset expansion happens at BUILD time, not at parse/expand time, so the
    // preset is still present here. The build test below checks the manifest.
    let p = &nb.dhcp.as_ref().expect("dhcp present").profiles[0];
    assert!(p.http_boot.is_some());
    let _ = std::fs::remove_file(&path);
}

/// The `pxeBoot` preset (inside a `dhcp.profiles[]` entry) is carried through
/// parse/expand and expands into DHCP header fields + options at build time.
#[test]
fn pxe_boot_preset_expands_into_options() {
    let path = write_temp_config(
        r#"
name: nbimg
arch: x86_64
netboot:
  dhcp:
    profiles:
      - pxeBoot:
          bootFile: "BOOTX64.EFI"
          nextServer: "${NETBOOT_IP}"
          architectures: [8]
  tftp:
    files:
      "BOOTX64.EFI": "file:boot.efi"
"#,
    );
    let with_dir = read_config(&path).expect("read config");
    let expanded = validate_and_expand_config(&with_dir).expect("expand");
    let nb = expanded.config.netboot.as_ref().expect("netboot present");
    let p = &nb.dhcp.as_ref().expect("dhcp present").profiles[0];
    assert!(p.pxe_boot.is_some());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn schema_accepts_valid_netboot_config() {
    let cfg = serde_json::json!({
        "name": "demo",
        "netboot": {
            "dhcp": {
                "listen": "${NETBOOT_IP}:67",
                "profiles": [
                    {
                        "siaddr": "${NETBOOT_IP}",
                        "bootFile": "boot.efi",
                        "options": {
                            "54": { "type": "ipv4", "value": "${NETBOOT_IP}" },
                            "60": { "type": "string", "value": "HTTPClient" }
                        }
                    }
                ]
            },
            "tftp": { "files": { "boot.efi": "file:boot.efi" } },
            "http": { "files": { "/k": "file:k" } }
        }
    });
    validate(&cfg, &config_schema()).expect("valid netboot config should pass");
}

#[test]
fn schema_accepts_http_boot_preset() {
    let cfg = serde_json::json!({
        "name": "demo",
        "netboot": {
            "dhcp": {
                "profiles": [
                    { "httpBoot": { "bootUrl": "http://${NETBOOT_IP}/b.efi", "architectures": [16] } }
                ]
            },
            "http": { "files": { "/b.efi": "file:b.efi" } }
        }
    });
    validate(&cfg, &config_schema()).expect("httpBoot preset should pass schema");
}

#[test]
fn schema_rejects_unknown_netboot_field() {
    let cfg = serde_json::json!({
        "name": "demo",
        "netboot": {
            "bogus": 1,
            "dhcp": { "profiles": [ { "options": { "60": { "type": "string", "value": "x" } } } ] }
        }
    });
    let err = validate(&cfg, &config_schema()).expect_err("expected validation error");
    let msg = err.to_string();
    assert!(
        msg.contains("Additional properties are not allowed"),
        "error {msg:?} should mention additional properties"
    );
}

#[test]
fn schema_rejects_unknown_dhcp_field() {
    let cfg = serde_json::json!({
        "name": "demo",
        "netboot": {
            "dhcp": {
                "bogus": 1,
                "profiles": [ { "options": { "60": { "type": "string", "value": "x" } } } ]
            }
        }
    });
    let err = validate(&cfg, &config_schema()).expect_err("expected validation error");
    assert!(
        err.to_string()
            .contains("Additional properties are not allowed")
    );
}

#[test]
fn schema_rejects_old_fixed_dhcp_fields() {
    // The old top-level `dhcp` fields (`serverId`/`bootFile`/`vendorClass`/
    // `siaddr`/`options`/`match`) no longer exist on `dhcp` — they moved under
    // `dhcp.profiles[...]`. The schema must reject them so configs are migrated
    // to the new model.
    let cfg = serde_json::json!({
        "name": "demo",
        "netboot": {
            "dhcp": { "serverId": "10.0.0.1", "bootFile": "boot.efi" }
        }
    });
    let err = validate(&cfg, &config_schema()).expect_err("old fields should be rejected");
    assert!(
        err.to_string()
            .contains("Additional properties are not allowed")
    );
}

/// Build a config with a netboot section referencing real files, and verify
/// the manifest carries the netboot section with content-addressed hash file
/// names (and the corresponding `.bin` files exist in the output directory),
/// and that the `pxeBoot` preset has been expanded into the generic options.
#[test]
fn build_emits_netboot_with_hash_file_names() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    fs::create_dir_all(rootfs.join("etc")).unwrap();
    fs::write(
        rootfs.join("etc").join("passwd"),
        "root:x:0:0:root:/root:/bin/sh\n",
    )
    .unwrap();
    fs::write(rootfs.join("hello.txt"), "hello netboot\n").unwrap();
    fs::create_dir_all(rootfs.join("boot")).unwrap();
    // A fake boot file to serve over TFTP and HTTP.
    let boot_payload = b"FAKE-BOOTLOADER-BYTES".to_vec();
    fs::write(rootfs.join("bootloader.efi"), &boot_payload).unwrap();

    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = format!(
        r#"
name: nbimg
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  erofs:
    rootfs:
      input:
        - destination: ""
          input: "."
disk:
  boot:
    type: gpt
    partitions:
      - name: esp
        type: C12A7328-F81F-11D2-BA4B-00A0C93EC93B
        content:
          type: fat
          files:
            - destination: "test.txt"
              input: hello.txt
netboot:
  dhcp:
    profiles:
      - pxeBoot:
          bootFile: "bootloader.efi"
          nextServer: "${{NETBOOT_IP}}"
          architectures: [8]
  tftp:
    listen: "${{NETBOOT_IP}}:69"
    files:
      "bootloader.efi": "file:bootloader.efi"
  http:
    listen: "${{NETBOOT_IP}}:8080"
    files:
      "/boot.efi": "file:bootloader.efi"
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();

    build_from_file(&config_path).expect("build should succeed");

    // Read the manifest JSON.
    let symlink = output.join("nbimg.json");
    let manifest_path = if symlink.exists() {
        symlink
    } else {
        let mut found = None;
        for entry in fs::read_dir(&output).unwrap() {
            let entry = entry.unwrap();
            let fname = entry.file_name().to_string_lossy().into_owned();
            if fname.starts_with("nbimg-") && fname.ends_with(".json") {
                found = Some(entry.path());
                break;
            }
        }
        found.expect("a manifest json should have been written")
    };
    let text = fs::read_to_string(&manifest_path).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&text).unwrap();
    validate(&manifest, &manifest_schema()).expect("built manifest should validate");

    let nb = manifest.get("netboot").expect("manifest has netboot");
    // The pxeBoot preset has been consumed: it is absent from the manifest.
    assert!(
        nb.get("pxeBoot").is_none(),
        "pxeBoot preset should be expanded and dropped from the manifest"
    );
    // A dhcp section was created by the preset expansion (shorthand: single
    // profile matched on vendor class "PXEClient").
    let dhcp = nb.get("dhcp").expect("preset should create a dhcp section");
    let p = &dhcp["profiles"][0];
    assert_eq!(p["siaddr"], "${NETBOOT_IP}");
    assert_eq!(p["bootFile"], "bootloader.efi");
    // The preset adds a match on vendor class "PXEClient" so it only answers
    // PXE clients, not every DHCP request.
    assert_eq!(p["match"]["vendorClass"][0], "PXEClient");
    // Option 60 defaults to "PXEClient"; option 67 mirrors bootFile; option 93
    // carries the architecture.
    assert_eq!(p["options"]["60"]["value"], "PXEClient");
    assert_eq!(p["options"]["67"]["value"], "bootloader.efi");
    assert_eq!(p["options"]["93"]["value"], 8);

    // No literal IP — only ${NETBOOT_IP}.
    let nb_str = serde_json::to_string(nb).unwrap();
    assert!(!nb_str.contains("192.168."));
    assert!(nb_str.contains("${NETBOOT_IP}"));

    // TFTP/HTTP file values are now content-addressed hash file names, not the
    // original input specifiers.
    let tftp_hash = nb["tftp"]["files"]["bootloader.efi"].as_str().unwrap();
    let http_hash = nb["http"]["files"]["/boot.efi"].as_str().unwrap();
    assert!(
        tftp_hash.ends_with(".bin"),
        "tftp value should be a .bin hash name, got {tftp_hash}"
    );
    assert!(
        http_hash.ends_with(".bin"),
        "http value should be a .bin hash name, got {http_hash}"
    );
    // Both reference the same source file -> same hash.
    assert_eq!(tftp_hash, http_hash);

    // The hash file is recorded in the manifest `file` map and exists on disk.
    let file_entry = &manifest["file"][tftp_hash];
    assert!(file_entry["size"].as_u64().unwrap_or(0) > 0);
    assert!(file_entry["hash"].as_str().unwrap().len() == 64); // sha-256 hex
    let bin_path = output.join(tftp_hash);
    assert!(
        bin_path.exists(),
        "content-addressed file {tftp_hash} should exist in output"
    );
    assert_eq!(fs::read(&bin_path).unwrap(), boot_payload);
}

/// Build with an `httpBoot` preset and verify the manifest carries option 60 =
/// "HTTPClient" and option 67 = the boot URL (UEFI HTTP boot).
#[test]
fn build_expands_http_boot_preset() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();
    let boot_payload = b"UEFI-HTTP-BOOT-EFI".to_vec();
    fs::write(rootfs.join("boot.efi"), &boot_payload).unwrap();

    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = format!(
        r#"
name: nbhttp
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  erofs:
    rootfs:
      input:
        - destination: ""
          input: "."
disk:
  boot:
    type: gpt
    partitions:
      - name: esp
        type: C12A7328-F81F-11D2-BA4B-00A0C93EC93B
        content:
          type: fat
          files:
            - destination: "x"
              input: boot.efi
netboot:
  dhcp:
    profiles:
      - httpBoot:
          bootUrl: "http://${{NETBOOT_IP}}/boot.efi"
          architectures: [16]
  http:
    files:
      "/boot.efi": "file:boot.efi"
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();

    build_from_file(&config_path).expect("build should succeed");

    let symlink = output.join("nbhttp.json");
    let manifest_path = if symlink.exists() {
        symlink
    } else {
        let mut found = None;
        for entry in fs::read_dir(&output).unwrap() {
            let entry = entry.unwrap();
            let fname = entry.file_name().to_string_lossy().into_owned();
            if fname.starts_with("nbhttp-") && fname.ends_with(".json") {
                found = Some(entry.path());
                break;
            }
        }
        found.expect("a manifest json should have been written")
    };
    let text = fs::read_to_string(&manifest_path).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&text).unwrap();
    validate(&manifest, &manifest_schema()).expect("built manifest should validate");

    let nb = manifest.get("netboot").expect("manifest has netboot");
    assert!(
        nb.get("httpBoot").is_none(),
        "httpBoot preset should be consumed"
    );
    let dhcp = nb
        .get("dhcp")
        .expect("httpBoot should create a dhcp section");
    let p = &dhcp["profiles"][0];
    // The preset adds a match on vendor class "HTTPClient" so it only answers
    // HTTP-boot clients.
    assert_eq!(p["match"]["vendorClass"][0], "HTTPClient");
    // siaddr is not set by the preset — build_proxy_dhcp_reply defaults it
    // to the server's own IP at runtime.
    assert!(p.get("siaddr").is_none() || p["siaddr"].is_null());
    // Option 60 = "HTTPClient" (UEFI HTTP boot vendor class).
    assert_eq!(p["options"]["60"]["value"], "HTTPClient");
    // Option 67 (bootfile name) = boot URL. EDK2's HttpBootDxe reads the boot
    // URI from option 67 (or the `file` header field), NOT from option 43.
    assert_eq!(p["options"]["67"]["value"], "http://${NETBOOT_IP}/boot.efi");
    // The `file` header field is also set to the boot URL (fallback path).
    assert_eq!(p["bootFile"], "http://${NETBOOT_IP}/boot.efi");
    // Option 93 = 16 (x64 UEFI HTTP boot).
    assert_eq!(p["options"]["93"]["value"], 16);
    // The boot file is served over HTTP.
    let http_hash = nb["http"]["files"]["/boot.efi"].as_str().unwrap();
    assert!(http_hash.ends_with(".bin"));
    assert!(output.join(http_hash).exists());
}

/// Build with multiple `dhcp.profiles` (a pxeBoot profile and an httpBoot
/// profile) and verify the manifest carries both, each preset expanded into
/// its own options and selected per-request by `match`.
#[test]
fn build_expands_multiple_profiles() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    fs::create_dir_all(rootfs.join("boot")).unwrap();
    let boot_payload = b"FAKE-BOOTLOADER-BYTES".to_vec();
    fs::write(rootfs.join("bootloader.efi"), &boot_payload).unwrap();

    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = format!(
        r#"
name: nbmulti
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
disk:
  boot:
    type: gpt
    partitions:
      - name: esp
        type: C12A7328-F81F-11D2-BA4B-00A0C93EC93B
        content:
          type: fat
          files:
            - destination: "test.txt"
              input: bootloader.efi
netboot:
  dhcp:
    listen: "${{NETBOOT_IP}}:67"
    profiles:
      - name: pxe-x64
        pxeBoot:
          bootFile: "bootloader.efi"
          nextServer: "${{NETBOOT_IP}}"
          architectures: [8]
        match:
          architecture: [8]
      - name: http-x64
        httpBoot:
          bootUrl: "http://${{NETBOOT_IP}}/boot.efi"
          architectures: [16]
        match:
          architecture: [16]
  tftp:
    listen: "${{NETBOOT_IP}}:69"
    files:
      "bootloader.efi": "file:bootloader.efi"
  http:
    listen: "${{NETBOOT_IP}}:8080"
    files:
      "/boot.efi": "file:bootloader.efi"
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();

    build_from_file(&config_path).expect("build should succeed");

    let symlink = output.join("nbmulti.json");
    let manifest_path = if symlink.exists() {
        symlink
    } else {
        let mut found = None;
        for entry in fs::read_dir(&output).unwrap() {
            let entry = entry.unwrap();
            let fname = entry.file_name().to_string_lossy().into_owned();
            if fname.starts_with("nbmulti-") && fname.ends_with(".json") {
                found = Some(entry.path());
                break;
            }
        }
        found.expect("a manifest json should have been written")
    };
    let text = fs::read_to_string(&manifest_path).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&text).unwrap();
    validate(&manifest, &manifest_schema()).expect("built manifest should validate");

    let nb = manifest.get("netboot").expect("manifest has netboot");
    // No top-level presets remain — both were consumed into profiles.
    assert!(nb.get("pxeBoot").is_none());
    assert!(nb.get("httpBoot").is_none());
    let dhcp = nb.get("dhcp").expect("dhcp section present");
    let profiles = dhcp["profiles"].as_array().expect("profiles is a list");
    assert_eq!(profiles.len(), 2, "two profiles expanded");

    // Profile 0: PXE x64.
    let pxe = &profiles[0];
    assert_eq!(pxe["name"], "pxe-x64");
    assert_eq!(pxe["match"]["architecture"][0], 8);
    // The pxeBoot preset adds a vendor-class match ("PXEClient") on top of the
    // user-configured architecture match.
    assert_eq!(pxe["match"]["vendorClass"][0], "PXEClient");
    assert_eq!(pxe["siaddr"], "${NETBOOT_IP}");
    assert_eq!(pxe["bootFile"], "bootloader.efi");
    assert_eq!(pxe["options"]["60"]["value"], "PXEClient");
    assert_eq!(pxe["options"]["67"]["value"], "bootloader.efi");
    assert_eq!(pxe["options"]["93"]["value"], 8);

    // Profile 1: HTTP x64.
    let http = &profiles[1];
    assert_eq!(http["name"], "http-x64");
    assert_eq!(http["match"]["architecture"][0], 16);
    // The httpBoot preset adds a vendor-class match ("HTTPClient") on top of
    // the user-configured architecture match.
    assert_eq!(http["match"]["vendorClass"][0], "HTTPClient");
    // siaddr is not set by the httpBoot preset — build_proxy_dhcp_reply
    // defaults it to the server's own IP at runtime.
    assert!(http.get("siaddr").is_none() || http["siaddr"].is_null());
    assert_eq!(http["options"]["60"]["value"], "HTTPClient");
    // Option 67 = boot URL (EDK2 reads the URI from option 67, not option 43).
    assert_eq!(
        http["options"]["67"]["value"],
        "http://${NETBOOT_IP}/boot.efi"
    );
    // The `file` header field is also set to the boot URL.
    assert_eq!(http["bootFile"], "http://${NETBOOT_IP}/boot.efi");
    assert_eq!(http["options"]["93"]["value"], 16);
}
