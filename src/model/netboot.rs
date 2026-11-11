//! Network-boot configuration type definitions.
//!
//! These types describe the optional `netboot` section of the user config,
//! carried through the manifest. The DHCP settings are passed through
//! unchanged; the TFTP/HTTP `files` maps change meaning between the two
//! documents:
//!
//! - In the **user config**, each `files` value is an *input specifier*
//!   (`build:…`, `file:…`, `podman:…` or a plain path) resolved through the
//!   input manager at build time, exactly like a QEMU firmware `code`/`vars`
//!   specifier.
//! - In the **manifest**, each `files` value is the content-addressed hash
//!   file name (a `<base64url-no-pad>.bin` entry of the manifest `file` map)
//!   produced by the build. At `sysimage netboot` time the bytes are read from
//!   `<manifest-directory>/<hash-file-name>`.
//!
//! This mirrors the [`crate::model::qemu`] firmware convention (same struct
//! reused for config and manifest, with documented meaning changes), so the
//! JSON Schema is generated from these structs automatically.
//!
//! # No IP addresses in the manifest
//!
//! None of these types should contain a literal IP address in the manifest:
//! anything that depends on the running host's address is written using the
//! `${NETBOOT_IP}` variable, which is resolved at `sysimage netboot` time from
//! the network interface the server is bound to (see [`crate::netboot`]).
//!
//! All implementation (the DHCP/TFTP/HTTP server pipeline, preset expansion,
//! client matching, interface-IP resolution) lives in [`crate::netboot`] and
//! [`crate::build::context`]; this module contains **only** type definitions.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The optional `netboot` section: configures the DHCP + TFTP + HTTP server set
/// started by `sysimage netboot` to serve built artifacts to PXE/UEFI clients.
///
/// Each of the three servers (`dhcp`, `tftp`, `http`) is independently optional
/// — only the configured ones are started. The `pxeBoot`/`httpBoot` convenience
/// presets live **inside `dhcp.profiles[]`** ([`ConfigNetbootDhcpProfile`]):
/// each preset expands at build time into that profile's `options` map (and
/// header fields) **and** adds a `match` filter on the relevant vendor class
/// (option 60) so the profile only answers clients booting via that method.
/// They are consumed at build time and never appear in the manifest.
///
/// To serve several boot kinds at once (e.g. PXE **and** HTTP boot), list one
/// [`ConfigNetbootDhcp::profiles`] entry per preset — each profile carries its
/// own [`match`](ConfigNetbootDhcpProfile::r#match) filter and preset, and the
/// server replies with the first profile that matches the incoming request.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigNetboot {
    /// Proxy DHCP server settings. The proxy DHCP server **does not** assign IP
    /// addresses — another DHCP server on the network handles lease management.
    /// This server only provides netboot-related options so PXE/UEFI/Raspberry
    /// Pi clients can discover where to download boot files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dhcp: Option<ConfigNetbootDhcp>,
    /// TFTP server settings. TFTP serves the boot loader / kernel / initrd to
    /// clients (the standard PXE download path).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tftp: Option<ConfigNetbootTftp>,
    /// HTTP server settings. HTTP serves larger artifacts (rootfs images,
    /// kernel, initrd) referenced by the boot loader or kernel command line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<ConfigNetbootHttp>,
}

/// DHCPv4 proxy DHCP server settings.
///
/// The server operates as a **PXE proxy DHCP** (RFC 5071): it does **not**
/// assign IP addresses or manage leases — another DHCP server on the network
/// handles that. This server only answers DHCPDISCOVER/DHCPREQUEST with the
/// netboot-related options, so a client can discover where to download its
/// boot files. The reply carries `yiaddr = 0.0.0.0` (no IP offered).
///
/// A single socket (configured by [`listen`](Self::listen)) serves every
/// request. The actual reply is selected per request from the ordered
/// [`profiles`](Self::profiles) list: the server walks it in order and replies
/// with the first profile whose [`match`](ConfigNetbootDhcpProfile::r#match)
/// filter passes (a profile with no `match` is a catch-all — put it last). This
/// lets one `sysimage netboot` instance serve PXE, UEFI HTTP boot and other
/// clients simultaneously, discriminating by option 60/93/97/MAC/etc.
///
/// Option 53 (message type) is always injected automatically per reply and
/// must not be set explicitly. Option 54 (server identifier), if set, must be
/// the same across all profiles — it identifies *this* proxy server. Use the
/// `${NETBOOT_IP}` variable in any value that should reflect the server's
/// bound address.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigNetbootDhcp {
    /// Socket address to bind the proxy DHCP server to. Accepts a full
    /// `host:port` (e.g. `${NETBOOT_IP}:67`), a bare port (`67`, bound to the
    /// netboot IP), or `None` (defaults to `${NETBOOT_IP}:67`). `${NETBOOT_IP}`
    /// is resolved at `sysimage netboot` time. This is a single shared socket
    /// for all profiles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    /// Ordered list of selectable DHCP profiles. For each incoming request the
    /// server picks the first profile whose `match` filter passes. Must be
    /// non-empty (validated at build time).
    #[serde(default)]
    pub profiles: Vec<ConfigNetbootDhcpProfile>,
}

/// One selectable DHCP profile: a full proxy-DHCP reply template plus the
/// `match` filter that decides which clients it answers.
///
/// A profile carries either a convenience preset ([`pxe_boot`](Self::pxe_boot)
/// / [`http_boot`](Self::http_boot)), which expands at build time into
/// [`siaddr`](Self::siaddr)/[`boot_file`](Self::boot_file)/[`options`](Self::options),
/// or a fully manual [`options`](Self::options) map. At most one preset may be
/// set per profile (enforced at build time); explicit `options`/`siaddr`/
/// `bootFile` always win over the preset.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigNetbootDhcpProfile {
    /// Optional human-readable label used in server logs, e.g. `"pxe-x64"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Selection filter: a request matches this profile only if it passes
    /// every set (non-empty) criterion. When `None` (or with all lists empty)
    /// the profile matches every client — a catch-all, normally placed last.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "match")]
    #[schemars(rename = "match")]
    pub r#match: Option<ConfigNetbootDhcpMatch>,
    /// DHCP header field `siaddr` — the "next server" (TFTP/HTTP server)
    /// address clients download the boot file from. Typically `${NETBOOT_IP}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub siaddr: Option<String>,
    /// DHCP header field `file` — the boot file name (up to 127 bytes), e.g.
    /// `BOOTX64.EFI`. Also mirrored as option 67 unless option 67 is set
    /// explicitly in [`options`](Self::options).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_file: Option<String>,
    /// Generic DHCP options, keyed by the option code as a string-encoded
    /// number (`"54"`, `"67"`, `"43"`, …). Each value is a typed
    /// [`DhcpOptionValue`] descriptor. Option 53 (message type) is managed
    /// automatically and must not appear here.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub options: BTreeMap<String, DhcpOptionValue>,
    /// Convenience preset for PXE/TFTP boot. Expands at build time into
    /// `siaddr`/`bootFile` and options 60/66/67/93, and adds a `match` filter
    /// on the vendor class (option 60, default `"PXEClient"`) so the profile
    /// only answers PXE clients. Mutually exclusive with
    /// [`http_boot`](Self::http_boot). Requires a `tftp` server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pxe_boot: Option<ConfigNetbootPxeBoot>,
    /// Convenience preset for UEFI HTTP boot. Expands at build time into
    /// options 60/43/93 and adds a `match` filter on the vendor class
    /// (option 60 = `"HTTPClient"`) so the profile only answers HTTP-boot
    /// clients. Mutually exclusive with
    /// [`pxe_boot`](Self::pxe_boot). Requires an `http` server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_boot: Option<ConfigNetbootHttpBoot>,
}

/// A typed DHCP option value. The `type` tag selects the wire encoding.
///
/// `array` concatenates the encoded bytes of its entries (useful for options
/// that pack several values, e.g. option 119 domain search list). `vendorOptions`
/// encodes an option-43-style blob of nested `code|len|value` sub-TLVs (the map
/// key is the suboption code as a string number).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum DhcpOptionValue {
    /// UTF-8 string bytes.
    String { value: String },
    /// IPv4 dotted-quad (e.g. `"${NETBOOT_IP}"`), encoded as 4 octets.
    Ipv4 { value: String },
    /// A single unsigned byte.
    U8 { value: u8 },
    /// A big-endian 16-bit unsigned integer.
    U16 { value: u16 },
    /// A big-endian 32-bit unsigned integer.
    U32 { value: u32 },
    /// Raw bytes, given as a colon-separated hex string (e.g. `"01:02:03"`).
    Bytes { value: String },
    /// Concatenation of several typed values (their encodings are appended in
    /// order). Useful for multi-valued options.
    Array { value: Vec<DhcpOptionValue> },
    /// A set of vendor-specific sub-options (option 43 style): the map key is
    /// the suboption code as a string number, the value is its string payload.
    /// Encoded as a sequence of `code|len|value` TLVs.
    VendorOptions { value: BTreeMap<String, String> },
}

/// Allowlist filters restricting which DHCP clients receive a reply. Every
/// set list is an allowlist; an empty/absent list imposes no constraint. A
/// request matches only if it passes **all** set filters.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigNetbootDhcpMatch {
    /// Allowed client MAC addresses. Each entry is either a full address
    /// (`"aa:bb:cc:dd:ee:ff"`) or an OUI prefix (`"aa:bb:cc"`). Matched against
    /// the DHCP `chaddr` field.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mac: Vec<String>,
    /// Allowed option 60 (vendor class identifier) values, matched as a
    /// prefix so `"PXEClient"` also matches `"PXEClient:Arch:…"`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vendor_class: Vec<String>,
    /// Allowed option 93 (client system architecture) codes, e.g. `[8]` for
    /// EFI x86-64 PXE or `[16]` for x64 UEFI HTTP boot.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub architecture: Vec<u16>,
    /// Allowed option 97 (client machine GUID) values, as lowercase hex with
    /// or without `:` separators.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub guid: Vec<String>,
    /// Allowed option 77 (user class) values.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub user_class: Vec<String>,
    /// Allowed option 61 (client identifier) values, as lowercase hex with or
    /// without `:` separators.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub client_id: Vec<String>,
}

/// Convenience preset for UEFI HTTP boot (UEFI 2.x §24.7). At build time this expands into the DHCP
/// `options` map and adds a `match` filter on the vendor class (option 60 =
/// `"HTTPClient"`) so the profile only answers HTTP-boot clients. The
/// manifest only carries the generic, already-expanded options. Requires
/// an `http` server entry to serve the boot file.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigNetbootHttpBoot {
    /// Boot file URL the client downloads over HTTP, e.g.
    /// `http://${NETBOOT_IP}/boot.efi`. Carried in DHCP option 67 (bootfile
    /// name) and the `file` header field — the delivery path EDK2's
    /// `HttpBootDxe` actually reads.
    pub boot_url: String,
    /// Client architecture types to advertise in option 93, as raw codes.
    /// Per the UEFI spec: `15` = x86 UEFI HTTP boot, `16` = x64 UEFI HTTP boot.
    /// When empty, option 93 is omitted (the client already knows its arch).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub architectures: Vec<u16>,
}

/// PXE/TFTP boot preset. At build time this expands into the DHCP header
/// fields (`siaddr`, `bootFile`) and options (60, 66, 67, 93), and adds a
/// `match` filter on the vendor class (option 60, default `"PXEClient"`) so
/// the profile only answers PXE clients. Requires a `tftp` server entry to
/// serve the boot file.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigNetbootPxeBoot {
    /// Boot file name (the TFTP filename), e.g. `BOOTX64.EFI`. Goes into the
    /// `file` header field and option 67.
    pub boot_file: String,
    /// TFTP "next server" IP (option 66 / `siaddr` header). Defaults to
    /// `${NETBOOT_IP}` (resolved at `sysimage netboot` time to the address of
    /// the interface the server is bound to).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_server: Option<String>,
    /// Vendor class identifier (option 60). Defaults to `"PXEClient"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor_class: Option<String>,
    /// Client architecture types to advertise in option 93, as raw codes.
    /// Per RFC 4578: `6` = EFI x86 (IA32), `8` = EFI x86-64, `9` = EFI ARM,
    /// `10` = EFI ARM-64, `0` = Intel x86 PC (BIOS). When empty, option 93 is
    /// omitted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub architectures: Vec<u16>,
}

/// TFTP server settings.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigNetbootTftp {
    /// Socket address to bind the TFTP server to. Accepts a full `host:port`
    /// (e.g. `${NETBOOT_IP}:69`), a bare port (`69`), or `None` (defaults to
    /// `${NETBOOT_IP}:69`). `${NETBOOT_IP}` is resolved at `sysimage netboot`
    /// time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    /// Files served over TFTP, keyed by the filename clients request. Each
    /// value is an input specifier in the config and a content-addressed hash
    /// file name in the manifest.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub files: BTreeMap<String, String>,
}

/// HTTP server settings.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigNetbootHttp {
    /// Socket address to bind the HTTP server to. Accepts a full `host:port`
    /// (e.g. `${NETBOOT_IP}:80`), a bare port (`8080`), or `None` (defaults to
    /// `${NETBOOT_IP}:80`). `${NETBOOT_IP}` is resolved at `sysimage netboot`
    /// time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    /// Files served over HTTP, keyed by the URL path clients request (with a
    /// leading `/`). Each value is an input specifier in the config and a
    /// content-addressed hash file name in the manifest.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub files: BTreeMap<String, String>,
}
