//! Regression test for building a FAT32 `build:block:` from a directory
//! containing many long-named files (e.g. a Raspberry Pi `/boot` folder).
//!
//! Previously most files vanished from the rendered image: only a handful of
//! directory entries survived while the file *data* clusters were still
//! allocated, leaving the volume nearly full but apparently empty.

use std::fs;
use std::path::Path;

use sysimage::build::build_from_file;

struct TempDir(std::path::PathBuf);
impl TempDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "sysimg-fatln-{}-{}",
            std::process::id(),
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The filenames from a real Raspberry Pi boot folder — long names that share a
/// long common prefix and differ only in their tail, which stresses short-name
/// (8.3) generation in the FAT writer.
const BOOT_FILES: &[&str] = &[
    "bcm2710-rpi-2-b.dtb",
    "bcm2710-rpi-3-b-plus.dtb",
    "bcm2710-rpi-3-b.dtb",
    "bcm2710-rpi-cm0.dtb",
    "bcm2710-rpi-cm3.dtb",
    "bcm2710-rpi-zero-2-w.dtb",
    "bcm2710-rpi-zero-2.dtb",
    "bcm2711-rpi-4-b.dtb",
    "bcm2711-rpi-400.dtb",
    "bcm2711-rpi-cm4-io.dtb",
    "bcm2711-rpi-cm4.dtb",
    "bcm2711-rpi-cm4s.dtb",
    "bcm2712-d-rpi-5-b.dtb",
    "bcm2712-rpi-5-b.dtb",
    "bcm2712-rpi-500.dtb",
    "bcm2712-rpi-cm5-cm4io.dtb",
    "bcm2712-rpi-cm5-cm5io.dtb",
    "bcm2712-rpi-cm5l-cm4io.dtb",
    "bcm2712-rpi-cm5l-cm5io.dtb",
    "bcm2712d0-rpi-5-b.dtb",
    "bcm2837-rpi-2-b.dtb",
    "bcm2837-rpi-3-a-plus.dtb",
    "bcm2837-rpi-3-b-plus.dtb",
    "bcm2837-rpi-3-b.dtb",
    "bcm2837-rpi-cm3-io3.dtb",
    "bcm2837-rpi-zero-2-w.dtb",
    "bootcode.bin",
    "cmdline.txt",
    "config.txt",
    "fixup.dat",
    "fixup4.dat",
    "fixup4cd.dat",
    "fixup4db.dat",
    "fixup4x.dat",
    "fixup_cd.dat",
    "fixup_db.dat",
    "fixup_x.dat",
    "kernel8.img",
    "start.elf",
    "start4.elf",
    "start4cd.elf",
    "start4db.elf",
    "start4x.elf",
    "start_cd.elf",
    "start_db.elf",
    "start_x.elf",
];

#[test]
fn fat32_keeps_all_long_named_files_from_directory_input() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    let boot = rootfs.join("boot");
    fs::create_dir_all(&boot).unwrap();
    // Give each file a distinct, non-trivial size so cluster allocation is
    // exercised (mimicking the real dtb/elf/img sizes).
    for (i, name) in BOOT_FILES.iter().enumerate() {
        let size = 32 * 1024 + i * 97; // ~32–37 KiB
        fs::write(boot.join(name), vec![b'x'; size]).unwrap();
    }
    // A subdirectory, to exercise directory creation too.
    fs::create_dir_all(boot.join("overlays")).unwrap();
    fs::write(boot.join("overlays").join("gpio-shutdown.dtbo"), b"overlay").unwrap();

    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = format!(
        r#"
name: fatln
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  block:
    bootimg:
      type: fat
      fatVersion: fat32
      emptySpace: "2M"
      files:
        - destination: ""
          input: boot/
disk:
  boot:
    type: gpt
    partitions:
      - name: whole
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: image
          input: build:block:bootimg
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();

    build_from_file(&config_path).expect("build should succeed");

    // Locate the rendered FAT image (the single .bin in the output dir).
    let bin = {
        let mut found = None;
        for entry in fs::read_dir(&output).unwrap() {
            let entry = entry.unwrap();
            if entry.path().extension().is_some_and(|e| e == "bin") {
                found = Some(entry.path());
            }
        }
        found.expect("a rendered .bin should be present in output")
    };

    let bf =
        sysimage::blockfile::BlockFile::open(&bin, 0, fs::metadata(&bin).unwrap().len()).unwrap();
    let fs = hadris_fat::sync::FatVolume::open(bf).unwrap();
    assert_eq!(
        fs.fat_type(),
        hadris_fat::FatType::Fat32,
        "fatVersion: fat32 should produce a FAT32 volume"
    );
    let root = fs.root_dir();
    let mut present = 0;
    for name in BOOT_FILES {
        match root.find(name) {
            Ok(Some(entry)) => {
                assert!(entry.is_file(), "{name} should be a regular file");
                present += 1;
            }
            Ok(None) => {
                eprintln!("MISSING from FAT image: {name}");
            }
            Err(e) => {
                eprintln!("ERROR looking up {name}: {e}");
            }
        }
    }
    if present != BOOT_FILES.len() {
        dump_fat_root_chain(&bin);
    }
    assert_eq!(
        present,
        BOOT_FILES.len(),
        "all {n} boot files should be present in the FAT image, only {present} survived",
        n = BOOT_FILES.len(),
    );

    // The overlays subdirectory and its file should also survive.
    let overlays = root
        .find("overlays")
        .expect("lookup ok")
        .expect("overlays/ dir present");
    assert!(overlays.is_directory(), "overlays should be a directory");
    let overlays_dir = root.open_dir("overlays").expect("open overlays/");
    assert!(
        overlays_dir
            .find("gpio-shutdown.dtbo")
            .expect("lookup ok")
            .is_some(),
        "overlays/gpio-shutdown.dtbo should be present"
    );
}

/// Raw-structure dumper used to diagnose missing entries: parses the FAT32
/// BPB, walks the root-directory cluster chain through the FAT, and prints
/// every 32-byte directory entry (LFN + 8.3 short name).
fn dump_fat_root_chain(image: &Path) {
    let bytes = fs::read(image).unwrap();
    let sector_size = u16::from_le_bytes(bytes[11..13].try_into().unwrap()) as usize;
    let spc = bytes[13] as usize;
    let reserved = u16::from_le_bytes(bytes[14..16].try_into().unwrap()) as usize;
    let num_fats = bytes[16] as usize;
    let fat_size_32 = u32::from_le_bytes(bytes[36..40].try_into().unwrap()) as usize;
    let root_cluster = u32::from_le_bytes(bytes[44..48].try_into().unwrap()) as usize;
    let cluster_size = sector_size * spc;
    let fat_start = reserved * sector_size;
    let data_start = fat_start + num_fats * fat_size_32 * sector_size;

    eprintln!(
        "DUMP: sector={sector_size} spc={spc} cluster={cluster_size} reserved={reserved} \
         fat_size={fat_size_32} root_cluster={root_cluster} data_start={data_start}"
    );

    let fat_entry = |cluster: usize| -> u32 {
        let off = fat_start + cluster * 4;
        u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap()) & 0x0FFF_FFFF
    };

    let mut cur = root_cluster as usize;
    let mut chain = Vec::new();
    let mut steps = 0;
    loop {
        chain.push(cur);
        let next = fat_entry(cur);
        if next >= 0x0FF8 || next == 0 {
            break;
        }
        cur = next as usize;
        steps += 1;
        if steps > 64 {
            eprintln!("DUMP: chain too long, stopping");
            break;
        }
    }
    eprintln!("DUMP: root dir cluster chain = {chain:?}");

    for (ci, cluster) in chain.iter().enumerate() {
        let base = data_start + (cluster - 2) * cluster_size;
        eprintln!("DUMP: --- cluster #{ci} (cluster {cluster}, byte {base}) ---");
        let n_entries = cluster_size / 32;
        for i in 0..n_entries {
            let off = base + i * 32;
            let entry = &bytes[off..off + 32];
            let first = entry[0];
            if first == 0x00 {
                eprintln!("DUMP:   [{i}] END (0x00)");
                break;
            }
            if first == 0xE5 {
                eprintln!("DUMP:   [{i}] free (0xE5)");
                continue;
            }
            let attr = entry[11];
            if attr & 0x0F == 0x0F {
                // LFN entry
                let seq = entry[0] & 0x1F;
                eprintln!("DUMP:   [{i}] LFN seq={seq}");
            } else {
                let name = &entry[0..11];
                eprintln!(
                    "DUMP:   [{i}] SHORT name={:?} attr=0x{:02x} first_clus={} size={}",
                    String::from_utf8_lossy(name),
                    attr,
                    ((entry[20] as u32) << 16) | (entry[26] as u32),
                    u32::from_le_bytes(entry[28..32].try_into().unwrap())
                );
            }
        }
    }
}
