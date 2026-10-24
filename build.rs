#[path = "src/branding.rs"]
mod branding;

fn main() {
    // Fail at build time rather than shipping an EXE that cannot start its backend.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        assert_eq!(
            std::env::var("CARGO_CFG_TARGET_ARCH").as_deref(),
            Ok("x86_64"),
            "The bundled Windows driver supports x64 only"
        );
        for name in ["x64/WinDivert.dll", "x64/WinDivert64.sys", "LICENSE"] {
            let path = format!("vendor/WinDivert/WinDivert-2.2.2-A/{name}");
            println!("cargo:rerun-if-changed={path}");
            assert!(
                std::path::Path::new(&path).is_file(),
                "Missing {path}. Run scripts/fetch-driver.ps1 before building."
            );
        }
        println!("cargo:rerun-if-changed=src/branding.rs");
        let icon =
            std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("true-proxy.ico");
        write_icon(&icon);
        embed_icon(&icon);
    }
    slint_build::compile_with_config(
        "ui/app.slint",
        slint_build::CompilerConfiguration::new()
            .with_style("fluent".into())
            .with_debug_info(std::env::var("PROFILE").as_deref() != Ok("release")),
    )
    .expect("Cannot compile the True Proxy interface");
}

fn embed_icon(icon: &std::path::Path) {
    use std::{path::PathBuf, process::Command};
    let output = icon.parent().unwrap();
    let script = output.join("true-proxy.rc");
    std::fs::write(
        &script,
        format!(
            "1 ICON \"{}\"\n",
            icon.display().to_string().replace('\\', "/")
        ),
    )
    .unwrap();
    let msvc = std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc");
    let resource = output.join(if msvc {
        "true-proxy.res"
    } else {
        "true-proxy.o"
    });
    let status = if msvc {
        let sdk = std::env::var_os("WindowsSdkDir")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(std::env::var_os("ProgramFiles(x86)").expect("Windows SDK not found"))
                    .join("Windows Kits/10")
            });
        let mut versions = std::fs::read_dir(sdk.join("bin"))
            .expect("Windows SDK bin not found")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
        versions.sort();
        let compiler = versions
            .into_iter()
            .rev()
            .map(|version| version.join("x64/rc.exe"))
            .find(|path| path.is_file())
            .unwrap_or_else(|| PathBuf::from("rc.exe"));
        Command::new(compiler)
            .arg("/nologo")
            .arg(format!("/fo{}", resource.display()))
            .arg(&script)
            .status()
    } else {
        let compiler = std::env::var_os("CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER")
            .and_then(|linker| {
                PathBuf::from(linker)
                    .parent()
                    .map(|dir| dir.join("windres.exe"))
            })
            .filter(|path| path.is_file())
            .unwrap_or_else(|| PathBuf::from("windres"));
        Command::new(compiler)
            .arg("--input")
            .arg(&script)
            .arg("--output")
            .arg(&resource)
            .arg("--output-format")
            .arg("coff")
            .status()
    }
    .expect("Cannot run the Windows resource compiler");
    assert!(
        status.success(),
        "Cannot embed the Windows application icon"
    );
    println!("cargo:rustc-link-arg-bin=true-proxy={}", resource.display());
}

fn write_icon(path: &std::path::Path) {
    let images = [16u32, 24, 32, 48, 64, 128, 256].map(|size| {
        let mut bytes = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut bytes, size, size);
            encoder.set_color(png::ColorType::Rgba);
            encoder.set_depth(png::BitDepth::Eight);
            encoder
                .write_header()
                .unwrap()
                .write_image_data(&branding::rgba(size, None))
                .unwrap();
        }
        (size, bytes)
    });
    let mut ico = vec![0, 0, 1, 0, images.len() as u8, 0];
    let mut offset = 6 + images.len() as u32 * 16;
    for (size, bytes) in &images {
        ico.extend_from_slice(&[*size as u8, *size as u8, 0, 0]);
        ico.extend_from_slice(&1u16.to_le_bytes());
        ico.extend_from_slice(&32u16.to_le_bytes());
        ico.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        ico.extend_from_slice(&offset.to_le_bytes());
        offset += bytes.len() as u32;
    }
    for (_, bytes) in images {
        ico.extend_from_slice(&bytes);
    }
    std::fs::write(path, ico).expect("Cannot write the application icon");
}
