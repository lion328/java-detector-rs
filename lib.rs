#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate error_chain;
extern crate regex;
extern crate which;
extern crate goblin;

#[cfg(windows)]
extern crate winreg;
#[cfg(windows)]
extern crate winapi;
#[cfg(windows)]
extern crate kernel32;

#[cfg(unix)]
extern crate nix;

use errors::*;
use errors::ErrorKind::*;
use std::env;
use std::process;
use std::path::PathBuf;
use std::ffi::{OsStr, OsString};
use std::io::{Read, BufReader, BufRead};
use std::fs::File;
use std::path::Path;
use regex::Regex;

/// A module for handling Java detection errors.
pub mod errors {
    use std::io;
    use goblin;

    error_chain! {
        foreign_links {
            Io(io::Error);
            Goblin(goblin::error::Error);
        }

        errors {
            /// An error using when a Java process' stderr returned Option::None.
            ChildNoneStderr {
                description("The Java process' stderr returned Option::None")
            }

            /// An error using when execute an unimplemented Java detector.
            DetectorNotImplemented {
                description("Java detector not implemented")
            }

            /// An error using when all Java detection methods failed.
            JavaNotFound {
                description("All Java detection methods failed")
            }

            /// An error using when failed to detect architecture of a Java executable.
            ArchitectureDectectionFailed {
                description("Java architecture detection failed")
            }

            /// An error using when Regex operations on Java stdout failed.
            VersionRegexFailed(msg: &'static str) {
                description("Regex operations on Java stdout failed")
                display("Regex operations on Java stdout failed: {}", msg)
            }

            /// An error using when a Java version detector failed.
            VersionDetectionFailed {
                description("Java version detection failed")
            }

            /// An error using when which-rs failed to detect Java.
            WhichDetectorFailed {
                description("which-rs failed to detect Java")
            }

            /// An error using when a system-dependent Java detector failed.
            SystemImplDetectorFailed {
                description("System-dependent method failed to detect Java")
            }

            /// An error using when the environment variable-based Java detector failed.
            EnvironmentDetectorFailed {
                description("Environment variable-based method failed to detect Java")
            }
        }
    }
}

/// A struct for store Java executable information.
#[derive(Debug, Clone)]
pub struct Java {
    /// The architecture that Java use.
    pub arch: Architecture,
    /// The Java version.
    pub version: String,
    /// The Java executable path.
    pub executable: OsString
}

/// A enum for detect operating system architecture.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Architecture {
    /// 32-bit operating system.
    Arch32,
    /// 64-bit operating system.
    Arch64,
    /// Unknown architecture
    Unknown
}

impl Java {

    /// Create a [`Java`] struct from the provided Java home directory path.
    pub fn from_home<T: Into<PathBuf>>(path: T) -> Result<Java> {
        let mut exec = path.into();
        exec.push("bin");
        exec.push(Java::executable_file());

        Java::from_executable(exec)
    }

    /// Create a [`Java`] struct from the provided Java executable path.
    pub fn from_executable<T: Into<PathBuf>>(exec: T) -> Result<Java> {
        let buf = exec.into();

        Ok(Java {
            arch: executable_arch(&buf).chain_err(|| ArchitectureDectectionFailed)?,
            version: Java::execute_version(&buf).chain_err(|| VersionDetectionFailed)?,
            executable: buf.into()
        })
    }

    /// Detect an installed Java and returns a [`Java`] struct.
    pub fn system() -> Result<Java> {
        Java::system_impl_env().chain_err(|| EnvironmentDetectorFailed)
            .or_else(|_| Java::system_impl()).chain_err(|| SystemImplDetectorFailed)
            .or_else(|_| Java::system_impl_which()).chain_err(|| WhichDetectorFailed)
            .chain_err(|| JavaNotFound)
    }

    /// Get Java executable filename as normally in Java home directory.
    pub fn executable_file() -> &'static str {
        if cfg!(windows) {
            "java.exe"
        } else {
            "java"
        }
    }

    #[cfg(not(windows))]
    fn system_impl() -> Result<Java> {
        // Turns out that which-rs is a cross-platform library, so no platform-specific method here.
        bail!(DetectorNotImplemented)
    }

    #[cfg(windows)]
    fn system_impl() -> Result<Java> {
        use winreg::RegKey;
        use winreg::enums::*;

        let jre_root = String::from(r"SOFTWARE\JavaSoft\Java Runtime Environment\");
        let mut reg_flag = KEY_WOW64_32KEY;
        let selected_jre;

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let jre_32 = hklm.open_subkey_with_flags(&jre_root, KEY_READ | reg_flag);

        if Architecture::os_arch() == Architecture::Arch32 {
            if jre_32.is_err() {
                bail!(JavaNotFound)
            }

            selected_jre = jre_32.unwrap();
        } else {
            selected_jre = match hklm.open_subkey_with_flags(&jre_root,
                                                             KEY_READ | KEY_WOW64_64KEY) {
                Ok(subkey) => {
                    reg_flag = KEY_WOW64_64KEY;
                    subkey
                }
                Err(_) => {
                    jre_32?
                }
            }
        }

        let current_version: String = selected_jre.get_value("CurrentVersion")?;
        let specific_jre_root = hklm.open_subkey_with_flags(jre_root + &current_version,
                                                            KEY_READ | reg_flag)?;
        let java_home: String = specific_jre_root.get_value("javaHome")?;

        Java::from_home(java_home)
    }

    fn system_impl_which() -> Result<Java> {
        Java::from_executable(which::which("java")?)
    }

    fn system_impl_env() -> Result<Java> {
        Java::from_home(match env::var_os("JAVA_HOME") {
            Some(home) => home,
            None => bail!(JavaNotFound)
        })
    }

    fn execute_version<T: AsRef<OsStr>>(executable: T) -> Result<String> {
        let mut child = process::Command::new(executable)
            .arg("-version")
            .stderr(process::Stdio::piped())
            .spawn()?;

        match child.stderr {
            Some(ref mut out) => {
                lazy_static! {
                    static ref REGEX: Regex = Regex::new("version \"(.*)\"").unwrap();
                }

                let reader = BufReader::new(out);
                let line = reader.lines().next()
                    .ok_or_else(|| VersionRegexFailed("Read line failed"))??;
                let caps = REGEX.captures(&line)
                    .ok_or_else(|| VersionRegexFailed("Capture failed"))?;

                caps.get(1).map(|x| String::from(x.as_str()))
                    .ok_or_else(|| VersionRegexFailed("Get capture failed").into())
            },
            None => bail!(ChildNoneStderr)
        }
    }
}

impl Architecture {

    /// Get the architecture of operating system currently running on.
    pub fn os_arch() -> Architecture {
        lazy_static! {
            static ref ARCH: Architecture = Architecture::os_arch_impl();
        }

        *ARCH
    }

    #[cfg(not(any(windows, unix)))]
    fn os_arch_impl() -> Architecture {
        use std::env;

        match env::consts::ARCH {
            "x86" => Arch::Arch32,
            "x86_64" => Arch::Arch64,
            _ => Arch::Unknown
        }
    }

    #[cfg(windows)]
    fn os_arch_impl() -> Architecture {
        use std::mem;
        use winapi::minwindef::MAX_PATH;
        use winapi::wchar_t;
        use kernel32;

        let mut buf = [0 as wchar_t; MAX_PATH];
        let len;

        unsafe {
            let ptr = mem::transmute(buf.as_mut_ptr());
            len = kernel32::GetSystemWow64DirectoryW(ptr, MAX_PATH as u32);
        }

        if len == 0 {
            return Architecture::Arch32
        }

        Architecture::Arch64
    }

    #[cfg(unix)]
    fn os_arch_impl() -> Architecture {
        use nix::sys::utsname;

        let uname = utsname::uname();

        match uname.machine() {
            "i386" | "i686" | "x86" => Architecture::Arch32,
            "amd64" | "ia64" | "x86_64" => Architecture::Arch64,
            _ => Architecture::Unknown
        }
    }
}

/// Get executable architecture.
pub fn executable_arch<T: AsRef<Path>>(path: T) -> Result<Architecture> {
    use goblin::elf::header::*;
    use goblin::pe::header::*;

    let mut file = File::open(path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;

    Ok(match goblin::Object::parse(&buf)? {
        goblin::Object::Elf(elf) => {
            match elf.header.e_machine {
                EM_386 => Architecture::Arch32,
                EM_X86_64 | EM_IA_64 => Architecture::Arch64,
                _ => Architecture::Unknown
            }
        },
        goblin::Object::PE(pe) => {
            match pe.header.coff_header.machine {
                COFF_MACHINE_X86 => Architecture::Arch32,
                COFF_MACHINE_X86_64 => Architecture::Arch64,
                _ => Architecture::Unknown
            }
        }
        _ => Architecture::Unknown
    })
}

