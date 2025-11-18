use std::{
    ffi::{OsStr, OsString},
    path::Path,
};

/// A struct owning a pair of [`String`]s representing a fuzzing
/// campaign ID and harness ID.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub(crate) struct CampaignAndHarness {
    /// Campaign ID.
    pub campaign: String,
    /// Harness ID.
    pub harness: String,
}

impl CampaignAndHarness {
    /// Return a unique* name for the campaign/harness pair, which is
    /// guaranteed to use only characters that are path-friendly on
    /// Linux.
    ///
    /// *may not be unique if two campaigns or harnesses have names
    /// differing only in non-alphanumeric characters, which will
    /// probably never happen
    pub(crate) fn path_safe_name(&self) -> String {
        let mut output = String::with_capacity(self.campaign.len() + self.harness.len() + 1);
        for c in self.campaign.chars() {
            if c.is_ascii_alphanumeric() {
                output.push(c);
            } else {
                output.push('_');
            }
        }

        // Originally I used ':' here, but that ends up causing problems
        // with `docker run -v /host:/guest` syntax, so, avoid that.
        // '-' is available, since it's neither alphanumeric nor '_'
        output.push('-');

        for c in self.harness.chars() {
            if c.is_ascii_alphanumeric() {
                output.push(c);
            } else {
                output.push('_');
            }
        }

        output
    }
}

pub(crate) trait HasCampaignAndHarness {
    fn campaign_and_harness(&self) -> CampaignAndHarness;
}

impl HasCampaignAndHarness for CampaignAndHarness {
    fn campaign_and_harness(&self) -> CampaignAndHarness {
        self.clone()
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub(crate) struct Seed {
    pub campaign_and_harness: CampaignAndHarness,
    pub name: String,
    pub data: Vec<u8>,
}

/// Move a file from one path to another.
///
/// This performs a cheap [`std::fs::rename`] if possible, or uses a
/// slower but more reliable fallback if not.
pub(crate) fn move_file<P: AsRef<Path>, Q: AsRef<Path>>(from: P, to: Q) -> std::io::Result<()> {
    if std::fs::rename(&from, &to).is_ok() {
        return Ok(());
    }

    std::fs::copy(&from, &to)?;
    std::fs::remove_file(&from)
}

pub(crate) fn getuid() -> libc::uid_t {
    unsafe { libc::getuid() }
}

pub(crate) fn getgid() -> libc::uid_t {
    unsafe { libc::getgid() }
}

/// Create an [`OsString`] of the form `"host_path:guest_path"`,
/// suitable for use as a Docker volume mapping (`-v`) argument.
pub fn create_docker_volume_arg(host_path: &Path, guest_path: &Path) -> OsString {
    let host_path = host_path.as_os_str();
    let guest_path = guest_path.as_os_str();

    let mut res = OsString::with_capacity(host_path.len() + 1 + guest_path.len());

    res.push(host_path);
    res.push(":");
    res.push(guest_path);

    res
}

/// Create an [`OsString`] of the form `"name=path"`,
/// suitable for use as a Docker environment variable (`-e`) argument.
pub fn create_docker_env_path_arg(name: &str, path: &Path) -> OsString {
    let name = OsStr::new(name);
    let path = path.as_os_str();

    let mut res = OsString::with_capacity(name.len() + 1 + path.len());

    res.push(name);
    res.push("=");
    res.push(path);

    res
}
