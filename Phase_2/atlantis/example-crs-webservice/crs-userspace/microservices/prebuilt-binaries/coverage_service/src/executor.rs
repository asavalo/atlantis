use std::{
    fmt::{Display, Formatter},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use crate::util::{
    CampaignAndHarness, Seed,
    move_file, getuid, getgid,
    create_docker_volume_arg, create_docker_env_path_arg,
};

/// Possible outcomes of executing an instrumented harness.
#[derive(Debug)]
pub(crate) enum ExecuteHarnessError {
    // NoInstrumentedBuildAvailable(CampaignAndHarness),
    FailedToCanonicalizeHarnessPath(PathBuf, std::io::Error),
    HarnessPathHasNoParent(PathBuf),
    FailedToCanonicalizeTempDir(PathBuf, std::io::Error),
    HarnessPathHasNoName(PathBuf),
    FailedToStartProcess(std::io::Error, String),
    FailedToExecuteProcess(std::io::Error, String),
    FailedToWriteInputFile(PathBuf, std::io::Error),
    FailedToCopyOutDirectory(PathBuf, String),
    NoProfrawCreated(PathBuf),
    FailedToMoveOutputFile(PathBuf, PathBuf, std::io::Error),
}

// impl ExecuteHarnessError {
//     /// Returns [`true`] if the seed should be put back into the queue
//     /// and retried again later.
//     pub(crate) fn should_retry(&self) -> bool {
//         matches!(self, Self::NoInstrumentedBuildAvailable(_))
//     }
// }


// Rust port of Ensembler's fs_copy() function, which was itself
// adapted from libCRS
fn fs_copy(src: &Path, dst: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dst).ok();

    let mut cmd = std::process::Command::new("rsync");

    if src.is_dir() {
        let mut src_arg = src.as_os_str().to_os_string();
        let src_arg_bytes = src_arg.as_encoded_bytes();
        if !src_arg_bytes.is_empty() && src_arg_bytes[src_arg_bytes.len() - 1] != b'/' {
            src_arg.push("/");
        }
        src_arg.push(".");
        cmd.arg("-a").arg(src_arg).arg(dst)
    } else {
        cmd.arg("-a").arg(src).arg(dst)
    };

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => return Err(format!("error launching rsync with args {cmd:?}: {e}")),
    };

    let _exit_status = match child.wait() {
        Ok(exit_status) => exit_status,
        Err(e) => return Err(format!("error running rsync with args {cmd:?}: {e}")),
    };

    Ok(())
}


impl Display for ExecuteHarnessError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Self::FailedToCanonicalizeHarnessPath(p, e) =>
                write!(f, "failed to canonicalize harness path \"{}\": {e}", p.display()),
            Self::HarnessPathHasNoParent(p) =>
                write!(f, "harness path \"{}\" has no parent", p.display()),
            Self::FailedToCanonicalizeTempDir(p, e) =>
                write!(f, "failed to canonicalize temp dir \"{}\": {e}", p.display()),
            Self::HarnessPathHasNoName(p) =>
                write!(f, "harness path \"{}\" has no name", p.display()),
            Self::FailedToStartProcess(e, cmd_str) =>
                write!(f, "failed to start harness process ({cmd_str}): {e}"),
            Self::FailedToExecuteProcess(e, cmd_str) =>
                write!(f, "failed to execute harness process ({cmd_str}): {e}"),
            Self::FailedToWriteInputFile(p, e) =>
                write!(f, "failed to create or write input data file \"{}\": {e}", p.display()),
            Self::FailedToCopyOutDirectory(p, msg) =>
                write!(f, "failed to copy /out directory (\"{}\"): {msg}", p.display()),
            Self::NoProfrawCreated(p) =>
                write!(f, "profraw file \"{}\" wasn't created as expected", p.display()),
            Self::FailedToMoveOutputFile(p, q, e) =>
                write!(f, "failed to move \"{}\" to \"{}\": {e}", p.display(), q.display()),
        }
    }
}

/// Struct responsible for executing instrumented harnesses and
/// gathering their profraw files.
///
/// Profraw files will be named `<seed name>.profraw` and placed in
/// subdirectories named by `Seed::campaign_and_harness.name()` within
/// the `profraw_directory` passed to [`Executor::new`].
pub(crate) struct Executor {
    /// Directory to store temporary files in
    temp_directory: PathBuf,
    /// Directory where generated profraw files will be placed (in
    /// subdirectories)
    profraw_directory: PathBuf,
}

impl Executor {
    /// Creates a new [`Executor`].
    pub fn new<Q, R>(temp_directory: Q, profraw_directory: R) -> Self
    where
        Q: AsRef<Path>,
        R: AsRef<Path>,
    {
        let s = Self {
            temp_directory: PathBuf::from(temp_directory.as_ref()),
            profraw_directory: PathBuf::from(profraw_directory.as_ref()),
        };

        if let Err(e) = std::fs::create_dir_all(&s.temp_directory) {
            println!("WARNING: couldn't create inputs directory \"{}\": {e}", s.temp_directory.display());
        }
        if let Err(e) = std::fs::create_dir_all(&s.profraw_directory) {
            println!("WARNING: couldn't create profraw directory \"{}\": {e}", s.profraw_directory.display());
        }

        s
    }

    /// Determine the directory where profraw files for a particular
    /// campaign-and-harness should be stored.
    ///
    /// This logic should match that of the corresponding method in the
    /// `OutputGenerator` struct.
    fn profraw_directory_for_campaign_and_harness(&self, campaign_and_harness: &CampaignAndHarness) -> PathBuf {
        self.profraw_directory.join(campaign_and_harness.path_safe_name())
    }

    /// Informs the [`Executor`] about an SBCC-instrumented build of a
    /// particular harness for a particular campaign.
    ///
    /// This function performs some sanity checks and prints warnings if
    /// anything looks wrong, and also creates a subdirectory in the
    /// profraw directory for this campaign/harness pair.
    pub fn check_harness_binary_and_prepare(&self, key: &CampaignAndHarness, path: &Path) {
        // Do some sanity checks and print warnings if anything about
        // the file looks horribly wrong

        if let Err(e) = Executor::check_if_file_exists_and_is_executable(path) {
            println!("WARNING: {e}");
        }

        let new_dir = self.profraw_directory_for_campaign_and_harness(key);
        if let Err(e) = std::fs::create_dir_all(&new_dir) {
            println!("WARNING: couldn't create profraw subdirectory \"{}\": {e}", new_dir.display());
        }
    }

    /// Checks if a file exists and is executable.
    ///
    /// Returns `Ok(())` if both conditions are satisfied, and
    /// `Err(message)` with a message describing the problem if not.
    fn check_if_file_exists_and_is_executable(path: &Path) -> Result<(), String> {
        match std::fs::metadata(path) {
            Err(e) => Err(format!("can't access \"{}\": {e}", path.display())),
            Ok(metadata) => {
                if !metadata.is_file() {
                    Err(format!("\"{}\" isn't a file", path.display()))
                } else if (metadata.permissions().mode() & 0o111) == 0 {
                    Err(format!("\"{}\" isn't marked as executable", path.display()))
                } else {
                    Ok(())
                }
            },
        }
    }

    /// Executes a SBCC-instrumented build of a harness, with the given
    /// [`Seed`] as input, and (if successful) places the resulting
    /// `profraw` file into the profraw directory that was previously
    /// passed to [`Executor::new`].
    pub async fn run_seed(&self, seed: &Seed, harness_bin: &Path, docker_image: &str) -> Result<(), ExecuteHarnessError> {
        type EHE = ExecuteHarnessError;

        let harness_host_bin = harness_bin;
        #[allow(unused_variables)] let harness_bin = ();

        // Guest dirs
        let out_guest_dir = Path::new("/out");
        let work_guest_dir = Path::new("/work");

        // Host dirs
        let harness_host_bin = match harness_host_bin.canonicalize() {
            Ok(path) => path,
            Err(e) => return Err(EHE::FailedToCanonicalizeHarnessPath(harness_host_bin.to_path_buf(), e)),
        };
        let Some(orig_out_host_dir) = harness_host_bin.parent() else {
            return Err(EHE::HarnessPathHasNoParent(harness_host_bin));
        };

        let temp_dir = match self.temp_directory.canonicalize() {
            Ok(path) => path,
            Err(e) => return Err(EHE::FailedToCanonicalizeTempDir(self.temp_directory.clone(), e)),
        };

        let out_host_dir = temp_dir.join("out");
        let work_host_dir = temp_dir.join("work");

        // Host and guest filenames
        let Some(harness_filename) = harness_host_bin.file_name() else {
            return Err(EHE::HarnessPathHasNoName(harness_host_bin));
        };
        let harness_guest_bin = out_guest_dir.join(harness_filename);

        let input_filename = format!("{}.bin", seed.name);
        let input_host_file = work_host_dir.join(&input_filename);
        let input_guest_file = work_guest_dir.join(&input_filename);

        // We have the instrumented binary write its profiling output
        // file to a temporary directory and then move it to the actual
        // output directory afterward, to minimize the chance that the
        // output generator will race with us and read a half-written
        // file
        let output_filename = format!("{}.profraw", seed.name);
        let temp_output_host_file = work_host_dir.join(&output_filename);
        let temp_output_guest_file = work_guest_dir.join(&output_filename);
        let mut final_output_host_file = self.profraw_directory_for_campaign_and_harness(&seed.campaign_and_harness);
        final_output_host_file.push(&output_filename);
        let final_output_host_file = final_output_host_file;

        // Create the /work directory
        if let Err(e) = std::fs::create_dir(&work_host_dir) {
            println!("WARNING: couldn't create work directory \"{}\": {e}", work_host_dir.display());
        }

        // Write input data
        if let Err(e) = std::fs::write(&input_host_file, &seed.data) {
            return Err(EHE::FailedToWriteInputFile(input_host_file, e));
        }

        // Copy the /out directory
        if let Err(e) = fs_copy(orig_out_host_dir, &out_host_dir) {
            return Err(EHE::FailedToCopyOutDirectory(orig_out_host_dir.to_path_buf(), e));
        }

        let mut cmd = tokio::process::Command::new("docker");

        cmd
            .arg("run")
            .arg("--rm")
            .arg("-v")
            .arg(create_docker_volume_arg(&out_host_dir, out_guest_dir))
            .arg("-v")
            .arg(create_docker_volume_arg(&work_host_dir, work_guest_dir))
            .arg("--user")
            .arg(format!("{}:{}", getuid(), getgid()))
            .arg("-e")
            .arg(create_docker_env_path_arg("LLVM_PROFILE_FILE", &temp_output_guest_file))
            .arg("-w")
            .arg(out_guest_dir)
            .arg(docker_image)
            .arg(harness_guest_bin)
            .arg(&input_guest_file);

        let mut proc = match cmd.spawn() {
            Ok(cmd) => cmd,
            Err(e) => return Err(EHE::FailedToStartProcess(e, format!("{:?}", cmd.as_std()))),
        };

        let _status = match proc.wait().await {
            Ok(status) => status,
            Err(e) => return Err(EHE::FailedToExecuteProcess(e, format!("{:?}", cmd.as_std()))),
        };

        // We don't really care much about the exit status, just whether
        // or not we got an output profraw file

        // It's not a big problem if the file can't be deleted for
        // whatever reason, we don't need to return an `Err` here
        if let Err(e) = std::fs::remove_file(&input_host_file) {
            println!("WARNING: seed {}: couldn't delete file {}: {e}", &seed.name, input_host_file.display());
        }

        if !temp_output_host_file.is_file() {
            return Err(EHE::NoProfrawCreated(temp_output_host_file));
        }

        if let Err(e) = move_file(&temp_output_host_file, &final_output_host_file) {
            return Err(EHE::FailedToMoveOutputFile(temp_output_host_file, final_output_host_file, e));
        }

        if let Err(e) = std::fs::remove_dir_all(&out_host_dir) {
            println!("WARNING: couldn't delete out directory \"{}\": {e}", out_host_dir.display());
        }
        if let Err(e) = std::fs::remove_dir_all(&work_host_dir) {
            println!("WARNING: couldn't delete work directory \"{}\": {e}", work_host_dir.display());
        }

        Ok(())
    }
}
