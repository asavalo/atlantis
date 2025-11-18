use std::{
    ffi::OsString,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Child, Command},
};

use crate::{
    protobuf,
    util::{
        CampaignAndHarness, HasCampaignAndHarness,
        getuid, getgid,
        create_docker_volume_arg,
    },
};

const OUTPUT_PROFDATA_FILENAME: &str = "coverage.profdata";
const OUTPUT_JSON_FILENAME: &str = "coverage.json";
const DEFAULT_SOURCE_CODE_FILENAME: &str = "code.c";


pub(crate) struct OutputGenerator {
    profraw_directory: PathBuf,
}

impl OutputGenerator {
    /// Creates a new [`OutputGenerator`].
    pub fn new<P>(profraw_directory: P) -> Self
    where
        P: AsRef<Path>,
    {
        Self {
            profraw_directory: PathBuf::from(profraw_directory.as_ref()),
        }
    }

    /// Determine the directory where profraw files for a particular
    /// campaign-and-harness should be stored.
    ///
    /// This logic should match that of the corresponding method in the
    /// `Executor` struct.
    fn profraw_directory_for_campaign_and_harness(&self, campaign_and_harness: &CampaignAndHarness) -> PathBuf {
        self.profraw_directory.join(campaign_and_harness.path_safe_name())
    }

    /// Handle a request from a remote service for source-level coverage
    /// data.
    pub(crate) fn process_request(
        &self,
        request: protobuf::coverage_service::CoverageRequest,
        cp_dir: &Path,
        cp_mount_dir: &Path,
        harness_bin: &Path,
        docker_image: &str,
    ) -> protobuf::coverage_service::CoverageResponse {
        let result = self.process_request_inner(&request, cp_dir, cp_mount_dir, harness_bin, docker_image);

        if let Err(ref e) = result {
            println!("ERROR: {e}");
        }

        protobuf::coverage_service::CoverageResponse {
            nonce: request.nonce,
            success: result.is_ok(),
        }
    }

    /// Create a list of profraw files that should be merged for an
    /// request for coverage for a specific seed.
    fn collect_profraw_files_individual(
        &self,
        campaign_and_harness: &CampaignAndHarness,
        scope: &protobuf::coverage_service::IndividualScope,
    ) -> Vec<PathBuf> {
        let profraw_dir = self.profraw_directory_for_campaign_and_harness(campaign_and_harness);
        vec![profraw_dir.join(format!("{}.profraw", scope.seed_name))]
    }

    /// Create a list of profraw files that should be merged for an
    /// aggregate (all seeds) coverage request.
    fn collect_profraw_files_aggregate(
        &self,
        campaign_and_harness: &CampaignAndHarness,
        _scope: protobuf::coverage_service::AggregateScope,
    ) -> Result<Vec<PathBuf>, String> {
        let profraw_dir = self.profraw_directory_for_campaign_and_harness(campaign_and_harness);
        match std::fs::read_dir(&profraw_dir) {
            Err(e) => Err(format!(
                "error while iterating profraw filenames in \"{}\": {e}",
                profraw_dir.display(),
            )),
            Ok(iter) => {
                let mut res = vec![];

                for entry in iter {
                    let Ok(entry) = entry else {
                        continue;
                    };

                    if let Ok(file_type) = entry.file_type() {
                        if file_type.is_dir() {
                            continue;
                        }
                    }

                    if !matches!(
                        entry.file_name().as_encoded_bytes(),
                        [.., b'.', b'p', b'r', b'o', b'f', b'r', b'a', b'w'],
                    ) {
                        continue;
                    }

                    res.push(entry.path());
                }

                Ok(res)
            },
        }
    }

    /// Run `llvm-profdata` to merge one or more profraw files into a
    /// profdata file.
    ///
    /// Assumption: all the profraw files are in the same directory as
    /// each other. The profdata file may be in a different directory.
    fn perform_merge(
        docker_image: &str,
        profraw_files: &[PathBuf],
        profdata_file: &Path,
    ) -> Result<(), String> {

        if profraw_files.is_empty() {
            return Err("no profraw files specified for merge".to_owned());
        }

        // We start with some boring path manipulation... ultimately we
        // end up with the following variables:
        // - profraw_host_files: host paths to the profraw files
        // - profraw_host_dir: parent directory of ^
        // - profraw_guest_files: guest paths to the profraw files
        // - profraw_guest_dir: parent directory of ^
        // - profdata_host_file: host path to the profdata file
        // - profdata_host_dir: parent directory of ^
        // - profdata_guest_file: guest path to the profdata file
        // - profdata_guest_dir: parent directory of ^

        let profraw_host_files = profraw_files;
        let profdata_host_file = profdata_file;
        #[allow(unused_variables)] let profraw_files = ();
        #[allow(unused_variables)] let profdata_file = ();

        let profraw_guest_dir = Path::new("/profraw");
        let profdata_guest_dir = Path::new("/profdata");

        // As stated in the doc comment, all the profraw files must be
        // in the same directory
        let Some(profraw_host_dir) = profraw_host_files[0].parent() else {
            return Err(format!(
                "profraw file \"{}\" has no parent",
                profraw_host_files[0].display(),
            ));
        };
        for file in &profraw_host_files[1..] {
            let Some(parent) = file.parent() else {
                return Err(format!("profraw file \"{}\" has no parent", file.display()));
            };
            if parent != profraw_host_dir {
                return Err(format!(
                    "profraw file \"{}\" is in a different directory from \"{}\"",
                    file.display(), profraw_host_files[0].display(),
                ));
            }
        }

        let mut profraw_guest_files = Vec::with_capacity(profraw_host_files.len());
        for file in profraw_host_files {
            let Some(name) = file.file_name() else {
                return Err(format!("profraw file \"{}\" has no name", file.display()));
            };
            profraw_guest_files.push(profraw_guest_dir.join(name));
        }
        let profraw_guest_files = profraw_guest_files;

        let Some(profdata_host_dir) = profdata_host_file.parent() else {
            return Err(format!("profdata file \"{}\" has no parent", profdata_host_file.display()));
        };
        let profdata_guest_file = if let Some(name) = profdata_host_file.file_name() {
            profdata_guest_dir.join(name)
        } else {
            return Err(format!("profdata file \"{}\" has no name", profdata_host_file.display()));
        };

        // OK, we have all the paths now. Time to call llvm-profdata

        let mut cmd = Command::new("docker");

        cmd
            .arg("run")
            .arg("--rm")
            .arg("-v")
            .arg(create_docker_volume_arg(profraw_host_dir, profraw_guest_dir))
            .arg("-v")
            .arg(create_docker_volume_arg(profdata_host_dir, profdata_guest_dir))
            .arg("--user")
            .arg(format!("{}:{}", getuid(), getgid()))
            .arg(docker_image)
            .arg("llvm-profdata")
            .arg("merge")
            .arg("--sparse")
            .args(profraw_guest_files)
            .arg("-o")
            .arg(profdata_guest_file.as_os_str());

        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(e) => return Err(format!("error launching llvm-profdata with args {cmd:?}: {e}")),
        };

        let _exit_status = match child.wait() {
            Ok(exit_status) => exit_status,
            Err(e) => return Err(format!("error running llvm-profdata with args {cmd:?}: {e}")),
        };

        // We don't really care much about the exit status, just whether
        // or not we got an output profdata file

        if !profdata_host_file.is_file() {
            return Err(format!(
                "profdata file \"{}\" was not created by llvm-profdata",
                profdata_host_file.display(),
            ));
        }

        Ok(())
    }

    fn create_llvm_cov_command(
        cp_dir: &Path,
        cp_mount_dir: &Path,
        harness_bin: &Path,
        docker_image: &str,
        profdata_file: &Path,
        output_dir: &Path,
        command_name: &str,
    ) -> Result<Command, String> {

        if !cp_dir.is_dir() {
            return Err(format!("CP directory \"{}\" does not exist", cp_dir.display()));
        }
        if !harness_bin.is_file() {
            return Err(format!("harness binary \"{}\" does not exist", harness_bin.display()));
        }
        if !profdata_file.is_file() {
            return Err(format!("profdata file \"{}\" does not exist", profdata_file.display()));
        }
        if !output_dir.is_dir() {
            return Err(format!("output directory \"{}\" does not exist", output_dir.display()));
        }

        // We start with some boring path manipulation... ultimately we
        // end up with the following variables:
        // - cp_host_dir: host path to the challenge project folder
        // - cp_guest_dir: guest path to the challenge project folder
        // - harness_host_file: host path to the harness binary
        // - harness_host_dir: parent directory of ^
        // - harness_guest_file: guest path to the harness binary
        // - harness_guest_dir: parent directory of ^
        // - profdata_host_file: host path to the profdata file
        // - profdata_host_dir: parent directory of ^
        // - profdata_guest_file: guest path to the profdata file
        // - profdata_guest_dir: parent directory of ^
        // - output_host_dir: host path to the output folder
        // - output_guest_dir: guest path to the output folder

        let cp_host_dir = cp_dir;
        let cp_guest_dir = cp_mount_dir;
        let harness_host_file = harness_bin;
        let profdata_host_file = profdata_file;
        let output_host_dir = output_dir;
        #[allow(unused_variables)] let cp_dir = ();
        #[allow(unused_variables)] let cp_mount_dir = ();
        #[allow(unused_variables)] let harness_file = ();
        #[allow(unused_variables)] let profdata_file = ();
        #[allow(unused_variables)] let output_dir = ();

        let harness_guest_dir = Path::new("/harness");
        let profdata_guest_dir = Path::new("/profdata");
        let output_guest_dir = Path::new("/out");

        let Some(harness_host_dir) = harness_host_file.parent() else {
            return Err(format!("harness binary \"{}\" has no parent", harness_host_file.display()));
        };

        let harness_guest_file = if let Some(name) = harness_host_file.file_name() {
            harness_guest_dir.join(name)
        } else {
            return Err(format!("harness binary \"{}\" has no name", harness_host_file.display()));
        };

        let Some(profdata_host_dir) = profdata_host_file.parent() else {
            return Err(format!("profdata file \"{}\" has no parent", profdata_host_file.display()));
        };

        let profdata_guest_file = if let Some(name) = profdata_host_file.file_name() {
            profdata_guest_dir.join(name)
        } else {
            return Err(format!("profdata file \"{}\" has no name", profdata_host_file.display()));
        };

        // OK, we're all set now. Time to call llvm-cov

        let mut cmd = Command::new("docker");

        // sigh
        let arg_part_1 = "--instr-profile=";
        let arg_part_2 = profdata_guest_file.as_os_str();
        let mut instr_profile_arg = OsString::with_capacity(arg_part_1.len() + arg_part_2.len());
        instr_profile_arg.push(arg_part_1);
        instr_profile_arg.push(arg_part_2);

        cmd
            .arg("run")
            .arg("--rm")
            .arg("-v")
            .arg(create_docker_volume_arg(cp_host_dir, cp_guest_dir))
            .arg("-v")
            .arg(create_docker_volume_arg(harness_host_dir, harness_guest_dir))
            .arg("-v")
            .arg(create_docker_volume_arg(profdata_host_dir, profdata_guest_dir))
            .arg("-v")
            .arg(create_docker_volume_arg(output_host_dir, output_guest_dir))
            .arg("--user")
            .arg(format!("{}:{}", getuid(), getgid()))
            .arg(docker_image)
            .arg("llvm-cov")
            .arg(command_name)
            .arg(harness_guest_file)
            .arg(instr_profile_arg);

        Ok(cmd)
    }

    fn perform_annotation(
        cp_dir: &Path,
        cp_mount_dir: &Path,
        harness_bin: &Path,
        docker_image: &str,
        profdata_file: &Path,
        output_dir: &Path,
        _annotated_source_code_config: &protobuf::coverage_service::AnnotatedSourceCodeConfig,
    ) -> Result<(), String> {

        let mut cmd = Self::create_llvm_cov_command(
            cp_dir,
            cp_mount_dir,
            harness_bin,
            docker_image,
            profdata_file,
            output_dir,
            "show",
        )?;

        cmd
            .arg("--use-color=false")
            .stdout(std::process::Stdio::piped());

        //   --ignore-filename-regex=<string> Skip source code files with file paths that match the given regular expression

        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(e) => return Err(format!("error launching llvm-cov with args {cmd:?}: {e}")),
        };

        Self::handle_llvm_cov_show_output(&mut child, cp_mount_dir, output_dir)?;

        let _exit_status = match child.wait() {
            Ok(exit_status) => exit_status,
            Err(e) => return Err(format!("error running llvm-cov with args {cmd:?}: {e}")),
        };

        Ok(())
    }

    fn handle_llvm_cov_show_output(
        proc: &mut Child,
        cp_guest_dir: &Path,
        output_dir: &Path,
    ) -> Result<(), String> {
        let Some(stdout) = proc.stdout.as_mut() else {
            return Err("llvm-cov has no stdout".to_owned());
        };
        let stdout = BufReader::new(stdout);

        // It should be possible to write a faster implementation than
        // this line-oriented approach, but this is simpler and probably
        // fast enough?

        // Anyway, the output format we're trying to parse here is like:

        // /src/path/to/file1.c:
        //     1|     20|#define BAR(x) ((x) || (x))
        //     2|      2|template <typename T> void foo(T x) {
        //     3|     22|  for (unsigned I = 0; I < 10; ++I) { BAR(I); }
        //     4|      2|}
        //   ------------------
        //   | void foo<int>(int):
        //   |    2|      1|template <typename T> void foo(T x) {
        //   |    3|     11|  for (unsigned I = 0; I < 10; ++I) { BAR(I); }
        //   |    4|      1|}
        //   ------------------
        //   | void foo<float>(int):
        //   |    2|      1|template <typename T> void foo(T x) {
        //   |    3|     11|  for (unsigned I = 0; I < 10; ++I) { BAR(I); }
        //   |    4|      1|}
        //   ------------------
        //     5|      1|int main() {
        //     6|      1|  foo<int>(0);
        //     7|      1|  foo<float>(0);
        //     8|      1|  return 0;
        //     9|      1|}
        //
        // /src/path/to/file2.c:
        //     1|     20|#define BAR(x) ((x) || (x))
        //     2|      2|template <typename T> void foo(T x) {
        //     3|     22|  for (unsigned I = 0; I < 10; ++I) { BAR(I); }
        //   (etc...)
        //
        // /src/path/to/file3.c:
        //     1|     20|#define BAR(x) ((x) || (x))
        //     2|      2|template <typename T> void foo(T x) {
        //     3|     22|  for (unsigned I = 0; I < 10; ++I) { BAR(I); }
        //   (etc...)

        // In other words, each file is separated by a blank line, and
        // each one starts with the file path plus ":".

        // Note that the filename header may be skipped if there's only
        // one source code file, which is unlikely to happen in the
        // competition, but let's attempt to handle it anyway.

        let mut current_file_path = None;
        let mut current_file_data = String::with_capacity(0x8000);  // kinda arbitrary

        for line in stdout.lines() {
            let Ok(mut line) = line else {
                continue;
            };

            if line.is_empty() {
                if let Some(current_file_path) = current_file_path {
                    Self::handle_llvm_cov_show_output_one_file(
                        Some(Path::new(&current_file_path)),
                        &current_file_data,
                        cp_guest_dir,
                        output_dir,
                    )?;
                } else {
                    Self::handle_llvm_cov_show_output_one_file(
                        None,
                        &current_file_data,
                        cp_guest_dir,
                        output_dir,
                    )?;
                }
                current_file_path = None;
                current_file_data.clear();
            } else if current_file_path.is_none() && line.starts_with('/') && line.ends_with(':') {
                line.pop();  // remove trailing ":"
                current_file_path = Some(line);
            } else {
                current_file_data.push_str(&line);
                current_file_data.push('\n');
            }
        }

        if !current_file_data.is_empty() {
            if let Some(current_file_path) = current_file_path {
                Self::handle_llvm_cov_show_output_one_file(
                    Some(Path::new(&current_file_path)),
                    &current_file_data,
                    cp_guest_dir,
                    output_dir,
                )?;
            } else {
                Self::handle_llvm_cov_show_output_one_file(
                    None,
                    &current_file_data,
                    cp_guest_dir,
                    output_dir,
                )?;
            }
        }

        Ok(())
    }

    fn handle_llvm_cov_show_output_one_file(
        guest_file_path: Option<&Path>,
        file_data: &str,
        cp_guest_dir: &Path,
        output_dir: &Path,
    ) -> Result<(), String> {
        let relative_path = if let Some(guest_file_path) = guest_file_path {
            let Ok(second_half) = guest_file_path.strip_prefix(cp_guest_dir) else {
                // could be a system header file or something, possibly --
                // let's not abort the entire operation just for this
                println!(
                    "WARNING: guest file path \"{}\" is not in {} -- skipping",
                    guest_file_path.display(), cp_guest_dir.display(),
                );
                return Ok(());
            };
            second_half
        } else {
            Path::new(DEFAULT_SOURCE_CODE_FILENAME)
        };

        let host_file_path = output_dir.join(relative_path);

        if let Some(parent) = host_file_path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                println!("WARNING: unable to create directory \"{}\" ({e}) -- skipping", parent.display());
                return Ok(());
            }
        }

        if let Err(e) = std::fs::write(&host_file_path, file_data) {
            return Err(format!("error writing output to \"{}\": {e}", host_file_path.display()));
        }

        Ok(())
    }

    fn perform_export(
        cp_dir: &Path,
        cp_mount_dir: &Path,
        harness_bin: &Path,
        docker_image: &str,
        profdata_file: &Path,
        output_dir: &Path,
        output_filename: &str,
        json_config: &protobuf::coverage_service::JsonConfig,
    ) -> Result<(), String> {

        let mut cmd = Self::create_llvm_cov_command(
            cp_dir,
            cp_mount_dir,
            harness_bin,
            docker_image,
            profdata_file,
            output_dir,
            "export",
        )?;

        if !json_config.include_detailed_measurements {
            cmd.arg("-summary-only");
        }

        cmd.stdout(std::process::Stdio::piped());

        let child = match cmd.spawn() {
            Ok(child) => child,
            Err(e) => return Err(format!("error launching llvm-cov with args {cmd:?}: {e}")),
        };

        let output = match child.wait_with_output() {
            Ok(output) => output,
            Err(e) => return Err(format!("error running llvm-cov with args {cmd:?}: {e}")),
        };

        let host_file_path = output_dir.join(output_filename);

        if let Err(e) = std::fs::write(&host_file_path, output.stdout) {
            return Err(format!("error writing output to \"{}\": {e}", host_file_path.display()));
        }

        Ok(())
    }

    /// The actual logic of `process_request()`, with a more convenient
    /// function signature.
    fn process_request_inner(
        &self,
        request: &protobuf::coverage_service::CoverageRequest,
        cp_dir: &Path,
        cp_mount_dir: &Path,
        harness_bin: &Path,
        docker_image: &str,
    ) -> Result<(), String> {
        let output_dir = Path::new(&request.output_directory);
        let campaign_and_harness = request.campaign_and_harness();

        let Some(ref scope) = request.scope else {
            return Err("no coverage-data scope (individual vs. aggregate) provided".to_owned());
        };

        let profraw_files = match scope {
            protobuf::coverage_service::coverage_request::Scope::Individual(individual_scope) =>
                self.collect_profraw_files_individual(&campaign_and_harness, individual_scope),
            protobuf::coverage_service::coverage_request::Scope::Aggregate(aggregate_scope) =>
                self.collect_profraw_files_aggregate(&campaign_and_harness, *aggregate_scope)?,
        };

        if profraw_files.is_empty() {
            return Err(format!("no coverage data available for campaign/harness \"{campaign_and_harness:?}\""));
        }

        // Try to create the output directory if it doesn't exist

        if !output_dir.is_dir() {
            if let Some(parent) = output_dir.parent() {
                if parent.is_dir() {
                    if let Err(e) = std::fs::create_dir(output_dir) {
                        return Err(format!(
                            "couldn't create output directory \"{}\": {e}",
                            output_dir.display(),
                        ));
                    }
                } else {
                    return Err(format!(
                        "output directory \"{}\" does not exist and neither does its parent",
                        output_dir.display(),
                    ));
                }
            } else {
                return Err(format!(
                    "output directory \"{}\" does not exist and has no parent",
                    output_dir.display(),
                ));
            }
        }

        let profdata_path = output_dir.join(OUTPUT_PROFDATA_FILENAME);
        Self::perform_merge(docker_image, &profraw_files, &profdata_path)?;

        if let Some(annotated_source_code_config) = &request.annotated_source_code_config {
            if !harness_bin.is_file() {
                println!(
                    "WARNING: instrumented harness binary \"{}\" doesn't exist -- skipping",
                    harness_bin.display(),
                );
            } else {
                Self::perform_annotation(
                    cp_dir,
                    cp_mount_dir,
                    harness_bin,
                    docker_image,
                    &profdata_path,
                    output_dir,
                    annotated_source_code_config,
                )?;
            }
        }

        if let Some(json_config) = &request.json_config {
            if !harness_bin.is_file() {
                println!(
                    "WARNING: instrumented harness binary \"{}\" doesn't exist -- skipping",
                    harness_bin.display(),
                );
            } else {
                Self::perform_export(
                    cp_dir,
                    cp_mount_dir,
                    harness_bin,
                    docker_image,
                    &profdata_path,
                    output_dir,
                    OUTPUT_JSON_FILENAME,
                    json_config,
                )?;
            }
        }

        Ok(())
    }
}
