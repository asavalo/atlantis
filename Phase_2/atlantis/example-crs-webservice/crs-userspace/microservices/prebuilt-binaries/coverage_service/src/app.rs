use std::{
    collections::{HashMap, VecDeque},
    path::{Path, PathBuf},
    sync::Arc,
};

use dashmap::DashMap;
use tokio::{
    sync::RwLock,
    time::{Duration, Instant},
};

use crate::{
    executor::Executor,
    output_generator::OutputGenerator,
    protobuf,
    util::{CampaignAndHarness, HasCampaignAndHarness, Seed},
};


pub(crate) trait SeedRequestInterface {
    // This is actually an `async fn`, it just needs to be desugared
    // here to add the Send bound. You can implement it with an
    // `async fn`.
    fn request_seeds(&self, request: protobuf::coverage_service::FuzzerSeedRequest) -> impl std::future::Future<Output = ()> + Send;
}


const MINIMUM_TIME_BETWEEN_REQUESTS: Duration = Duration::from_millis(200);
const MINIMUM_TIME_BETWEEN_RUN_SEED_ERRORS: Duration = Duration::from_millis(2000);
const QUEUE_LOW_WATER_MARK: usize = 10;
const REQUESTER_THREAD_SLEEP_TIME: Duration = Duration::from_millis(100);
const RUNNER_THREAD_SLEEP_TIME: Duration = Duration::from_millis(100);


enum ShouldRetry {
    No,
    Yes,
}

impl ShouldRetry {
    fn should_retry(&self) -> bool {
        matches!(self, Self::Yes)
    }
}


/// Represents the overall application state.
///
/// This struct manages concurrency internally -- the caller doesn't
/// need to worry about it. As such, all public methods take immutable
/// references to self.
pub(crate) struct App<R>
where
    R: SeedRequestInterface + Send + Sync + 'static,
{
    /// An object used to broadcast requests to the fuzzer for more
    /// seeds when we're running low.
    requester: R,

    /// An object responsible for executing seeds and gathering their
    /// source-level coverage data (profraw files).
    executor: Executor,

    /// An object responsible for using previously generated profraw
    /// files to generate source-level coverage data as requested by
    /// remote clients.
    output_generator: OutputGenerator,

    /// List of campaign/harness pairs that are currently active.
    active_campaigns: RwLock<Vec<CampaignAndHarness>>,

    /// List of harness-builder nonces that refer to libfuzzer_sbcc
    /// harness builds.
    libfuzzer_sbcc_nonces: RwLock<Vec<String>>,

    /// Queue of somewhat-randomly-sampled seeds provided to us by the
    /// fuzzer, which we have yet to re-execute.
    seed_queue: RwLock<VecDeque<Seed>>,

    /// Queue of "interesting" seeds provided to us by the fuzzer, which
    /// we have yet to re-execute.
    interesting_seed_queue: RwLock<VecDeque<Seed>>,

    /// Map indicating the challenge-project directories for each
    /// campaign/harness pair
    cp_directories: DashMap<CampaignAndHarness, PathBuf>,

    /// Map indicating the guest directory to mount the
    /// challenge-project source repo to for each campaign/harness pair
    cp_mount_directories: DashMap<CampaignAndHarness, PathBuf>,

    /// Map indicating the SBCC-instrumented build for each
    /// campaign/harness pair
    harness_binaries: DashMap<CampaignAndHarness, PathBuf>,

    /// Map indicating the Docker image name for each
    /// campaign/harness pair
    docker_images: DashMap<CampaignAndHarness, String>,

    /// The last time a run-seed error was printed to the console (helps
    /// prevent us from spamming it too much)
    last_run_seed_error: RwLock<Instant>,
}

impl<R> App<R>
where
    R: SeedRequestInterface + Send + Sync + 'static,
{
    /// Creates a new [`App`], wrapped in an [`Arc`].
    pub(crate) fn new_arc<Q>(requester: R, cache_directory: Q) -> Arc<Self>
    where Q: AsRef<Path>,
    {
        let mut temp_inputs_directory = PathBuf::from(cache_directory.as_ref());
        temp_inputs_directory.push("inputs");
        let mut profraw_directory = PathBuf::from(cache_directory.as_ref());
        profraw_directory.push("profraw");
        let executor = Executor::new(&temp_inputs_directory, &profraw_directory);
        let output_generator = OutputGenerator::new(&profraw_directory);

        let app = Arc::new(App {
            requester,
            executor,
            output_generator,
            active_campaigns: RwLock::default(),
            libfuzzer_sbcc_nonces: RwLock::default(),
            seed_queue: RwLock::default(),
            interesting_seed_queue: RwLock::default(),
            cp_directories: DashMap::new(),
            cp_mount_directories: DashMap::new(),
            harness_binaries: DashMap::new(),
            docker_images: DashMap::new(),
            last_run_seed_error: RwLock::new(Instant::now() - MINIMUM_TIME_BETWEEN_RUN_SEED_ERRORS - Duration::from_secs(1)),
        });

        let clone_1 = Arc::clone(&app);
        tokio::spawn(async move {
            clone_1.requester_thread().await;
        });

        let clone_2 = Arc::clone(&app);
        tokio::spawn(async move {
            clone_2.runner_thread().await;
        });

        app
    }

    /// Thread that continually checks how full the seed queues are, and
    /// sends requests to the fuzzer(s) for more seeds when necessary.
    async fn requester_thread(&self) {
        let mut last_request_times: HashMap<CampaignAndHarness, Instant> = HashMap::new();
        loop {
            // Clone the campaigns list so we hold the lock for as
            // little time as possible (we don't expect the vec to grow
            // very large)
            let active_campaigns_clone = self.active_campaigns.read()
                .await
                .clone();
            for cah in active_campaigns_clone {
                // If we already sent a request for this campaign
                // recently, don't send another one again yet
                if let Some(last_request_time) = last_request_times.get(&cah) {
                    if Instant::now() - *last_request_time < MINIMUM_TIME_BETWEEN_REQUESTS {
                        continue;
                    }
                }

                // Measure the number of pending seeds for this campaign
                let num_pending_seeds = self.seed_queue.read()
                    .await
                    .iter()
                    .filter(|s| s.campaign_and_harness == cah)
                    .count();
                let num_pending_interesting_seeds = self.interesting_seed_queue.read()
                    .await
                    .iter()
                    .filter(|s| s.campaign_and_harness == cah)
                    .count();

                println!(
                    "Seed queue for {}:{}: {num_pending_seeds} normal, {num_pending_interesting_seeds} interesting ({} total)",
                    &cah.campaign,
                    &cah.harness,
                    num_pending_seeds + num_pending_interesting_seeds
                );

                // Send a new request if necessary
                if num_pending_seeds + num_pending_interesting_seeds < QUEUE_LOW_WATER_MARK {
                    self.send_seed_request(&cah).await;
                    last_request_times.insert(cah, Instant::now());
                }
            }

            tokio::time::sleep(REQUESTER_THREAD_SLEEP_TIME).await;
        }
    }

    /// Send a request to the appropriate fuzzer to get more seeds for
    /// the indicated campaign/harness pair.
    async fn send_seed_request(&self, campaign_and_harness: &CampaignAndHarness) {
        self.requester.request_seeds(protobuf::coverage_service::FuzzerSeedRequest {
            campaign_id: campaign_and_harness.campaign.clone(),
            harness_id: campaign_and_harness.harness.clone(),
        }).await;
    }

    /// Thread that continually pops seeds from the queues and executes
    /// them to collect their source-level coverage data (profraw
    /// files).
    async fn runner_thread(&self) {
        loop {
            let mut ran_something = false;

            // Anonymous scope so we release the seed-queue lock as soon
            // as possible
            {
                let mut queue = self.interesting_seed_queue.write().await;
                if let Some(seed) = queue.pop_front() {
                    if let Err(e) = self.run_seed(&seed).await {
                        if e.should_retry() {
                            queue.push_back(seed);
                        }
                    } else {
                        ran_something = true;
                    }
                }
            }

            // This `if` statement also doubles as another scope for
            // lock-releasing
            if !ran_something {
                let mut queue = self.seed_queue.write().await;
                if let Some(seed) = queue.pop_front() {
                    if let Err(e) = self.run_seed(&seed).await {
                        if e.should_retry() {
                            queue.push_back(seed);
                        }
                    } else {
                        ran_something = true;
                    }
                }
            }

            if !ran_something {
                tokio::time::sleep(RUNNER_THREAD_SLEEP_TIME).await;
            }
        }
    }

    async fn print_run_seed_error(&self, message: &str) {
        if Instant::now() - *self.last_run_seed_error.read().await > MINIMUM_TIME_BETWEEN_RUN_SEED_ERRORS {
            *self.last_run_seed_error.write().await = Instant::now();
            println!("{message}");
        }
    }

    async fn run_seed(&self, seed: &Seed) -> Result<(), ShouldRetry> {
        let Some(harness_bin) = self.harness_binaries.get(&seed.campaign_and_harness) else {
            self.print_run_seed_error(&format!("no SBCC-instrumented build available (yet?) for campaign/harness \"{:?}\"", seed.campaign_and_harness)).await;
            return Err(ShouldRetry::Yes);
        };

        // unsure if this is necessary, just being extra careful to
        // avoid holding the lock for too long
        let harness_bin = harness_bin.clone();

        let Some(docker_image) = self.docker_images.get(&seed.campaign_and_harness) else {
            self.print_run_seed_error(&format!("no Docker image available (yet?) for campaign/harness \"{:?}\"", seed.campaign_and_harness)).await;
            return Err(ShouldRetry::Yes);
        };

        // unsure if this is necessary, just being extra careful to
        // avoid holding the lock for too long
        let docker_image = docker_image.clone();

        if let Err(e) = self.executor.run_seed(seed, &harness_bin, &docker_image).await {
            self.print_run_seed_error(&format!("WARNING: discarding seed {} due to error: {e}", &seed.name)).await;
            return Err(ShouldRetry::No);
        }

        Ok(())
    }

    pub(crate) async fn process_harness_builder_request(
        &self,
        data: protobuf::harness_builder::BuildRequest,
    ) {
        if data.mode != (protobuf::harness_builder::Mode::LibfuzzerSbcc as i32) {
            // We don't care about other build modes
            return;
        }

        println!("Received harness-builder libfuzzer_sbcc build request: {data:?}");

        let mut v = self.libfuzzer_sbcc_nonces.write().await;
        v.push(data.nonce);
    }

    pub(crate) async fn process_harness_builder_response(
        &self,
        data: protobuf::harness_builder::BuildRequestResponse,
    ) {
        // Only way to know if this is a libfuzzer-sbcc build is to
        // compare the nonce to ones we've previously recorded

        // Anonymous scope to release this lock as soon as possible
        {
            let v = self.libfuzzer_sbcc_nonces.read().await;
            if !v.contains(&data.nonce) {
                // Nope
                return;
            }
        }

        println!("Received harness-builder libfuzzer_sbcc build response: {data:?}");

        for (harness_id, harness_path) in &data.harnesses {
            let campaign_and_harness = CampaignAndHarness {
                campaign: "main".to_owned(),
                harness: harness_id.clone(),
            };

            self.harness_binaries.insert(
                campaign_and_harness.clone(),
                PathBuf::from(&harness_path),
            );
        }
    }

    pub(crate) async fn process_fuzzer_launch_announcement(
        &self,
        data: protobuf::fuzzer_manager::FuzzerLaunchAnnouncement,
    ) {
        println!("Received fuzzer launch announcement: {data:?}");

        let campaign_and_harness = data.campaign_and_harness();

        let Some(binary_paths) = &data.binary_paths else {
            println!("Binary paths not present -- aborting");
            return;
        };

        // If there's already an entry for this campaign/harness, that's
        // OK, we'll just replace it with the new directory (if it's any
        // different)

        self.cp_directories.insert(
            campaign_and_harness.clone(),
            PathBuf::from(data.cp_src_path),
        );

        self.cp_mount_directories.insert(
            campaign_and_harness.clone(),
            PathBuf::from(data.cp_mount_path),
        );

        self.executor.check_harness_binary_and_prepare(
            &campaign_and_harness,
            Path::new(&binary_paths.libfuzzer_sbcc),
        );

        // We don't update self.harness_binaries here, since fuzzer
        // launch announcements might not include libfuzzer_sbcc builds,
        // since the controller doesn't wait for those to be finished
        // before launching the actual fuzzers. We instead get that info
        // by watching harness builder-related messages.

        self.docker_images.insert(
            campaign_and_harness.clone(),
            data.docker_image_name.clone(),
        );

        // Add to self.active_campaigns, but skip if it's already there
        let mut ac = self.active_campaigns.write().await;
        if let Err(idx) = ac.binary_search(&campaign_and_harness) {
            ac.insert(idx, campaign_and_harness);
        }
    }

    /// Handle a message from a fuzzer providing us with new seed data.
    pub(crate) async fn process_seed_update(&self, data: protobuf::coverage_service::FuzzerSeedUpdate) {
        println!("Received seed update: {data:?}");

        let seed = Seed {
            campaign_and_harness: data.campaign_and_harness(),
            name: data.seed_name,
            data: data.data,
        };

        if data.is_interesting {
            self.interesting_seed_queue.write().await.push_back(seed);
        } else {
            self.seed_queue.write().await.push_back(seed);
        }
    }

    /// Handle a request from a remote service for source-level coverage
    /// data.
    pub(crate) fn process_request(
        &self,
        request: protobuf::coverage_service::CoverageRequest,
    ) -> Option<protobuf::coverage_service::CoverageResponse> {
        println!("Received service request: {request:?}");

        let campaign_and_harness = request.campaign_and_harness();

        let Some(cp_dir) = self.cp_directories.get(&campaign_and_harness) else {
            println!("no CP dir available (yet?) for campaign/harness \"{campaign_and_harness:?}\"");
            return Some(protobuf::coverage_service::CoverageResponse {
                nonce: request.nonce,
                success: false,
            });
        };

        // unsure if this is necessary, just being extra careful to
        // avoid holding the lock for too long
        let cp_dir = cp_dir.clone();

        let Some(cp_mount_dir) = self.cp_mount_directories.get(&campaign_and_harness) else {
            println!("no CP mount dir available (yet?) for campaign/harness \"{campaign_and_harness:?}\"");
            return Some(protobuf::coverage_service::CoverageResponse {
                nonce: request.nonce,
                success: false,
            });
        };

        // unsure if this is necessary, just being extra careful to
        // avoid holding the lock for too long
        let cp_mount_dir = cp_mount_dir.clone();

        let Some(harness_bin) = self.harness_binaries.get(&campaign_and_harness) else {
            println!("no SBCC-instrumented build available (yet?) for campaign/harness \"{campaign_and_harness:?}\"");
            return Some(protobuf::coverage_service::CoverageResponse {
                nonce: request.nonce,
                success: false,
            });
        };

        // unsure if this is necessary, just being extra careful to
        // avoid holding the lock for too long
        let harness_bin = harness_bin.clone();

        let Some(docker_image) = self.docker_images.get(&campaign_and_harness) else {
            println!("no Docker image available (yet?) for campaign/harness \"{campaign_and_harness:?}\"");
            return Some(protobuf::coverage_service::CoverageResponse {
                nonce: request.nonce,
                success: false,
            });
        };

        // unsure if this is necessary, just being extra careful to
        // avoid holding the lock for too long
        let docker_image = docker_image.clone();

        Some(self.output_generator.process_request(request, &cp_dir, &cp_mount_dir, &harness_bin, &docker_image))
    }
}
