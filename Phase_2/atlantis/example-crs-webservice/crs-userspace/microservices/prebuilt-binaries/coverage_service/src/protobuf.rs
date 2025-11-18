pub mod coverage_service {
    use crate::util::{CampaignAndHarness, HasCampaignAndHarness};

    include!(concat!(env!("OUT_DIR"), "/coverage_service.rs"));

    impl HasCampaignAndHarness for FuzzerSeedRequest {
        fn campaign_and_harness(&self) -> CampaignAndHarness {
            CampaignAndHarness {
                campaign: self.campaign_id.clone(),
                harness: self.harness_id.clone(),
            }
        }
    }

    impl HasCampaignAndHarness for FuzzerSeedUpdate {
        fn campaign_and_harness(&self) -> CampaignAndHarness {
            CampaignAndHarness {
                campaign: self.campaign_id.clone(),
                harness: self.harness_id.clone(),
            }
        }
    }

    impl HasCampaignAndHarness for CoverageRequest {
        fn campaign_and_harness(&self) -> CampaignAndHarness {
            CampaignAndHarness {
                campaign: self.campaign_id.clone(),
                harness: self.harness_id.clone(),
            }
        }
    }
}

pub mod fuzzer_manager {
    use crate::util::{CampaignAndHarness, HasCampaignAndHarness};

    include!(concat!(env!("OUT_DIR"), "/fuzzer_manager.rs"));

    impl HasCampaignAndHarness for FuzzerLaunchAnnouncement {
        fn campaign_and_harness(&self) -> CampaignAndHarness {
            CampaignAndHarness {
                campaign: "main".to_owned(),
                harness: self.harness_id.clone(),
            }
        }
    }
}

pub mod harness_builder {
    include!(concat!(env!("OUT_DIR"), "/harness_builder.rs"));
}
