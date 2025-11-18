# Most sources, such as
# https://github.com/google/oss-fuzz/blob/86bba1c44ab799c5b3fbdd4c46b959f4df1362fa/infra/cifuzz/base_runner_utils.py#L32
# indicate that the default OSS-Fuzz timeout is 25 seconds.
# But one place in the documentation
# (https://google.github.io/oss-fuzz/advanced-topics/reproducing/#fuzz-target-bugs)
# says 65 seconds.
# That's *probably* a mistake, but since the competition organizers
# haven't announced a specific duration, let's be conservative and go
# with the longer duration just in case.
DEFAULT_SCORABLE_TIMEOUT_DURATION = 65
