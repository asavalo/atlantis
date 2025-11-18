# CFLAGS: https://github.com/Team-Atlanta/oss-fuzz/blob/main/infra/base-images/base-clang/Dockerfile#L66-L78
# SANITIZER_FLAGS: https://github.com/Team-Atlanta/oss-fuzz/blob/85ea937d23d265915583ad9e5a4492e8e8b5695f/infra/base-images/base-builder/Dockerfile#L70
# COVERAGE_FLAGS: https://github.com/Team-Atlanta/oss-fuzz/blob/85ea937d23d265915583ad9e5a4492e8e8b5695f/infra/base-images/base-builder/Dockerfile#L96
# Final CFLAGS: https://github.com/Team-Atlanta/oss-fuzz/blob/85ea937d23d265915583ad9e5a4492e8e8b5695f/infra/base-images/base-builder/compile#L130
OSS_FUZZ_DEFAULT_CFLAGS = "-O1   -fno-omit-frame-pointer   -gline-tables-only   -Wno-error=enum-constexpr-conversion   -Wno-error=incompatible-function-pointer-types   -Wno-error=int-conversion   -Wno-error=deprecated-declarations   -Wno-error=implicit-function-declaration   -Wno-error=implicit-int   -Wno-error=vla-cxx-extension   -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"

OSS_FUZZ_DEFAULT_CXXFLAGS_EXTRA = "-stdlib=c++"
OSS_FUZZ_DEFAULT_CXXFLAGS = (
    f"{OSS_FUZZ_DEFAULT_CFLAGS} {OSS_FUZZ_DEFAULT_CXXFLAGS_EXTRA}"
)
