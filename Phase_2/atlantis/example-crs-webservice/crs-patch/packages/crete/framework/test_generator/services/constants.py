"""
Common constants used across the test generator modules.
"""

# Directory and file paths
TEST_DIR = "test"
TEST_SCRIPT_PREFIX = "generated_test"
TEST_SCRIPT_EXT = ".sh"
TEST_RESULT_LOG_PREFIX = "test_result_log"
TEST_RESULT_LOG_EXT = ".txt"
INFORMATION_DIR = "information"
SUCCESS_DIR = "success"

# Container paths
CONTAINER_SRC_DIR = "/out/src"
CONTAINER_OUT_DIR = "/out"

# File names
SUCCESS_TEST_FILENAME = f"{TEST_SCRIPT_PREFIX}{TEST_SCRIPT_EXT}"
SUCCESS_LOG_FILENAME = f"{TEST_RESULT_LOG_PREFIX}{TEST_RESULT_LOG_EXT}"
TEST_BUILD_NAME = "test_build.sh"
EXTRA_INFO_FILE_NAME = "extrinfo.txt"
TEST_INFO_FILE_NAME = "llmtestinfo.txt"

# Token limits
STDOUT_MAX_TOKEN = 100000
STDERR_MAX_TOKEN = 10000
FILE_MAX_TOKEN = 8000
LLM_MAX_TOKEN = 12700

# Timeouts
TEST_TIMEOUT_MINUTES = 10

# Dev Tester
DEV_TESTER_DIR = "dev_tester"
CALLSTACK_DIR = "callstack"
CALL_STACK_MAKER_FILENAME = "call_stack_maker.sh"
DEV_TESTER_FILENAME = "dev_tester.sh"
DEV_TESTER_RESULT_FILENAME = "dev_tester_result.txt"
DEV_TESTER_MIN_CALLSTACK_FILES = (
    1  # Minimum number of callstack files required for success
)

# Search parameters
MAX_SEARCH_DEPTH = 3
MAX_FILE_COUNT = 10

# Information keys
LLMTESTINFO_KEY = "LLMTESTINFO"
LLM_TEST_INFO_KEY = "LLM_TEST_INFO"
EXTRINFO_KEY = "EXTRINFO"
EXTRA_INFO_KEY = "EXTRA_INFO"

# Major project list
MAJOR_PROJECT_NAMES = [
    # C/C++ (60)
    "openssl",
    "boost-beast",
    "boost",
    "boost-json",
    "libxml2",
    "apache-httpd",
    "libpng",
    "libssh2",
    "libssh",
    "curl",
    "zlib",
    "zlib-ng",
    "adal",
    "c-ares",
    "cjson",
    "civetweb",
    "croaring",
    "harfbuzz",
    "libevent",
    "libmodbus",
    "libsodium",
    "libxslt",
    "mbedtls",
    "miniz",
    "net-snmp",
    "nghttp2",
    "openexr",
    "openjpeg",
    "opus",
    "proj4",
    "rapidjson",
    "tinyxml2",
    "vorbis",
    "xz",
    "fmt",
    "hdf5",
    "lz4",
    "jackson-databind",
    "dropwizard",
    "netty",
    "javapoet",
    "apache-commons-io",
    "apache-commons-codec",
    "antlr4-java",
    "dom4j",
    "jfreechart",
    "json-java",
    "jsoup",
    "joda-time",
    "jakarta-mail-api",
    "spring-cloud-config",
    "llvm",
    "ffmpeg",
    "gstreamer",
    "libtiff",
    "libjpeg-turbo",
    "libarchive",
    "bzip2",
    "pcre2",
    "freetype2",
    # Java (40)
    "apache-commons-cli",
    "apache-commons-validator",
    "lucene",
    "jersey",
    "xstream",
    "httpcomponents-client",
    "spring-integration",
    "httpcomponents-core",
    "apache-commons-lang",
    "apache-commons-text",
    "jackson-core",
    "gson",
    "guava",
    "spring-boot",
    "hibernate-orm",
    "rxjava",
    "logback",
    "jetty",
    "spring-security",
    "retrofit",
    "spring-amqp",
    "tomcat",
    "mariadb",
    "struts",
    "quartz",
    "pdfbox",
    "spring-framework",
    "protobuf-java",
    "fastjson",
    "jsqlparser",
    "woodstox",
    "zxing",
    "httpcore",
    "jettison",
    "rome",
    "junrar",
    "spdlog",
    "jsoncpp",
    "simdjson",
    "libzip",
]
