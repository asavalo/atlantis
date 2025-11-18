# fmt: off
# Define targets and their harnesses within the script
R2_TARGETS_CONFIG = {
    # full mode test
    "aixcc/jvm/r2-apache-commons-compress": [
        "CompressorGzipFuzzer",
        "CompressTarFuzzer",
        "CompressZipFuzzer",
        "ExpanderFuzzer"
    ],
    "aixcc/c/r2-freerdp": ["TestFuzzCoreServer"],
    "aixcc/jvm/r2-zookeeper": ["MultiProcessTxnFuzzer"],
    "aixcc/c/r2-libxml2": ["api", "xml"],
    "aixcc/c/r2-integration-test": ["fuzz_vuln"],
    "aixcc/c/r2-libpng": ["libpng_read_fuzzer"],
    "aixcc/c/r2-sqlite3": ["customfuzz3"],

    # diff mode test
    "aixcc/jvm/r2-zookeeper-diff-1": ["MessageTrackerPeekReceivedFuzzer"],
    "aixcc/jvm/r2-apache-commons-compress-diff-2": ["ExpanderFuzzer"],
    "aixcc/jvm/r2-apache-commons-compress-diff-1": ["CompressTarFuzzer"],
    "aixcc/c/r2-sqlite3-diff-1": ["customfuzz3"],
    "aixcc/c/r2-freerdp-diff-1": ["TestFuzzCryptoCertificateDataSetPEM"],
    "aixcc/c/r2-libxml2-diff-2": ["xml"],
    "aixcc/c/r2-libxml2-diff-1": ["html"],
}

TARGETS_CONFIG_SANITIY = {
    "aixcc/c/mock-c": ["fuzz_process_input_header", "fuzz_parse_buffer_section"],
    "aixcc/jvm/mock-java": ["OssFuzz1"],
    "aixcc/c/asc-nginx": ["pov_harness"],
    # "aixcc/jvm/olingo": ["OlingoOne"],
}

TARGET_CONFIG_STRESS = {
    "aixcc/c/stress-test": [
        "timeout-harness",
        "path-constraints-harness",
        "oom-harness",
        "stdout-spam-harness",
        "tempfile-harness",
        "deep-crash-harness",
        "forkbomb-harness",
        "unicode-harness",
        "fd-exhaustion-harness",
        "signals-harness",
        "longjmp-harness",
    ],
}

R3_TARGETS_CONFIG = {
    "aixcc/jvm/r3-apache-commons-compress": [
        # "ArchiverArFuzzer",
        # "ArchiverArjFuzzer",
        # "ArchiverCpioFuzzer",
        # "ArchiverDumpFuzzer",
        # "ArchiverTarStreamFuzzer",
        # "ArchiverZipStreamFuzzer",
        # "CompressorBZip2Fuzzer",
        # "CompressorDeflate64Fuzzer",
        "CompressorGzipFuzzer",
        # "CompressorLZ4Fuzzer",
        # "CompressorSnappyFuzzer",
        # "CompressorZFuzzer",
        # "CompressSevenZFuzzer",
        "CompressTarFuzzer",
        "CompressZipFuzzer",
        "ExpanderFuzzer"
    ],
    "aixcc/jvm/r3-zookeeper-delta-02": [
        # "DataTreeFuzzer",
        # "MessageTrackerPeekReceivedFuzzer",
        "MultiProcessTxnFuzzer",
        # "ProcessTxnFuzzer",
        # "SerializeFuzzer"
    ],
    "aixcc/jvm/r3-apache-commons-compress-delta-02": [
        # "ArchiverArFuzzer",
        # "ArchiverArjFuzzer",
        # "ArchiverCpioFuzzer",
        # "ArchiverDumpFuzzer",
        # "ArchiverTarStreamFuzzer",
        # "ArchiverZipStreamFuzzer",
        # "CompressorBZip2Fuzzer",
        # "CompressorDeflate64Fuzzer",
        # "CompressorGzipFuzzer",
        # "CompressorLZ4Fuzzer",
        # "CompressorSnappyFuzzer",
        # "CompressorZFuzzer",
        # "CompressSevenZFuzzer",
        # "CompressTarFuzzer",
        # "CompressZipFuzzer",
        "ExpanderFuzzer"
    ],
    "aixcc/jvm/r3-zookeeper-delta-01": [
        # "DataTreeFuzzer",
        "MessageTrackerPeekReceivedFuzzer",
        # "MultiProcessTxnFuzzer",
        # "ProcessTxnFuzzer",
        # "SerializeFuzzer"
    ],
    "aixcc/jvm/r3-tika": [
        # "HtmlParserFuzzer",
        # "M3U8ParserFuzzer",
        "RTFParserFuzzer",
        "TextAndCSVParserFuzzer",
        # "ThreeDXMLParserFuzzer",
        # "TikaAppRUnpackerFuzzer",
        "TikaAppUnpackerFuzzer",
        "TikaAppUntarringFuzzer",
        "XliffParserFuzzer"
    ],
    "aixcc/jvm/r3-tika-delta-05": [
        # "HtmlParserFuzzer",
        # "M3U8ParserFuzzer",
        # "RTFParserFuzzer",
        # "TextAndCSVParserFuzzer",
        # "ThreeDXMLParserFuzzer",
        # "TikaAppRUnpackerFuzzer",
        "TikaAppUnpackerFuzzer",
        # "TikaAppUntarringFuzzer",
        # "XliffParserFuzzer"
    ],
    "aixcc/jvm/r3-tika-delta-04": [
        # "HtmlParserFuzzer",
        # "M3U8ParserFuzzer",
        # "RTFParserFuzzer",
        # "TextAndCSVParserFuzzer",
        # "ThreeDXMLParserFuzzer",
        "TikaAppRUnpackerFuzzer",
        # "TikaAppUnpackerFuzzer",
        # "TikaAppUntarringFuzzer",
        # "XliffParserFuzzer"
    ],
    "aixcc/jvm/r3-tika-delta-03": [
        # "HtmlParserFuzzer",
        # "M3U8ParserFuzzer",
        # "RTFParserFuzzer",
        # "TextAndCSVParserFuzzer",
        "ThreeDXMLParserFuzzer",
        # "TikaAppRUnpackerFuzzer",
        # "TikaAppUnpackerFuzzer",
        # "TikaAppUntarringFuzzer",
        # "XliffParserFuzzer"
    ],
    "aixcc/jvm/r3-tika-delta-02": [
        # "HtmlParserFuzzer",
        "M3U8ParserFuzzer",
        # "RTFParserFuzzer",
        # "TextAndCSVParserFuzzer",
        # "ThreeDXMLParserFuzzer",
        # "TikaAppRUnpackerFuzzer",
        # "TikaAppUnpackerFuzzer",
        # "TikaAppUntarringFuzzer",
        # "XliffParserFuzzer"
    ],
    "aixcc/jvm/r3-zookeeper": [
        # "DataTreeFuzzer",
        # "MessageTrackerPeekReceivedFuzzer",
        "MultiProcessTxnFuzzer",
        # "ProcessTxnFuzzer",
        # "SerializeFuzzer"
    ],
    "aixcc/jvm/r3-apache-commons-compress-delta-01": [
        # "ArchiverArFuzzer",
        # "ArchiverArjFuzzer",
        # "ArchiverCpioFuzzer",
        # "ArchiverDumpFuzzer",
        # "ArchiverTarStreamFuzzer",
        # "ArchiverZipStreamFuzzer",
        # "CompressorBZip2Fuzzer",
        # "CompressorDeflate64Fuzzer",
        # "CompressorGzipFuzzer",
        # "CompressorLZ4Fuzzer",
        # "CompressorSnappyFuzzer",
        # "CompressorZFuzzer",
        # "CompressSevenZFuzzer",
        "CompressTarFuzzer",
        # "CompressZipFuzzer",
        # "ExpanderFuzzer"
    ],
    "aixcc/jvm/r3-tika-delta-01": [
        "HtmlParserFuzzer",
        # "M3U8ParserFuzzer",
        # "RTFParserFuzzer",
        # "TextAndCSVParserFuzzer",
        # "ThreeDXMLParserFuzzer",
        # "TikaAppRUnpackerFuzzer",
        # "TikaAppUnpackerFuzzer",
        # "TikaAppUntarringFuzzer",
        # "XliffParserFuzzer"
    ],
    "aixcc/c/r3-sqlite3-delta-01": [
        # "ossfuzz",
        "customfuzz3"
    ],
    # "aixcc/c/r3-dropbear": [
    #     "fuzzer-cliconf",
    #     "fuzzer-client",
    #     "fuzzer-client_nomaths",
    #     "fuzzer-kexcurve25519",
    #     "fuzzer-kexdh",
    #     "fuzzer-kexecdh",
    #     "fuzzer-kexmlkem-cli",
    #     "fuzzer-kexmlkem-srv",
    #     "fuzzer-kexsntrup-cli",
    #     "fuzzer-kexsntrup-srv",
    #     "fuzzer-postauth_nomaths",
    #     "fuzzer-preauth",
    #     "fuzzer-preauth_nomaths",
    #     "fuzzer-pubkey",
    #     "fuzzer-verify"
    # ],
    "aixcc/c/r3-libpng-delta-01": [
        "libpng_read_fuzzer",
    ],
    # "aixcc/c/r3-libpostal": [
    #     "libpostal_string_utils_fuzzer"
    # ],
    "aixcc/c/r3-sqlite3-delta-03": [
        # "ossfuzz",
        "customfuzz3",
    ],
    "aixcc/c/r3-sqlite3": [
        # "ossfuzz",
        "customfuzz3",
    ],
    "aixcc/c/r3-curl-delta-01": [
        # "curl_fuzzer",
        # "curl_fuzzer_bufq",
        # "curl_fuzzer_dict",
        # "curl_fuzzer_file",
        # "curl_fuzzer_ftp",
        # "curl_fuzzer_gopher",
        # "curl_fuzzer_http",
        # "curl_fuzzer_https",
        # "curl_fuzzer_imap",
        # "curl_fuzzer_mqtt",
        # "curl_fuzzer_pop3",
        # "curl_fuzzer_rtsp",
        # "curl_fuzzer_smb",
        # "curl_fuzzer_smtp",
        # "curl_fuzzer_tftp",
        "curl_fuzzer_ws",
        # "fuzz_url"
    ],
    "aixcc/c/r3-curl": [
        "curl_fuzzer",
        # "curl_fuzzer_bufq",
        # "curl_fuzzer_dict",
        # "curl_fuzzer_file",
        # "curl_fuzzer_ftp",
        # "curl_fuzzer_gopher",
        # "curl_fuzzer_http",
        # "curl_fuzzer_https",
        # "curl_fuzzer_imap",
        # "curl_fuzzer_mqtt",
        # "curl_fuzzer_pop3",
        # "curl_fuzzer_rtsp",
        # "curl_fuzzer_smb",
        # "curl_fuzzer_smtp",
        # "curl_fuzzer_tftp",
        # "curl_fuzzer_ws",
        # "fuzz_url"
    ],
    "aixcc/c/r3-integration-test": [
        "fuzz_vuln"
    ],
    "aixcc/c/r3-libxml2-delta-02": [
        # "api",
        # "html",
        # "lint",
        # "reader",
        # "regexp",
        # "schema",
        # "uri",
        # "valid",
        # "xinclude",
        "xml",
        # "xpath"
    ],
    "aixcc/c/r3-sqlite3-delta-02": [
        # "ossfuzz",
        "customfuzz3"
    ],
    "aixcc/c/r3-freerdp": [
        # "TestFuzzCodecs",
        # "TestFuzzCommonAssistanceBinToHexString",
        # "TestFuzzCommonAssistanceHexStringToBin",
        # "TestFuzzCommonAssistanceParseFileBuffer",
        # "TestFuzzCoreClient",
        "TestFuzzCoreServer",
        # "TestFuzzCryptoCertificateDataSetPEM"
    ],
    "aixcc/c/r3-libxml2-delta-01": [
        # "api",
        "html",
        # "lint",
        # "reader",
        # "regexp",
        # "schema",
        # "uri",
        # "valid",
        # "xinclude",
        # "xml",
        # "xpath"
    ],
    "aixcc/c/r3-freerdp-delta-01": [
        # "TestFuzzCodecs",
        # "TestFuzzCommonAssistanceBinToHexString",
        # "TestFuzzCommonAssistanceHexStringToBin",
        # "TestFuzzCommonAssistanceParseFileBuffer",
        # "TestFuzzCoreClient",
        # "TestFuzzCoreServer",
        "TestFuzzCryptoCertificateDataSetPEM"
    ],
    "aixcc/c/r3-libexif-delta-01": [
        "exif_from_data_fuzzer",
        "exif_loader_fuzzer"
    ]
}


OUR_TARGETS_CONFIG = {
    "aixcc/c/asc-nginx": [
        # "mail_request_harness",
        "pov_harness",
        # "smtp_harness"
    ],
    # "aixcc/c/babynginx": [
    #     "http_request_fuzzer",
    #     "http_request_patched_fuzzer"
    # ],
    # "aixcc/c/babynote": [
    #     "filein_harness"
    # ],
    "aixcc/c/concolic-test": [
        "basic_harness",
        "read_harness",
        "scanf_harness",
        "simd_harness"
    ],
    # "aixcc/c/faad2": [
    #     "fuzz_decode_drm_fixed",
    #     "fuzz_decode_fixed"
    # ],
    # "aixcc/c/file": [
    #     "magic_fuzzer_fd",
    #     "magic_fuzzer_loaddb"
    # ],
    # "aixcc/c/hdf5-58622": [
    #     "h5_extended_fuzzer"
    # ],
    # "aixcc/c/hdf5-58701": [
    #     "h5_extended_fuzzer"
    # ],
    # "aixcc/c/itoa": [
    #     "filein_harness"
    # ],
    "aixcc/c/jq": [
        "jq_fuzz_fixed",
        # "jq_fuzz_parse_extended"
    ],
    "aixcc/c/libavc": [
        "mvc_dec_fuzzer",
        "svc_dec_fuzzer"
    ],
    # "aixcc/c/libcue": [
    #     "fuzz"
    # ],
    # "aixcc/c/libjpeg-vulnloc-cve-2018-14498": [
    #     "libjpeg_cjpeg_fuzzer"
    # ],
    "aixcc/c/libjpeg-vulnloc-cve-2018-19664": [
        "libjpeg_djpeg_fuzzer"
    ],
    # "aixcc/c/libtiff": [
    #     "tiffcp",
    #     "tiffinfo",
    #     "tiff_open",
    #     "tiff_read_rgba_tile_ext"
    # ],
    "aixcc/c/libxml2": [
        "api"
    ],
    # "aixcc/c/mock-c": [
    #     "fuzz_parse_buffer_section",
    #     "fuzz_process_input_header"
    # ],
    # "aixcc/c/mock-cp": [
    #     "filein_harness"
    # ],
    "aixcc/c/nasm": [
        "fuzz_nasm"
    ],
    "aixcc/c/rpn-calculator": [
        "filein_harness"
    ],
    # "aixcc/c/selinux-28654": [
    #     "secilc-fuzzer"
    # ],
    # # "aixcc/c/selinux-30717": [
    # #     "secilc-fuzzer"
    # # ],
    # "aixcc/c/selinux-30775": [
    #     "secilc-fuzzer"
    # ],
    # "aixcc/c/selinux-42729": [
    #     "binpolicy-fuzzer"
    # ],
    # "aixcc/c/selinux-42741": [
    #     "binpolicy-fuzzer"
    # ],
    # "aixcc/c/selinux-60583": [
    #     "binpolicy-fuzzer"
    # ],
    # "aixcc/c/simple-switch": [
    #     "ossfuzz-1"
    # ],
    # "aixcc/c/timeouts-and-crashes": [
    #     "signal_harness",
    #     "timeout_harness"
    # ],
    "aixcc/c/tmux": [
        "input-fuzzer"
    ],
    "aixcc/c/user-nginx": [
        "pov_harness"
    ],
    "aixcc/jvm/activemq": [
        "ActivemqOne",
        "ActivemqOneFDP"
    ],
    "aixcc/jvm/activemq-var": [
        "ActivemqVariantOne",
        "ActivemqVariantOneFDP"
    ],
    "aixcc/jvm/aerospike": [
        "AerospikeOne"
    ],
    "aixcc/jvm/apache-commons-validator": [
        "UrlValidator2Fuzzer"
    ],
    "aixcc/jvm/apache-commons-validator-diff": [
        "UrlValidator2Fuzzer"
    ],
    "aixcc/jvm/batik": [
        "BatikOne",
        "BatikOneFDP"
    ],
    "aixcc/jvm/bcel": [
        "BCELOne",
        "BCELOneFDP"
    ],
    "aixcc/jvm/beanutils": [
        "BeanUtilsOne"
    ],
    "aixcc/jvm/cron-utils": [
        "CronUtilsOne",
        "CronUtilsOneFDP"
    ],
    "aixcc/jvm/cxf": [
        "CXFOne",
        "CXFThree",
        "CXFTwo"
    ],
    "aixcc/jvm/feign": [
        "BodyTemplateFuzzer"
    ],
    "aixcc/jvm/fuzzy": [
        "FuzzyOne",
        "FuzzyOneFDP"
    ],
    "aixcc/jvm/geonetwork": [
        "GeonetworkOne",
        "GeonetworkOneFDP"
    ],
    "aixcc/jvm/htmlunit": [
        "HtmlunitOne",
        "HtmlunitOneFDP"
    ],
    "aixcc/jvm/imaging": [
        "ImagingOne",
        "ImagingOneFDP",
        "ImagingTwo",
        "ImagingTwoFDP"
    ],
    "aixcc/jvm/jackson-databind": [
        "JacksonDatabindOne",
        "JacksonDatabindOneFDP"
    ],
    "aixcc/jvm/jakarta-mail-api": [
        "MailApiHarnessOne",
        "MailApiHarnessOneFDP"
    ],
    "aixcc/jvm/jenkins": [
        "JenkinsFive",
        "JenkinsFiveFDP",
        "JenkinsFour",
        "JenkinsThree",
        "JenkinsThreeFDP",
        "JenkinsTwo",
        "JenkinsTwoFDP"
    ],
    "aixcc/jvm/json-java": [
        "JsonJavaFuzzer"
    ],
    "aixcc/jvm/jsoup": [
        "HtmlFuzzer"
    ],
    "aixcc/jvm/keycloak": [
        "ServicesUtilsFuzzer"
    ],
    "aixcc/jvm/kylin": [
        "KylinOne"
    ],
    "aixcc/jvm/lucene": [
        "IndexSearchFuzzer"
    ],
    # "aixcc/jvm/mock-java": [
    #     "OssFuzz1"
    # ],
    "aixcc/jvm/netty": [
        "ByteBufUtilFuzzer",
        # "HttpRequestDecoderFuzzer",
        # "ServerCookieDecoderFuzzer"
    ],
    # "aixcc/jvm/olingo": [
    #     "OlingoOne",
    #     "OlingoOneFDP"
    # ],
    "aixcc/jvm/oripa": [
        "OripaOne",
        "OripaOneFDP"
    ],
    "aixcc/jvm/pac4j": [
        "Pac4jOne"
    ],
    "aixcc/jvm/rdf4j": [
        "Rdf4jOne"
    ],
    "aixcc/jvm/shiro": [
        "ShiroOne"
    ],
    "aixcc/jvm/snappy-java": [
        "BitShuffleFuzzer",
        "SnappyStreamFuzzer"
    ],
    "aixcc/jvm/spring-framework": [
        "SpelExpressionFuzzer"
    ],
    "aixcc/jvm/sqlite-jdbc": [
        "SqliteConnectionFuzzer"
    ],
    "aixcc/jvm/struts": [
        "StrutsOne"
    ],
    "aixcc/jvm/tika": [
        "TikaOne",
        "TikaTwo"
    ],
    "aixcc/jvm/widoco": [
        "WidocoOne"
    ],
    "aixcc/jvm/xstream": [
        "XmlFuzzer"
    ],
    "aixcc/jvm/ztzip": [
        "ZTZIPOne"
    ],
    "aixcc/cpp/cp-user-opencv": [
        "harness",
        "harness_fdp",
    ],
    "aixcc/cpp/cp-user-openssl": [
        # "decoder",
        # "pem",
        # "pem_fdp",
        # "punycode",
        "x509",
        "ossfuzz",
        "libpng_read_fuzzer",
    ],
    # "aixcc/cpp/mock-cpp": [
    #     "ossfuzz-1",
    #     "ossfuzz-2",
    # ],
}


R3_TARGETS_FILTERED_CONFIG = {
    "aixcc/jvm/r3-tika-delta-03": [
        "ThreeDXMLParserFuzzer",
    ],
    "aixcc/jvm/r3-apache-commons-compress": [
        "CompressTarFuzzer",
        "CompressZipFuzzer",
        "ExpanderFuzzer",
    ],
    "aixcc/jvm/r3-tika": [
        "RTFParserFuzzer",
        "TikaAppUnpackerFuzzer",
        "XliffParserFuzzer",
    ],
    "aixcc/jvm/r3-zookeeper": [
        "MultiProcessTxnFuzzer",
    ],
    "aixcc/c/r3-sqlite3": [
        "customfuzz3",
    ],
    "aixcc/c/r3-curl-delta-01": [
        "curl_fuzzer_ws",
    ],
    "aixcc/c/r3-sqlite3-delta-02": [
        "customfuzz3",
    ],
    "aixcc/c/r3-freerdp": [
        "TestFuzzCoreServer",
    ],
    "aixcc/c/r3-freerdp-delta-01": [
        "TestFuzzCryptoCertificateDataSetPEM",
    ],
    "aixcc/c/r3-libexif-delta-01": [
        "exif_from_data_fuzzer",
        "exif_loader_fuzzer",
    ]
}


R3_TARGETS_FILTERED_CONFIG2 = {
    "aixcc/c/r3-curl-delta-01": [
        "curl_fuzzer_ws",
    ],
    "aixcc/jvm/r3-apache-commons-compress": [
        "CompressTarFuzzer",
    ],
    "aixcc/jvm/r3-tika-delta-03": [
        "ThreeDXMLParserFuzzer",
    ],
    "aixcc/jvm/r3-tika": [
        "TikaAppUnpackerFuzzer",
    ],
    "aixcc/jvm/r3-zookeeper": [
        "MultiProcessTxnFuzzer",
    ],
}


# TARGETS_CONFIG = R3_TARGETS_CONFIG
# TARGETS_CONFIG = OUR_TARGETS_CONFIG
# TARGETS_CONFIG = R2_TARGETS_CONFIG
# TARGETS_CONFIG = TARGETS_CONFIG_SANITIY
# TARGETS_CONFIG = R3_TARGETS_FILTERED_CONFIG
TARGETS_CONFIG = R3_TARGETS_FILTERED_CONFIG2

# Input generation combinations to test
INPUT_GEN_COMBINATIONS = [
    # # ["mlla"],
    # ["given_fuzzer"],
    # ["given_fuzzer", "mlla"],
    # ["given_fuzzer", "testlang_input_gen"],
    # ["given_fuzzer", "dict_input_gen"],
    ["given_fuzzer", "concolic_input_gen", "testlang_input_gen", "dict_input_gen", "mlla"],
    # ["given_fuzzer", "concolic_input_gen"],
]

# Configuration constants
# NCPU_PER_RUN = 64                    # CPU cores per harness
# EVAL_DURATION_SECONDS = 60 * 60     # Evaluation time in seconds for each CP


# NCPU_PER_RUN = 8                    # CPU cores per harness
# EVAL_DURATION_SECONDS = 60 * 30     # Evaluation time in seconds for each CP

NCPU_PER_RUN = 24                    # CPU cores per harness
EVAL_DURATION_SECONDS = 60 * 60 * 2  # Evaluation time in seconds for each CP


#######
PYENV_ENV_NAME = "crs-e2e-experiments"  # This will be set by install_deps.sh
# fmt: on
