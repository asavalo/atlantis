add_library(msa_sync STATIC election.cpp lock.cpp)

find_library(ZOOKEEPER_LIB zookeeper_mt)
if(NOT ZOOKEEPER_LIB)
    message(FATAL_ERROR "ZooKeeper library not found. Please install it on your system.")
endif()

target_link_libraries(msa_sync
    PRIVATE
    ${ZOOKEEPER_LIB}
)