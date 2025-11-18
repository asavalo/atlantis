set(SymCCRtSrc
  ${SHARED_RUNTIME_SOURCES}
  Runtime.cpp)

add_library(SymCCRtObj OBJECT
        ${SymCCRtSrc})

set_property(TARGET SymCCRtObj PROPERTY POSITION_INDEPENDENT_CODE 1)

add_library(SymCCRtShared SHARED $<TARGET_OBJECTS:SymCCRtObj>)
add_library(SymCCRtStatic STATIC $<TARGET_OBJECTS:SymCCRtObj>)

target_include_directories(SymCCRtObj PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}     # for our fake pin.H and Runtime.h
  ${SYMCC_RT_INCLUDE_DIR}) # for common runtime components

target_include_directories(SymCCRtObj SYSTEM PRIVATE
  ${QSYM_SOURCE_DIR})

target_link_libraries(SymCCRtShared PRIVATE
 c++ pthread) 
