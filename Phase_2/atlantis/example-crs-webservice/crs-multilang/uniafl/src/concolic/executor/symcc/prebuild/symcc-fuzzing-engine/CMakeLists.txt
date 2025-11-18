cmake_minimum_required(VERSION 3.10)
project(SymCCFuzzingEngine)
add_library(FuzzingEngine STATIC Main.cpp)
set_target_properties(FuzzingEngine PROPERTIES OUTPUT_NAME "SymCCFuzzingEngine")
