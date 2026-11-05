###########
# Add test addition macros
###########
include(${CMAKE_CURRENT_SOURCE_DIR}/CMake/add_test.cmake)


###########
# Create Lib - benchmark suite has its own reduced version of CMSIS-DSP
###########
set(AES_TOP ${CMAKE_CURRENT_SOURCE_DIR}/)

###########
# Add tests for the benchmark suite
###########

#Set location for build binaries
set(BINARY_DIR ${BUILD_DIR}/benchmark_sources/aes/)

file(GLOB folders "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/*" )
foreach(item ${folders})
    string(REPLACE "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/" "" bm ${item})
    if (${VERILATOR_SIM})
    	add_Benchmark_Verilator(${bm})
    endif()
    if (${GEM5_SIM})
    	#add_Benchmark_Gem5(toycar_int8 ${CMAKE_CURRENT_SOURCE_DIR}/Int8/toycar/ ${BINARY_DIR} gem5_caches)
    endif()
    if (${HYBRID_GEM5_SIM})
    	#add_Benchmark_Hybrid(toycar_int8 ${CMAKE_CURRENT_SOURCE_DIR}/Int8/toycar/ ${BINARY_DIR} hybrid_caches)
    	#add_Benchmark_Hybrid(toycar_int8 ${CMAKE_CURRENT_SOURCE_DIR}/Int8/toycar/ ${BINARY_DIR} hybrid_only)
    endif()
    if(${SPIKE_SIM})
    	add_Benchmark_Spike(${bm})
    endif()
endforeach()

