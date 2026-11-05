#######
# Macro for adding a tinyml benchmark to CTest
#######
include(${TOOLCHAIN_TOP}/CMake/toolchain_build.cmake) #include toolchain macros
macro(add_Benchmark_Verilator TEST)

    # Check if verilator model is built  TODO: Implement check to confirm params are the same?
    if(NOT EXISTS "${VERILATOR_MODEL_DIR}/build/verilated_model")
        message(FATAL_ERROR "Verilator Model executable not present!  Build it and try again.")
    endif()

    set(TEST_NAME ${TEST}_Verilator)

    add_executable(${TEST_NAME})

    target_include_directories(${TEST_NAME} PRIVATE
        ${AES_TOP}/tiny-AES-c/
        ${AES_TOP}/generated/
        ${AES_TOP}/benchmarks/${TEST}
        ${FRAMEWORK_TOP}/
    )

    target_sources(${TEST_NAME} PUBLIC
        ${FRAMEWORK_TOP}/main.cpp
        ${AES_TOP}/benchmarks/${TEST}/benchmark.hpp
        ${AES_TOP}/generated/aes_kat.cpp
    )
    target_compile_definitions(${TEST_NAME} PUBLIC TEST_AES128=1)

    #Set Linker
    target_link_options(${TEST_NAME} PRIVATE "-nostartfiles")
    #target_link_options(${TEST_NAME} PRIVATE "-nostdlib")

    target_link_options(${TEST_NAME} PRIVATE "-T${VICUNA_BSP_TOP}/lld_link.ld")


    #Link BSP
    target_link_libraries(${TEST_NAME} PRIVATE bsp_Vicuna UART_Vicuna sim_Verilator)  

    add_custom_command(TARGET ${TEST_NAME}
                       POST_BUILD
                       COMMAND ${CMAKE_OBJCOPY} -O binary ${TEST_NAME}.elf ${TEST_NAME}.bin
                       COMMAND srec_cat ${TEST_NAME}.bin -binary -offset 0x0000 -byte-swap 4 -o ${TEST_NAME}.vmem -vmem
                       COMMAND rm -f prog_${TEST_NAME}.txt
                       COMMAND echo -n "${BUILD_DIR}/benchmark_sources/aes/${TEST_NAME}.vmem ${BUILD_DIR}/benchmark_sources/aes/${TEST_NAME}_unused.txt " > prog_${TEST_NAME}.txt
                       COMMAND readelf -s ${TEST_NAME}.elf | sed '2,13 s/ //1' | grep vref_start | cut -d " " -f 6 | tr [=["\n"]=] " " >> prog_${TEST_NAME}.txt
                       COMMAND readelf -s ${TEST_NAME}.elf | sed '2,13 s/ //1' | grep vref_end | cut -d " " -f 6 | tr [=["\n"]=] " " >> prog_${TEST_NAME}.txt
                       COMMAND echo -n "${BUILD_DIR}/benchmark_sources/aes/${TEST_NAME}_vicuna_sim_out.txt " >> prog_${TEST_NAME}.txt
                       COMMAND readelf -s ${TEST_NAME}.elf | sed '2,13 s/ //1' | grep vdata_start | cut -d " " -f 6 | tr [=["\n"]=] " " >> prog_${TEST_NAME}.txt
                       COMMAND readelf -s ${TEST_NAME}.elf | sed '2,13 s/ //1' | grep vdata_end | cut -d " " -f 6 | tr [=["\n"]=] " " >> prog_${TEST_NAME}.txt
                       COMMAND ${CMAKE_OBJDUMP} -D ${TEST_NAME}.elf > ${TEST_NAME}_dump.txt
                       )
    
    #VERY DANGEROUS TO USE TRACE

    #VERY DANGEROUS TO USE TRACE
    if(TRACE)
        set(VCD_TRACE_FLAG "--trace")
        set(VCD_TRACE_ARG "${BUILD_DIR}/benchmark_sources/aes/test_${TEST_NAME}_sig.vcd")
    else()
        set(VCD_TRACE_FLAG "")
        set(VCD_TRACE_ARG "")
    endif()

    if(COMMIT_LOG)
        set(COMMIT_FLAG "--commit")
        set(COMMIT_ARG "${BUILD_DIR}/benchmark_sources/aes/")
    else()
        set(COMMIT_FLAG "")
        set(COMMIT_ARG "")
    endif()

    #Add Test
    add_test(NAME ${TEST_NAME} 
             COMMAND ./${VERILATOR_MODEL_DIR}/build/verilated_model ${BUILD_DIR}/benchmark_sources/aes/prog_${TEST_NAME}.txt ${MEM_PORTS} ${MEM_W} 4194304 ${MEM_LATENCY} 1 ${TEST_NAME} ${VREG_W} 0 ${VCD_TRACE_FLAG} ${VCD_TRACE_ARG} ${COMMIT_FLAG} ${COMMIT_ARG}#TODO: PASS ALL THESE ARGUMENTS IN FROM USER
             WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/../..)
             
    set_tests_properties(${TEST_NAME} PROPERTIES TIMEOUT  1000) #TODO: Find a reasonable timeout for these tests

    message(STATUS "Successfully added ${TEST_NAME}")

endmacro()

# macro(add_Benchmark_Gem5 TEST SOURCE_DIR BINARY_DIR CONFIG_SCRIPT)
#     #Check if Gem5 simulator has been built.  If not build it. TODO: Currently, if changes are made to the rtl/verilator model, the gem5 build must be manually deleted to rebuild. Should automatically detect if new model has been generated and rebuild gem5
#     if(NOT EXISTS "${GEM5_MODEL_DIR}/gem5/build/ALL/gem5.opt" OR (REBUILD_GEM5 AND NOT REBUILT)) 
#         message("Gem5 executable not present!  Building it now.")
#         set(REBUILT ON)
#         # Make sure verilator C files have been built
#         if(NOT EXISTS "${VERILATOR_MODEL_DIR}/build/CMakeFiles/verilated_model.dir/Vvproc_top.dir/")
#             message(FATAL_ERROR "Verilator Model C Files not present!  Build the verilator model and try again.")
#         endif()
#         #${nproc} not parsing correctly?
#         execute_process(COMMAND scons EXTRAS=${GEM5_MODEL_DIR}/vicuna2_simobject -j32 build/ALL/gem5.opt 
#                             WORKING_DIRECTORY ${GEM5_MODEL_DIR}/gem5/)
#     endif()

#     set(TEST_NAME ${TEST}_Gem5_${CONFIG_SCRIPT})

#     add_executable(${TEST_NAME})

#     target_include_directories(${TEST_NAME} PRIVATE
#         ${SOURCE_DIR}
#         ${SOURCE_DIR}/model_data
#         ${FRAMEWORK_TOP}/
#     )

#     target_sources(${TEST_NAME} PUBLIC
#         ${FRAMEWORK_TOP}/main.cpp  
#         ${SOURCE_DIR}/${TEST}_data/${TEST}_input_data.cc
#         ${SOURCE_DIR}/${TEST}_data/${TEST}_input_data.h
#         ${SOURCE_DIR}/${TEST}_data/${TEST}_model_data.cc
#         ${SOURCE_DIR}/${TEST}_data/${TEST}_model_data.h
#         ${SOURCE_DIR}/${TEST}_data/${TEST}_model_settings.cc
#         ${SOURCE_DIR}/${TEST}_data/${TEST}_model_settings.h
#         ${SOURCE_DIR}/${TEST}_data/${TEST}_output_data_ref.cc
#         ${SOURCE_DIR}/${TEST}_data/${TEST}_output_data_ref.h
#     )
#     #Use default Linker TODO: use unified/standard one
#     #target_link_options(${TEST_NAME} PRIVATE "-nostartfiles")
#     #target_link_options(${TEST_NAME} PRIVATE "-T${VICUNA_BSP_TOP}/lld_link.ld")
#     #Link tflm (for gem5 only build no bsp/) TODO: UART_VICUNA isnt needed, but include wants it
#     target_link_libraries(${TEST_NAME} PRIVATE tflm sim_gem5)

#     add_custom_command(TARGET ${TEST_NAME}
#                        POST_BUILD
#                        COMMAND ${CMAKE_OBJDUMP} -D ${TEST_NAME}.elf > ${TEST_NAME}_dump.txt
#                        )
#     #Add Test # TODO: Current exit condition for gem5 is a segfault(from invalid uart write to be unified with other sim techniques) which reports test failed.  Improve exit conditions with gem5 API calls once generic testing structure is finished.
#     add_test(NAME ${TEST_NAME} 
#              COMMAND ${GEM5_MODEL_DIR}/gem5/build/ALL/gem5.opt ${GEM5_MODEL_DIR}/configuration_scripts/${CONFIG_SCRIPT}.py ${VREG_W} ${BINARY_DIR}/${TEST_NAME}.elf
#              WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
             
#     set_tests_properties(${TEST_NAME} PROPERTIES TIMEOUT 0) #TODO: Find a reasonable timeout for these tests

#     message(STATUS "Successfully added ${TEST_NAME}")
# endmacro()

# macro(add_Benchmark_Hybrid TEST SOURCE_DIR TEST_BUILD_DIR CONFIG_SCRIPT)
#     #Check if Gem5 simulator has been built.  If not build it. TODO: Currently, if changes are made to the rtl/verilator model, the gem5 build must be manually deleted to rebuild
#     if(NOT EXISTS "${GEM5_MODEL_DIR}/gem5/build/ALL/gem5.opt"  OR (REBUILD_GEM5 AND NOT REBUILT))
#         message("Gem5 executable not present!  Building it now.")
#         set(REBUILT ON)
#         # Make sure verilator C files have been built
#         if(NOT EXISTS "${VERILATOR_MODEL_DIR}/build/CMakeFiles/verilated_model.dir/Vvproc_top.dir/")
#             message(FATAL_ERROR "Verilator Model C Files not present!  Build the verilator model and try again.")
#         endif()
#         #${nproc} not parsing correctly?
#         execute_process(COMMAND scons EXTRAS=${GEM5_MODEL_DIR}/vicuna2_simobject -j32 build/ALL/gem5.opt 
#                             WORKING_DIRECTORY ${GEM5_MODEL_DIR}/gem5/)
#     endif()

#     set(TEST_NAME ${TEST}_Hybrid_${CONFIG_SCRIPT})

#     add_executable(${TEST_NAME})

#     target_include_directories(${TEST_NAME} PRIVATE
#         ${SOURCE_DIR}
#         ${SOURCE_DIR}/model_data
#         ${FRAMEWORK_TOP}/
#     )

#     target_sources(${TEST_NAME} PUBLIC
#         ${FRAMEWORK_TOP}/main.cpp
#         ${SOURCE_DIR}/${TEST}_data/${TEST}_input_data.cc
#         ${SOURCE_DIR}/${TEST}_data/${TEST}_input_data.h
#         ${SOURCE_DIR}/${TEST}_data/${TEST}_model_data.cc
#         ${SOURCE_DIR}/${TEST}_data/${TEST}_model_data.h
#         ${SOURCE_DIR}/${TEST}_data/${TEST}_model_settings.cc
#         ${SOURCE_DIR}/${TEST}_data/${TEST}_model_settings.h
#         ${SOURCE_DIR}/${TEST}_data/${TEST}_output_data_ref.cc
#         ${SOURCE_DIR}/${TEST}_data/${TEST}_output_data_ref.h
#     )
#     #Set Linker
#     target_link_options(${TEST_NAME} PRIVATE "-nostartfiles")
#     #target_link_options(${TEST_NAME} PRIVATE "-nostdlib")

#     target_link_options(${TEST_NAME} PRIVATE "-T${VICUNA_BSP_TOP}/lld_link.ld")


#     #Link BSP
#     target_link_libraries(${TEST_NAME} PRIVATE bsp_Vicuna UART_Vicuna tflm sim_hybrid)

#     add_custom_command(TARGET ${TEST_NAME}
#                        POST_BUILD
#                        COMMAND ${CMAKE_OBJDUMP} -D ${TEST_NAME}.elf > ${TEST_NAME}_dump.txt
#                        )

#     #Hybrid Sim allows trace outputs, should be able to enable it here
#     # set(INST_TRACE_ARGS "${BUILD_DIR}/Testing/inst_trace.txt")

#     # if(TRACE)
#     #     set(MEM_TRACE_ARGS "${BUILD_DIR}/Testing/last_test_mem.csv")
#     #     set(VCD_TRACE_ARGS "${BUILD_DIR}/Testing/last_test_sig.vcd")

#     # else()
#     #     set(MEM_TRACE_ARGS "")
#     #     set(VCD_TRACE_ARGS "")
#     # endif()
                       
	              
#   #Add Test
#         add_test(NAME ${TEST_NAME} 
#              COMMAND ${GEM5_MODEL_DIR}/gem5/build/ALL/gem5.opt ${GEM5_MODEL_DIR}/configuration_scripts/${CONFIG_SCRIPT}.py ${BINARY_DIR}/${TEST_NAME}.elf
#              WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})

#     set_tests_properties(${TEST_NAME} PROPERTIES TIMEOUT 60) #TODO: Find a reasonable timeout for these tests

#     message(STATUS "Successfully added ${TEST_NAME}")

# endmacro()

macro(add_Benchmark_Spike TEST)
    #Build spike if it isnt present
    build_spike()

    set(TEST_NAME ${TEST}_Spike)
    
    add_executable(${TEST_NAME})

    target_include_directories(${TEST_NAME} PRIVATE
        ${AES_TOP}/tiny-AES-c/
        ${AES_TOP}/generated/
        ${AES_TOP}/benchmarks/${TEST}
        ${FRAMEWORK_TOP}/
    )
    target_compile_definitions(${TEST_NAME} PUBLIC TEST_AES128=1)

    target_sources(${TEST_NAME} PUBLIC
        ${FRAMEWORK_TOP}/main.cpp
        ${FRAMEWORK_TOP}/vicuna2_bsp/crt0.S
        ${AES_TOP}/benchmarks/${TEST}/benchmark.hpp
        ${AES_TOP}/generated/aes_kat.cpp
    )

#     #Set Linker
    target_link_options(${TEST_NAME} PRIVATE "-nostartfiles")

    target_link_options(${TEST_NAME} PRIVATE "-T${FRAMEWORK_TOP}/vicuna2_bsp/lld_link.ld") #Spike address space starts at 0x80000000, needs different linker script
    #Link tflm and spike sim libraries
    target_link_libraries(${TEST_NAME} PRIVATE sim_spike)   

    add_custom_command(TARGET ${TEST_NAME}
                       POST_BUILD
                       COMMAND ${CMAKE_OBJDUMP} -D ${TEST_NAME}.elf > ${TEST_NAME}_dump.txt)    


    #Add Test
    add_test(NAME ${TEST_NAME} 
             COMMAND ${TOOLCHAIN_TOP}/spike/bin/spike --isa=rv32imf_zicntr_zihpm_zfh_zve32f_zvfh_zvl${VREG_W}b ${BUILD_DIR}/benchmark_sources/aes/${TEST_NAME}.elf 
             WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/../..)

    set_tests_properties(${TEST_NAME} PROPERTIES TIMEOUT 5) #TODO: Find a reasonable timeout for these tests

    message(STATUS "Successfully added ${TEST_NAME}")

 endmacro()




