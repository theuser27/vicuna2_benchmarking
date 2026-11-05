#ifndef BENCHMARK_HPP
#define BENCHMARK_HPP 

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#if TEST_AES256 == 1
    #define AES256 1
    #define GET_SERIALISED_ARRAY(name) name##256, name##256##_count
    #define ENCRYPT_ECB aes256_ecb_encrypt_rvv
    #define DECRYPT_ECB aes256_ecb_decrypt_rvv
    #define ENCRYPT_CBC aes256_cbc_encrypt_rvv
    #define DECRYPT_CBC aes256_cbc_decrypt_rvv
#elif TEST_AES192 == 1
    #define AES192 1
    #define GET_SERIALISED_ARRAY(name) name##192, name##192##_count
    #define ENCRYPT_ECB aes192_ecb_encrypt_rvv
    #define DECRYPT_ECB aes192_ecb_decrypt_rvv
    #define ENCRYPT_CBC aes192_cbc_encrypt_rvv
    #define DECRYPT_CBC aes192_cbc_decrypt_rvv
#elif TEST_AES128 == 1
    #define AES128 1
    #define GET_SERIALISED_ARRAY(name) name##128, name##128##_count
    #define ENCRYPT_ECB aes128_ecb_encrypt_rvv
    #define DECRYPT_ECB aes128_ecb_decrypt_rvv
    #define ENCRYPT_CBC aes128_cbc_encrypt_rvv
    #define DECRYPT_CBC aes128_cbc_decrypt_rvv
#else
    #error No AES size has been defined
#endif

//Includes for benchmark
#include "implementation.hpp"
#include <aes_kat.hpp>

class Benchmark
{
    private:
    /*
    * Private Helper Functions and variables
    */
    enum class AESMode { CBCMode, ECBMode };
    int fail_count = 0;

    void run_test(const AESParameters *test_cases, size_t test_case_count, AESMode mode)
    {
        uint8_t output[16];

        for (size_t i = 0; i < test_case_count; ++i)
        {
            // keys and in/output buffers need to match sizes expected by the algorithm
            assert(test_cases[i].input_output_length == sizeof(output));

            size_t nblocks = test_cases[i].input_output_length / 16;

            if (mode == AESMode::CBCMode)
            {
                if (test_cases[i].is_decrypting)
                    DECRYPT_CBC(test_cases[i].input, output, 
                        nblocks, test_cases[i].key, test_cases[i].init_vector);
                else
                    ENCRYPT_CBC(test_cases[i].input, output, 
                        nblocks, test_cases[i].key, test_cases[i].init_vector);
            }
            else if (mode == AESMode::ECBMode)
            {
                if (test_cases[i].is_decrypting)
                    DECRYPT_ECB(test_cases[i].input, output, nblocks, test_cases[i].key);
                else
                    ENCRYPT_ECB(test_cases[i].input, output, nblocks, test_cases[i].key);
            }
            else
            {
                // missing mode
                assert(false);
            }

            if (memcmp(test_cases[i].output, output, sizeof(output)))
            {
                ++fail_count;
                fprintf(stderr, "\n\nExpected: ");
                for (size_t j = 0; j < sizeof(output); ++j)
                    fprintf(stderr, "%X ", test_cases[i].output[j]);
                fprintf(stderr, "\nReceived: ");
                for (size_t j = 0; j < sizeof(output); ++j)
                    fprintf(stderr, "%X ", output[j]);
            }
        }
    }

    public:
    /*
    * Required Functions for test framework
    */
    Benchmark()
    {
        fail_count = 0;
    };

    //Call code to be benchmarked
    int run_benchmark()
    {
        run_test(GET_SERIALISED_ARRAY(CBCVarKey), AESMode::CBCMode);
        run_test(GET_SERIALISED_ARRAY(CBCVarTxt), AESMode::CBCMode);
        run_test(GET_SERIALISED_ARRAY(ECBVarKey), AESMode::ECBMode);
        run_test(GET_SERIALISED_ARRAY(ECBVarTxt), AESMode::ECBMode);

        return 0; //cannot fail internally
    };

    //Validate Output
    int validate_benchmark()
    {
        return fail_count;
    };

    //Cleanup any allocatations
    ~Benchmark()
    {
    };
};
#endif
