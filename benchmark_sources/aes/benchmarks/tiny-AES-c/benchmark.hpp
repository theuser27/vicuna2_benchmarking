#ifndef BENCHMARK_HPP
#define BENCHMARK_HPP 

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#if TEST_AES256 == 1
    #define AES256 1
    #define GET_SERIALISED_ARRAY(name) name##256, name##256##_count
#elif TEST_AES192 == 1
    #define AES192 1
    #define GET_SERIALISED_ARRAY(name) name##192, name##192##_count
#elif TEST_AES128 == 1
    #define AES128 1
    #define GET_SERIALISED_ARRAY(name) name##128, name##128##_count
#else
    #error No AES size has been defined
#endif

//Includes for benchmark
#include <aes_kat.hpp>
extern "C"
{
    #include <aes.h>
    #include <aes.c>
}

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
        AES_ctx context;
        uint8_t output[AES_BLOCKLEN];

        for (size_t i = 0; i < test_case_count; ++i)
        {
            // keys and in/output buffers need to match sizes expected by the algorithm
            assert(test_cases[i].key_length == AES_KEYLEN);
            assert(test_cases[i].input_output_length == AES_BLOCKLEN);

            if (mode == AESMode::CBCMode)
            {
                AES_init_ctx_iv(&context, test_cases[i].key, test_cases[i].init_vector);

                if (test_cases[i].is_decrypting)
                    AES_CBC_decrypt_buffer(&context, output, test_cases[i].input_output_length);
                else
                    AES_CBC_encrypt_buffer(&context, output, test_cases[i].input_output_length);
            }
            else if (mode == AESMode::ECBMode)
            {
                AES_init_ctx(&context, test_cases[i].key);
                if (test_cases[i].is_decrypting)
                    AES_ECB_encrypt(&context, output);
                else
                    AES_ECB_decrypt(&context, output);
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
                for (size_t j = 0; j < AES_BLOCKLEN; ++j)
                    fprintf(stderr, "%X ", test_cases[i].output[j]);
                fprintf(stderr, "\nReceived: ");
                for (size_t j = 0; j < AES_BLOCKLEN; ++j)
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
        fail_count += run_test(GET_SERIALISED_ARRAY(CBCVarKey), AESMode::CBCMode);
        fail_count += run_test(GET_SERIALISED_ARRAY(CBCVarTxt), AESMode::CBCMode);
        fail_count += run_test(GET_SERIALISED_ARRAY(ECBVarKey), AESMode::ECBMode);
        fail_count += run_test(GET_SERIALISED_ARRAY(ECBVarTxt), AESMode::ECBMode);

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
