#ifndef BENCHMARK_HPP
#define BENCHMARK_HPP 

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#if TEST_AES256 == 1
    #define AES256 1
    #define GET_SERIALISED_ARRAY(name) name##256, name##256##_count
#elif TEST_AES128 == 1
    #define AES128 1
    #define GET_SERIALISED_ARRAY(name) name##128, name##128##_count
#else
    #error No AES size has been defined
#endif

// Includes for benchmark
extern "C"
{
    #include <aes.h>
    #include <aes.c>
}
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
        AES_ctx context;
        uint8_t output[AES_BLOCKLEN];

        for (size_t i = 0; i < test_case_count; ++i)
        {
            // keys and in/output buffers need to match sizes expected by the algorithm
            assert(test_cases[i].key_length == AES_KEYLEN);
            assert(test_cases[i].input_output_length == AES_BLOCKLEN);

            memcpy(output, test_cases[i].input, sizeof(output));
            
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
                    AES_ECB_decrypt(&context, output);
                else
                    AES_ECB_encrypt(&context, output);
            }
            else
            {
                // missing mode
                assert(false);
            }

            if (memcmp(test_cases[i].output, output, sizeof(output)))
                ++fail_count;
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
