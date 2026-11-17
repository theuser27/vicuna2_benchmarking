#ifndef SIMULATOR_HPP
#define SIMULATOR_HPP 

#include <cstdint>


#include <cstdint>
class Simulator
{
    private:

    // Stats variables
    uint32_t start_cycles, start_instr;
    uint32_t end_cycles, end_instr;

    public:

    Simulator(){};

    //Function to start measurement TODO: Spike output for instructions executed
    inline void begin_measurement()
    {
    };

    //Function to end measurement
    inline void end_measurement()
    {

    };

    //Termination success or failure function for this simulator
    int terminate(int return_code)
    {
         if (return_code == 0)
        {
            __asm__ volatile("li t0, 0x00000001");     //LSB exits spike, all other bits signal failure
            __asm__ volatile("la t1, tohost");
            __asm__ volatile("auipc t2, 0x0");
            __asm__ volatile("sw t0, 0(t1)");
            __asm__ volatile("jalr x0, 4(t2)");

        } else {
            __asm__ volatile("li t0, 0xFFFFFFFF");     //LSB exits spike, all other bits signal failure
            __asm__ volatile("la t1, tohost");
            __asm__ volatile("auipc t2, 0x0");
            __asm__ volatile("sw t0, 0(t1)");
            __asm__ volatile("jalr x0, 4(t2)");
        }

        return 0;
    };

    //Cleanup any allocatations
    ~Simulator(){};
};
#endif
