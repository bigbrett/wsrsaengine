[![experimental](http://badges.github.io/stability-badges/dist/experimental.svg)](http://github.com/badges/stability-badges)
# wsrsaengine
A minimal openSSL engine for offloading rsa functions to a hardware accelerator in FPGA logic

## Prerequisites
1. You are running linux on the Xilinx ZYNQ-7000 development board, with the necessary design instantiated in PL [link to final design goes here]
2. Ensure you have openSSL using the command `$ openssl version`. If you have lower than version 1.0.2, you must upgrade to this version.
3. Check out the repository using git `$ git clone https://github.com/bigbrett/wsrsaengine.git` 

## Building the engine

    $ cd wsrsaengine
    $ make

You can verify that the engine can be loaded using: 

    $ openssl engine -t -c `pwd`/bin/libwsrsaengine.so
    (/home/brett/wsrsaengine/bin/libwsrsaengine.so) A test engine for the ws rsa hardware encryption module, on the Xilinx ZYNQ7000
    Loaded: (wsrsaengine) A test engine for the ws rsa hardware encryption module, on the Xilinx ZYNQ7000
        [ available ]

## Testing the engine
### Quck test
A quick and easy test goes like this, where the output of the decryption should match the input: 

TODO

### Custom Test
A more advanced test, using a c test program, can be conducted like this (see test/wsrsaengine\_test.c for implementation): 
    
    $ make test
    $ source test/runtest.sh

NOTE: the runtest.sh script must remain in the test directory, but should be able to be called from anywhere
    
### OpenSSL speed test
The speed of the engine's encryption/decryption can be tested using the built-in openSSL speed command 

    $ openssl speed rsa1024 -engine /path/to/libwsrsaengine.so


