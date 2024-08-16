# General
Contains the Noise-C reference implementation of Noise with our additions of the PQNoise and hybrid patterns. Additionally, contains the code used for the evaluation as well.


## Prerequisites
This code has been tested and works fine on Ubuntu 22.04.04 LTS and Armbian 24.5.1 Jammy.

Needs liboqs installed to run, since their implementation of kyber is used, specifically Kyber512. The install instructions can be found on their github : "https://github.com/open-quantum-safe/liboqs", however we need to create a shared library, so "-DBUILD_SHARED_LIBS=ON" has to be appended to the "cmake -GNinja .." command, as written in their instructions.
Then run  "sudo ldconfig" to update the ldconfig path. If it doesn't work then add a new .config file in /etc/ld.so.conf.d and add the path to the libraries install directory, followed by running "sudo ldconfig".

Any existing prerequities for Noise-C still apply, and instructions for Noise-C can be found in their documentation: http://rweather.github.io/noise-c/index.html.


To run the post-quantum and hybrid TLS timing tests:

Needs openssl 3.x installed, a version that works should be pre-installed on any system with Ubuntu 22.04 or higher, not sure for earlier versions. 
Need to install and activate oqsprovider, to do so simply follow the build and install instructions on their github https://github.com/open-quantum-safe/oqs-provider. Their github also contains instructions on how to activate and use the oqsprovider, for our tests we need to explicitly activate the following algorithms: X25519, kyber512, x25519_kyber512


Additional instructions when running on a similar Board that we used:
We are measuring the computational time taken by the Noise patterns in both ms and cpu-cycles, on our board this became an issue as the registers were not readable by users. To avoid this either we first needed to install some missing kernel headers, if using an Armbian version of Ubuntu like we did, then this can be done using their Armbian-config tool. Other OS versions might not have this header issue but we don't know for sure. Next we then need to install a kernel module that changes the permissions on the registers, using the code and following the instructions from this github worked fine for us: https://github.com/thoughtpolice/enable_arm_pmu, further information for that specific code can also be found in the following blog post of the same author: http://neocontra.blogspot.com/2013/05/user-mode-performance-counters-for.html-




## Changes that were made to the existing implementations


### Noise-c

#### Adding PQNoise

**src/protocol/patterns.c**: Added the PQNoise patterns and added translation for ID lookup for them.

**src/protocol/names.c**: Added the new patterns as well as an ID for Kyber(as a replacement for the DH algo to be used with the PQNoise patterns) to the ID mapping.

**include/noise/protocol/constants.h**: Added the IDs for the patterns as well as for Kyber.

**src/protocol/internal.h**: Added function declaration for creation of kyber based DHObject. Added cipher_len field to the definition of the DHState_s to be set for any KEM object to be implemented. Added functions for encapsulation and decapsulation in the DH objects. Added the EKEM and SKEM tokens.

**src/protocol/dhstate.c**: In function noise_dhstate_new_by_id added case for NOISE_DH_KYBER, where a new kyber based DHObject is created via a call to the pqnoise_kyber_new function declared in internal.h .

**/src/backend/ref/dh-kyber.c**: Added the file and all necessary functions for the kyber dh struct, this is where the pqnoise_kyber_new function mentioned earlier is implemented as well.

**src/protocol/handshakestate.c**: Added function for decapsulation as well as cases for the EKEM and SKEM tokens for the read and write functions.

**src/protocol/Makefile.am**: Added dh-kyber.c to the file under libnoiseprotocol_a_SOURCES.  

Added -loqs to the LDADD variable in the **Makefile.am** file in the following folders:  
										 	./tools/keytools  
											./tests/unit  
											./tests/vector  
											./tests/performance  
											./tests/vector-gen  
											./examples/echo/echo-client  
											./examples/echo/echo-server  
											./examples/echo/echo-keygen  
											
											
#### Adding a hybrid version combining regular and post quantum Noise

**src/protocol/patterns.c**: Added the hybrid patterns and added their translation for the ID lookup.

**src/protocol/names.c**: Added the new patterns to the ID mapping.

**include/noise/protocol/constants.h**: Added the IDs for the patterns.

**src/protocol/internal.h**: Added the EH, SH, EKEMH and SKEMH tokens for the hybrid versions, basically the same tokens that were used for the non-hybrid version but they use the content of the hybrid DH objects, maybe possible to use the EKEM and SKEM instead of adding H versions but it might be better to split them cleanly. Added attributes for static hybrid keys in the definition of the NoiseHandshakeState_s struct. Added the NOISE_PAT_FLAG_LOCAL_HYBRID_STATIC and NOISE_PAT_FLAG_REMOTE_HYBRID_STATIC flags that signify if these new static hybrid keys are required.

**include/noise/protocol/handshakestate.h**: Added declarations for the following functions: noise_handshakestate_get_local_hybrid_keypair_dh, noise_handshakestate_get_remote_hybrid_public_key_dh, noise_handshakestate_needs_local_hybrid_keypair, noise_handshakestate_has_local_hybrid_keypair, noise_handshakestate_needs_remote_hybrid_public_key, noise_handshakestate_has_remote_hybrid_public_key. These are all functions used to check whether hybrid keys/keypairs are needed as well as those that return you the dh object so you can set the relevant keys.

**src/protocol/handshakestate.c**: Added the implementation for the additional functions declared in the handshakestate.h file. Implemented the four new "h" cases in the noise_handshakestate_write and noise_handshakestate_read functions. Added cases to the noise_handshakestate_start function checking if the hybrid static keys are set if needed, added cases to the noise_handshakestate_free function that removes the new hybrid static keys when we are done and lastly added cases for the noise_handshakestate_new function that checks whether to create the hybrid static DH objects as well as set the sender/receiver role for them as well as a slight change to the check that decides whether the hybrid_id gets set or not.


## Building

The Noise-C implementation can be built using the same process as described in their their documentation: http://rweather.github.io/noise-c/index.html.
How to build the test files and how I used them is written in the commands.txt file in the Testing_Stuff folder.


