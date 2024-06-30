# General
The changed versions of noise-c and EmbeddedDisco code that add the PQNoise handshakes. Also contains the PQNoise go code as it was used to test for compatibility between the c and go code.


## Prerequisites
All of this works fine on a laptop with ubuntu 22.04, no clue about any other platform.

Needs liboqs installed to run, since their implementation of kyber is used, specifically kyber512. The install instructions on their github work fine: https://github.com/open-quantum-safe/liboqs, however we need to make a shared library, so -DBUILD_SHARED_LIBS=ON is needed on the cmake -GNinja .. command, as written in their instructions.
Then do sudo ldconfig to update the ldconfig path. If it doesn't work then add a new .config file in /etc/ld.so.conf.d where you add the path to where the library was installed, followed by sudo ldconfig.

Any prerequities of the regular noise-c and embedded disco implementations of course still apply as well.


To run post quantum TLS timing tests (no tests yet, writing this down before I forget):

Needs openssl 3.x installed, a version that works should be pre-installed on any system with ubuntu 22.04, not sure for earlier versions. 
Need to install and activate oqsprovider, to do so simply follow the build and install instructions on their github https://github.com/open-quantum-safe/oqs-provider , it might be necessary do install the built library manually, so copying it to the correct folder so openssl can find it. Simply run a command like this: "openssl list -signature-algorithms -provider oqsprovider", which should list the available signature algorithms for the provider, if it can find it, if not then the error message should contain the exact folder where it expects the library to be, so you can simply copy the library there manually.
Lastly the provider can be permanently activated by following the instructions in their usage.md file. It is also necessary to set the KEM algorithms we want to use in the conf file as well, again instructions for this are in their usage.md file, in our case the algorithms that need to be activated are kyber512 and x25519_kyber512.




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


### Disco

**handshake_patterns.py**: Added the PQNoise handshakes to have the python program generate the token strings for the patterns correctly.  

**disco_asymmetric.h**: Added the generated token strings for the PQNoise patterns as well as a function, generate_pqKeyPair, to generate kyber keypairs. Added additional arguments for the disco_Initialize function, which are just the possible PQNoise keys you may have. Added keypair variables for the post quantum keys in the handshakestate struct.
	
**disco_asymmetric.c**: Added the token strings for the new PQNoise tokens, EKEM and SKEM. Changed the disco_Initialize and added the generate_pqKeyPair function as already explained for the .h file, the disco_initialize function also needed extra cases for when the pre-send symmetric keys were PQ keys. Added PQ key cases for the E and S token cases in the write and read functions, in those same functions I also added the cases for the SKEM and EKEM tokens.  

**Makefile**: Added commands nk_example and pq_example, which build an executable client and server file. This was just to test the regular nk handshake as well as the post quantum nk handshake on one pc. Also added the a command to make a libdisco.a static library, which makes it easier to run the full tests from the Testing_Stuff folder, simply run "make disco.a" to generate the static library file.


## Building

Both noise-c and embedded disco can be build in the same way as they would normally be, so their respective README.md files should have the correct instructions, though if you wish to run the tests you need to create a libdisco.a static library as mentioned above.  
How to build the test files and how I used them is written in the commands.txt file in the Testing_Stuff folder, maybe I should rename both of those at some point.  


