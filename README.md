# General
The changed versions of noise-c and EmbeddedDisco code that add the PQNoise handshakes. Also contains the PQNoise go code as it was used to test for compatibility between the c and go code.


## Prerequisites
All of this works fine on a laptop with ubuntu 22.04, no clue about any other platform.

Needs liboqs installed to run, since their implementation of kyber is used, specifically kyber512. The install instructions on their github work fine: https://github.com/open-quantum-safe/liboqs, however we need to make a shared library, so -DBUILD_SHARED_LIBS=ON is needed on the cmake -GNinja .. command, as written in their instructions.

Then do sudo ldconfig to update the ldconfig path. If it doesn't work then add a new .config file in /etc/ld.so.conf.d where you add the path to where the library was installed, followed by sudo ldconfig.

Any prerequities of the regular noise-c and embedded disco implementations of course still apply as well.




## Changes that were made to the existing implementations


### Noise-c

patterns.c: Added the PQNoise patterns and added translation for ID lookup for the PQ patterns.  
names.c: Added the new patterns as well as an ID for Kyber(as a replacement for the DH algo to be used with the PQNoise patterns) to the ID mapping.  
constants.h: Added he IDs for the patterns as well as for Kyber. (Unsure if these work out of the gate)  
internal.h: Added function declaration for creation of kyber based DHObject. Also added pq_only field to the definition of the DHState_s to be set for the kyber object. (Currently not used for anything 
	however) Also added functions for encapsulation and decapsulation in the same object.  
dhstate.c: In function noise_dhstate_new_by_id added case for NOISE_DH_KYBER, where a new kyber based DHObject is created via a call to the pqnoise_kyber_new function declared in internal.h .  
dh-kyber.c: Added necessary functions and struct for kyber dh object.  
handshakestate.c: Added function for decapsulation as well as cases for the EKEM and SKEM tokens for the read and write functions.   

Added the dh-kyber.c file to the src/protocol/Makefile.am file under libnoiseprotocol_a_SOURCES.  
Added -loqs to the LDADD variable in the Makefile.am file in the following folders: 	./tools/keytools  
											./tests/unit  
											./tests/vector  
											./tests/performance  
											./tests/vector-gen  
											./examples/echo/echo-client  
											./examples/echo/echo-server  
											./examples/echo/echo-keygen  
											
											


### Disco

handshake_patterns.py: Added the PQNoise handshakes to have the python program generate the token strings for the patterns correctly.  
disco_asymmetric.h: Added the generated token strings for the PQNoise patterns as well as a function, generate_pqKeyPair, to generate kyber keypairs. Also added additional arguments for the 		
	disco_Initialize function, which are just the possible PQNoise keys you may have.  
disco_asymmetric.c: Added the token strings for the new PQNoise tokens, EKEM and SKEM. Changed the disco_Initialize and added the generate_pqKeyPair function as already explained for the .h file, the 
	disco_initialize function also needed extra cases for when the pre-send symmetric keys were PQ keys. Added PQ key cases for the E and S token cases in the write and read functions, in those same
	functions I also added the cases for the SKEM and EKEM tokens.  
Makefile: Added commands nk_example and pq_example, which build an executable client and server file which was just to test the regular nk handshake as well as the post quantum nk handshake on one pc.  


## Building

Both noise-c and embedded disco can be build in the same way as they would normally be, so their respective README.md files should have the correct instructions.  
How to build the test files and how I used them is written in the commands.txt file in the Testing_Stuff folder, maybe I should rename both of those at some point.  


