
build-secp256k1:
		cd c-secp256k1 && ./autogen.sh && ./configure --enable-experimental --enable-module-ecdh --enable-module-recovery && make -j$(cat /proc/cpuinfo | grep processor | wc -l)

install: build-secp256k1
		go install