# secp256k1-go

This package provides bindings (using cgo) to the upstream [https://github.com/bitcoin-core/secp256k1](libsecp256k1) C library.  

It exposes numerous high level functions for dealing with secp256k1.

## Overview

There have been some slight changes to the API exposed by libsecp256k1. 
This section will document conventions adopted in the design. 

#### Always return error code from libsecp256k1
There are some functions which return more than one error code, indicating
the specific failure which occurred. With this in mind, the raw error
code is always returned as the first return value. 

To help provide some meaning to the error codes, the last parameter will
be used to return reasonable error messages.

#### Use write-by-reference where upstream uses it
In functions like EcPrivkeyTweakAdd, libsecp256k1 will take a pointer
to the private key, tweaking the value in place (overwriting the original value)

To avoid making copies of secrets in memory, we allow upstream to
overwrite the original values. If the to-be-written value is a new object,
it is returned as a return value.
  
## Installation

    git submodule update --init
    make install
    
    