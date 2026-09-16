# Stateless Hash Digital Signature Algorithm (SLH-DSA, FIPS 205)

This repository implements [FIPS 205](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.205.pdf) in Go.

[![Build Status](https://github.com/trailofbits/go-slh-dsa/actions/workflows/ci.yml/badge.svg)](https://github.com/trailofbits/go-slh-dsa/actions/workflows/ci.yml)

## Installation

```terminal
go get https://github.com/trailofbits/go-slh-dsa
```

## Usage

```go
import (
	"crypto/rand"

	"github.com/trailofbits/go-slh-dsa/slh_dsa"
)

// First, specify the desired parameter set by name
parameterSet, err := slh_dsa.GetParamSet("SLH-DSA-SHA2-128f")
// Alternatively, `parameterSet := slh_dsa.SlhDsaSha2_128f()`

// To generate a key
sk, pk, err := slh_dsa.SLHKeygen(parameterSet)

// To save/load keys
sk_bytes := sk.Bytes()
pk_bytes := pk.Bytes()
loaded_sk, err := slh_dsa.LoadSecretKey(parameterSet, sk_bytes)
loaded_pk, err := slh_dsa.LoadPublicKey(parameterSet, pk_bytes)

// To sign a message. The library implements crypto.Signer
// Note: message should be a []byte
sig_bytes, err := sk.Sign(rand.Reader, message, nil)

// To verify a message
// First, deserialize the signature
sig, err := slh_dsa.LoadSignature(parameterSet, sig_bytes)
if pk.Verify(sig, message, []byte{}) {
	// ok
}

// Serialize the signature as bytes
sig_bytes = sig.Bytes()

// Deserialize bytes to a Signature object
loaded_sig, err := slh_dsa.LoadSignature(parameterSet, sig_bytes)
```

## Testing

This project includes fuzzing and mutation testing to ensure the quality and
robustness of the implementation.

### Fuzzing

To run the fuzz tests, use the following commands:

```terminal
go test -fuzz=FuzzSignAndVerify -fuzztime 60s ./slh_dsa
go test -fuzz=FuzzLoaders -fuzztime 60s ./slh_dsa
```

This will run the fuzz tests for 60 seconds.

### Mutation Testing

To run the mutation tests, you'll first need to install `go-gremlins`:

```terminal
go install github.com/go-gremlins/gremlins@latest
```

Then, run the following command:

```terminal
gremlins -v ./...
```
