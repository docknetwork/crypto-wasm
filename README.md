# crypto-wasm

This repository is a WASM wrapper over [Dock's Rust crypto library](https://github.com/docknetwork/crypto) and is home to 
- BBS+, a performant multi-message digital signature algorithm implementation which supports
deriving zero knowledge proofs that enable selective disclosure from the originally signed message set.
- bilinear map, positive and universal accumulators supporting single and batch updates to the accumulator and witness
- composite proof system that lets you combine BBS+ signatures, accumulators and Schnorr protocols

This project started as fork of [@mattrglobal/bbs-signatures](https://github.com/mattrglobal/bbs-signatures) but now only borrows the 
WASM setup; the API is quite different.

This repo contains a thin wrapper over the Rust code and exposes free floating JS functions. For a Typescript wrapper with better 
abstractions, check [this](https://github.com/docknetwork/crypto-wasm-ts). 

## Overview
Following is a conceptual explanation of the primitives. For the API, check the [tests](./tests/js).  

### BBS+ Signatures
BBS+ signature allow for signing an ordered list of messages, producing a signature of constant size independent of the number 
of messages. The signer needs to have a public-private keypair and signature parameters which are public values whose size 
depends on the number of messages being signed. A verifier who needs to verify the signature needs to know the 
signature parameters used to sign the messages and the public key of the signer.  
BBS+ signature also allow a user to request a blind signature from a signer where the signer does not know 1 or more messages 
from the list. The user can then unblind the blind signature to get a regular signature which can be verified by a verifier in 
the usual way. Such blind signatures can be used to hide a user specific secret like a private key or some unique identifier 
as a message in the message list and the signer does not become aware of the hidden message.     
With a BBS signature, a user in possession of the signature and messages and create a [zero-knowledge proof of knowledge](https://en.wikipedia.org/wiki/Proof_of_knowledge) 
of the signature and the corresponding signed messages such that he can prove to a verifier that he knows a signature and the 
messages and optionally reveal one or more of the messages.  
A typical use of BBS+ signatures looks like:
  - Signature parameters of the required size are assumed to exist and published at a public location. The signer can create 
    his own or reuse parameters created by another party.
  - Signer public-private keypair and publishes the public key. The keypair can be reused for signing other messages as well. 
  - User requests a signature from the signer.
  - Signer signs the message list using the signature parameters and his private key.
  - User verifies the signature on the  message list using the signature parameters and signer's public key
  - User creates a proof of knowledge of the signature and message list and optionally reveals 1 or more messages to the verifier.
  - The verifier uses the signature parameters and signer's public key to verify this proof. If successful, the verifier is 
    convinced that the user does have a signature from the signer and any messages revealed were part of the message list 
    signed by the signer.

### Accumulator
An accumulator is a "set like" data-structure in which elements can be added or removed but the size of the accumulator remains 
constant. But an accumulator cannot be directly checked for presence of an element, an element needs to have accompanying data called 
the witness (its the manager's signature on the element), the element and the witness and these together can be used to check the presence 
or absence of the element. An accumulator can be considered similar to the root of the merkle tree where the inclusion proof is the witness 
of the element (non-membership proofs aren't possible with simple merkle trees). As with merkle trees, as elements are added or 
removed from the accumulator, the witness (inclusion proof) needs to be updated for the current accumulated value (root).  
2 kinds of accumulators are provided, **positive** and **universal**. Positive support only membership witnesses while universal support both 
membership and non-membership witnesses. Creating non-membership witnesses is expensive however and the cost depends on the 
number of members present in the accumulator. Both accumulators are owned by an accumulator manager who has the private key to the accumulator 
and only the owner can add or remove elements or create witnesses using the accumulator.    
Accumulator allows proving membership of the member (or non-member) and the corresponding witness in zero knowledge meaning 
a user in possession of an accumulator member (or non-member) and the witness can convince a verifier that he knows of an 
element present (or absent) in the accumulator without revealing the element or the witness. Note, the like merkle trees, 
witnesses (inclusion proof) are tied to the accumulated value (root) and need to be updated as accumulator changes.  
Witnesses can be updated either by the accumulator manager using his private key or the manager can publish witness update 
information and the updates (additions and removals) and users can update their witnesses. 
A typical use of accumulator looks like:
  - Accumulator parameters are assumed to exist and published at a public location. The manager can create his own params or 
    reuse existing ones.
  - Accumulator manager creates a keypair and publishes the public key.
  - Accumulator manager initializes the accumulator and publishes the accumulator.
  - User requests an element to be added to the accumulator and the membership witness from the manager. The user could have 
    also requested a non-membership witness for an absent element.
  - Signer checks whether requested element is not already present (in his database) and adds the element to the 
    accumulator if not already present. He publishes the new accumulator and creates a (non)membership witness and sends to the user.
  - User verifies the (non)membership using the element, the witness, the new accumulated value and the accumulator params and signer's public key.
  - To prove knowledge of (non)membership in zero knowledge, user and verifier agree on a proving key. Anyone can generate this. 
  - User can create a proof of knowledge of the element and the witness corresponding to the accumulator.
  - Verifier can verify above proof using the current accumulator, the parameters and signer's public key and is convinced 
    that the user knows of an element and its witness and the (non)-membership.

### Verifiable encryption
Allow a verifier to check that the plaintext satisfies some properties, and it correctly encrypted for a specified public key without 
learning the plaintext itself. This is implemented using a protocol called [SAVER](https://eprint.iacr.org/2019/1270).  

### Bound check
Allow a verifier to check that some message satisfies given bounds `min` and `max`, i.e. `min <= message <= max` without 
learning the message itself. This is implemented using a protocol called LegoGroth16, a protocol described in the SNARK framework [Legosnark](https://eprint.iacr.org/2019/142)

### Composite proofs
The above primitives can be combined using the composite proof system. An example is (in zero knowledge) proving knowledge of 2 
different signatures and the message lists. Another example is proving knowledge of the signature and messages and certain message's presence (absence) 
in an accumulator. Or the knowledge of 5 signatures and proving certain message is the same in the 5 message lists. 

### DKG from FROST

### Threshold BBS+ and BBS

## Getting started

To use this package within your project simply run

```
npm install @docknetwork/crypto-wasm
```

Or with [Yarn](https://yarnpkg.com/)

```
yarn add @docknetwork/crypto-wasm
```

See the [sample](./sample) directory for a runnable demo's.

The following is a short sample on how to use the API

## Element Size

Within a digital signature there are several elements for which it is useful to know the size, the following table
outlines the general equation for calculating element sizes in relation to BBS+ signatures as it is dependent on the
pairing friendly curve used.

| Element     | Size Equation                        |
| ----------- | ------------------------------------ |
| Private Key | F                                    |
| Public Key  | G2                                   |
| Signature   | G1 + 2\*F                            |
| Proof       | 5*G1 + (4 + no_of_hidden_messages)*F |

- `F` A field element
- `G1` A point in the field of G1
- `G2` A point in the field of G2
- `no_of_hidden_messages` The number of the hidden messages

This library includes specific support for BLS12-381 keys with BBS+ signatures and hence gives rise to the following
concrete sizes

| Element     | Size with BLS12-381                     |
| ----------- | --------------------------------------- |
| Private Key | 32 Bytes                                |
| Public Key  | 96 Bytes                                |
| Signature   | 112 Bytes                               |
| Proof       | 368 + (no_of_hidden_messages)\*32 Bytes |

## Getting started as a contributor

The following describes how to get started as a contributor to this project

### Prerequisites

The following is a list of dependencies you must install to build and contribute to this project

- [Yarn](https://yarnpkg.com/) - make sure you're not using the legacy version.
- [Rust](https://www.rust-lang.org/)

For more details see our [contribution guidelines](./docs/CONTRIBUTING.md)

#### Install

To install the package dependencies run:

```
yarn install --frozen-lockfile
```

#### Build

To build the project for debug, run:

```
yarn build
```

To build the project for release, run:

```
yarn build:release
```

To build the project for profiling (slower to build, faster to run), run:

```
yarn build:profiling
```

#### Test

To run the all test in the project run:

```
yarn test
```

To run just the tests for a node environment using the wasm module run:

```
yarn test:wasm
```

Before running the JS tests, build the project with `yarn build`.

To run just the tests for a browser environment run:

```
yarn test:browser
```

Above runs the Rust tests [here](./tests/). To run specific modules, use following wasm-pack command and pass the test module 
name. Eg. for running accumulator tests, run:

```
wasm-pack test --headless --chrome -- --test accumulator
```

For BBS+, run:
```
wasm-pack test --headless --chrome -- --test bbs_plus
```

For accumulator, run:
```
wasm-pack test --headless --chrome -- --test accumulator
```

Some tests take long (few minutes) to run and to prevent timeout of such tests, set env variable `WASM_BINDGEN_TEST_TIMEOUT` 
to the number of seconds for the timeout. eg. the following sets the timeout to 360 seconds, i.e. 6 minutes

```
WASM_BINDGEN_TEST_TIMEOUT=360 wasm-pack test --headless --chrome
```

It's better to run tests in release mode since debug mode takes a long time. Increasing the timeout helps as well as shown below.

```
WASM_BINDGEN_TEST_TIMEOUT=360 wasm-pack test --release --headless --chrome
```

#### Benchmark

To benchmark the implementation locally in a node environment using the wasm module run:

```
yarn benchmark:wasm
```

## Usage

Since loading WASM is an async process, before any function can be used `initializeWasm` should be called and resolved which 
loads WASM.

Example of using BBS+ signature

```js
import {
  bbsPlusGenerateSignatureParamsG1, bbsPlusGeneratePublicKeyG2, bbsPlusGenerateSigningKey, bbsPlusSignG1, bbsPlusVerifyG1, 
  bbsPlusInitializeProofOfKnowledgeOfSignature, bbsPlusGenProofOfKnowledgeOfSignature, bbsPlusVerifyProofOfKnowledgeOfSignature, 
  bbsPlusChallengeContributionFromProtocol, bbsPlusChallengeContributionFromProof, generateChallengeFromBytes, 
  initializeWasm
} from "../../../lib";

const stringToBytes = (str: string) => Uint8Array.from(Buffer.from(str, "utf-8"));

const main = async () => {
    // Load the WASM module
    await initializeWasm();

    // Generate some random messages
    const messages = [
        Uint8Array.from(Buffer.from("message1", "utf8")),
        Uint8Array.from(Buffer.from("message2", "utf8")),
        Uint8Array.from(Buffer.from("message3", "utf8")),
    ];

  const label = stringToBytes("test-params");
  const messageCount = messages.length;

  // Generate params deterministically using a label
  const sigParams = bbsPlusGenerateSignatureParamsG1(messageCount, label);
  console.log('params is', sigParams);

  // Generate a new key pair
  const sk = bbsPlusGenerateSigningKey();
  const pk = bbsPlusGeneratePublicKeyG2(sk, sigParams);
  console.log("Key pair generated");
  console.log(
    `Public key base64 = ${Buffer.from(pk).toString("base64")}`
  );

  console.log("Signing a message set of " + messages);

  // Create the signature
  const signature = bbsPlusSignG1(messages, sk, sigParams, true);
  console.log(
    `Output signature base64 = ${Buffer.from(signature).toString("base64")}`
  );

  // Verify the signature
  const isVerified = bbsPlusVerifyG1(messages, signature, pk, sigParams, true);
  const isVerifiedString = JSON.stringify(isVerified);
  console.log(`Signature verified ? ${isVerifiedString}`);

  // Derive a proof from the signature revealing the first message
  const revealed = new Set<number>();
  revealed.add(0);
  const revealedMsgs = new Map();
  revealedMsgs.set(0, messages[0]);
  
  const protocol = bbsPlusInitializeProofOfKnowledgeOfSignature(
      signature,
      sigParams,
      messages,
    new Map(),
      revealed,
      true
  );

  const challengeProver = generateChallengeFromBytes(bbsPlusChallengeContributionFromProtocol(protocol, revealedMsgs, sigParams, true));
  const proof = bbsPlusGenProofOfKnowledgeOfSignature(protocol, challengeProver);

  console.log(`Output proof base64 = ${Buffer.from(proof).toString("base64")}`);

  // Verify the created proof
  const challengeVerifier = generateChallengeFromBytes(bbsPlusChallengeContributionFromProof(proof, revealedMsgs, sigParams, true));
  const isProofVerified = bbsPlusVerifyProofOfKnowledgeOfSignature(
    proof,
      revealedMsgs,
    challengeVerifier,
    pk,
    sigParams,
    true,
  );
  const isProofVerifiedString = JSON.stringify(isProofVerified);
  console.log(`Proof verified ? ${isProofVerifiedString}`);
};

main();

```

See the [tests](./tests/js) for more thorough examples.


## Dependencies

This library uses the creates defined in [Dock's crypto library](https://github.com/docknetwork/crypto) which is then 
wrapped and exposed in javascript/typescript using [Web Assembly](https://webassembly.org/).

## Security Policy

Please see our [security policy](./SECURITY.md) for additional details about responsible disclosure of security related issues.

## Relevant References

For those interested in more details, you might find the following resources helpful

- [BLS12-381 For The Rest Of Us](https://hackmd.io/@benjaminion/bls12-381)
- [Pairing-based cryptography](https://en.wikipedia.org/wiki/Pairing-based_cryptography)
- [Exploring Elliptic Curve Pairings](https://vitalik.ca/general/2017/01/14/exploring_ecp.html)
- [Anonymous Attestation Using the Strong Diffie Hellman Assumption Revisited](https://www.researchgate.net/publication/306347781_Anonymous_Attestation_Using_the_Strong_Diffie_Hellman_Assumption_Revisited)
- [Pairing Friendly Curves](https://tools.ietf.org/html/draft-irtf-cfrg-pairing-friendly-curves-01)
- BBS+ signature defined in [Anonymous Attestation Using the Strong Diffie Hellman Assumption Revisited](https://eprint.iacr.org/2016/663)
- Dynamic accumulator defined in [Dynamic Universal Accumulator with Batch Update over Bilinear Groups](https://eprint.iacr.org/2020/777)
- Verifiable encryption using [SAVER](https://eprint.iacr.org/2019/1270)
- LegoGroth16, described in the appending H.5 of the [Legosnark paper](https://eprint.iacr.org/2019/142)

To build, use
```
BUILD_MODE=DEBUG ./scripts/build-package.sh 
```

or

```
BUILD_MODE=RELEASE ./scripts/build-package.sh 
```

or

```
BUILD_MODE=PROFILING ./scripts/build-package.sh 
```

To run jest tests, build with target nodejs as `wasm-pack build --out-dir lib --target nodejs` 
