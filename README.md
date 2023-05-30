# Vats
Master Thesis 2023


This thesis work aims to evaluate the practical application of threshold signature
schemes in vehicular settings, with a specific focus on strengthening the security and
redundancy of private keys used in mutual TLS (mTLS) in vehicle-to-everything,
V2X, communication. The proposed VATS (Vehicular Application of Threshold Sig-
nature) scheme introduces an innovative approach to secure key sharing among elec-
tronic control units (ECUs) within vehicles, significantly enhancing key management
security. Using a carefully designed secure secret sharing scheme, the VATS scheme
enables the reconstruction of the private key by using a predetermined threshold of
ECUs. This approach ensures that no single ECU possesses the complete private
key, mitigating the risks associated with key compromise or unauthorized access.
Instead, multiple ECUs collaboratively contribute their shares to reconstruct the
private key, thus establishing a higher level of security and resilience in vehicular
networks. To validate the effectiveness and practicality of the VATS scheme, exten-
sive evaluations and benchmarking have been performed. The performance of the
scheme, including execution time, resource utilization, and scalability, has been mea-
sured and analyzed. These evaluations provide valuable insights into the scheme’s
efficiency and its ability to handle various amounts of participants in the scheme.


Implementing a cryptographical sheme requires algebraic operations performed in a finite field. To accomplish this task, Ed25519-dalek was chosen. It is a fast and efficient Rust implementation of ed25519 key generation, signing, and verification. A proof-of-concept implementation of the project scheme is implemented in Rust using Risttreto over curve25519 as the group operations. Therefore, it makes significant use of the Ed25519-Dalek library. The Dalek Library is frequently used for cryptographic schemes and is used in implementations of FROST and ICE-FROST,-Ed25519-Daleks implementation of correctness, safety, and clarity as a priority and a secondary goal of performance, which makes it a very suitable library for a scheme like VATS. Since VATS implementation is created to be a secure signature scheme but also feasible and measured to be practical, it requires security and performance. 

To effectively handle asynchronicity in communications between network participants, Tokio was used. Tokio  is an asynchronous runtime for the Rust programming language that provides the functions necessary to write networking applications. It is flexible and able to target a wide range of systems, from large servers with dozens of cores to small embedded devices such as vehicle ECUs. Furthermore, Tokio helps to ensure that a functional network interface is present in the vehicle and adaptable to the internal network infrastructure of the vehicle.
At a high level, Tokio provides a few major components that make networking efficient and possible.

A multithreaded runtime to execute asynchronous code.
An asynchronous version of the standard library.
A large ecosystem of libraries.

Also, as part of the underlining network to test the implementation of VATS, Warp was used to enable communication between participants.Warp is a composable web server framework for creating a fast and reliable server and client communication. Warp is also adaptable to be used with TLS, where the user can provide locally stored keys and signatures. Since secure communication will be essential to the ECU's internal communication, Warp with TLS enabled helps ensure that such communication is safe against man-in-the-middle attacks. In addition, Warp can custom input certificates in its TLS communication, making it easy to provide it with a certificate authority made locally for testing and official certificate authorities used in real-world implementations.
