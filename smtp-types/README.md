# Misuse-resistant SMTP Types

This library provides types, i.e., `struct`s and `enum`s, to support [SMTP] implementations.

## Features

* Rust's type system is used to enforce correctness and make the library misuse-resistant. 
It must not be possible to construct a type that violates the SMTP specification.

# License

This crate is dual-licensed under Apache 2.0 and MIT terms.

[SMTP]: https://www.rfc-editor.org/rfc/rfc5321
