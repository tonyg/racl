#lang scribble/manual

@require[(for-label racket racl)
         scribble/racket]

@title{Racl, Racking bindings for NaCl.}
@(author "Tony Garnock-Jones")
@defmodule[racl]

A set of Racket bindings for @hyperlink["http://nacl.cr.yp.to"]{NaCl}, a cryptographic library.


@section{Pseudorandom Number Generation}
@defproc[(random-bytes [count exact-nonnegative-integer?])
         exact-nonnegative-integer?]


@section{Hashing}
@defproc[(crypto-hash-bytes [bs bytes?]) bytes?]


@section{Boxing}
@defproc[(crypto-box-state? [v any/c]) boolean?]
@;@defstruct*[crypto-box-keypair ([pk bytes?] [sk bytes?]) #:prefab]

@defproc[(crypto-box-random-nonce) bytes?]
@defproc[(crypto-box [msg bytes?] [nonce bytes?] [pk bytes?] [sk bytes?]) bytes?]
@defproc[(crypto-box-open [ciphertext bytes?] [nonce bytes?] [pk bytes?] [sk bytes?]) bytes?]

@defproc[(crypto-box-precompute [pk bytes?] [sk bytes?]) crypto-box-state?]
@defproc[(crypto-box* [msg bytes?] [nonce bytes?] [state crypto-box-state?]) bytes?]
@defproc[(crypto-box-open* [ciphertext bytes?] [nonce bytes?] [state crypto-box-state?]) bytes?]


@section{Signing}
@defproc[(crypto-sign-keypair? [v any/c]) boolean?]
@defproc[(crypto-sign-keypair-pk [keypair crypto-sign-keypair?]) bytes?]
@defproc[(crypto-sign-keypair-sk [keypair crypto-sign-keypair?]) bytes?]
@defproc[(make-crypto-sign-keypair) crypto-sign-keypair?]
@defproc[(crypto-sign [msg bytes?] [sk bytes?]) bytes?]
@defproc[(crypto-sign-open [signed-msg bytes?] [pk bytes?]) bytes?]


@section{Authenticated Symmetric-Key Encryption}
@defproc[(crypto-secretbox-random-nonce) bytes?]
@defproc[(crypto-secretbox [msg bytes?] [nonce bytes?] [key bytes?]) bytes?]
@defproc[(crypto-secretbox-open [ciphertext bytes?] [nonce bytes?] [key bytes?]) bytes?]


@section{Symmetric-Key Encryption}
@defproc[(crypto-stream-random-nonce) bytes?]
@defproc[(crypto-stream [count exact-nonnegative-integer?] [nonce bytes?] [key bytes?]) bytes?]
@defproc[(crypto-stream! [out (and/c bytes? (not/c immutable?))] [nonce bytes?] [key bytes?]) bytes?]
@defproc[(crypto-stream-xor [msg bytes?] [nonce bytes?] [key bytes?]) bytes?]
@defproc[(crypto-stream-xor! [out (and/c bytes? (not/c immutable?))] [msg bytes?] [nonce bytes?] [key bytes?]) bytes?]


@section{Authentication}
@defproc[(crypto-auth [msg bytes?] [key bytes?]) bytes?]
@defproc[(crypto-auth-veriify [authenticator bytes?] [msg bytes?] [key bytes?]) boolean?]


@section{One-Time Authentication}
@defproc[(crypto-onetimeauth [msg bytes?] [key bytes?]) bytes?]
@defproc[(crypto-onetimeauth-verify [authenticator bytes?] [msg bytes?] [key bytes?]) boolean?]


@section{Key Derivation}
@defproc[(bytes->crypto-sign-keypair [bs bytes?]) crypto-sign-keypair?]
@defproc[(seed->crypto-sign-keypair [seed bytes?]) crypto-sign-keypair?]
@;@defproc[(bytes->crypto-box-keypair [bs bytes?]) crypto-box-keypair?]
@defproc[(crypto-box-sk->pk [sk bytes?]) bytes?]
