#lang scribble/manual

@require[(for-label racket racl)
         scribble/racket]

@title{Racl, Racking bindings for NaCl.}
@(author "Tony Garnock-Jones")
@defmodule[racl]

A set of Racket bindings for cryptographic library @hyperlink["http://nacl.cr.yp.to"]{NaCl}.



@section{Miscellaneous}


@defstruct*[(exn:fail:contract:racl exn:fail:contract) () #:transparent]{
  Raised when invalid byte strings are passed to any of the functions
  in @racketmodname[racl], or when a cryptographic primitive fails.
}

@defproc[(random-bytes [count exact-nonnegative-integer?])
         exact-nonnegative-integer?]{
  Returns a new mutable byte string containing @racket[count] randomly generated
  bytes. Uses the Unix device file @code{/dev/urandom} for number generation.
}

@defproc[(crypto-hash-bytes [bs bytes?]) bytes?]{
  Returns a byte string hash of @racket[bs], using SHA-512 as the hash function.
}




@section{Public-key cryptography}


@subsection{Boxes}
@defstruct*[crypto-box-keypair ([pk bytes?] [sk bytes?]) #:prefab]{
  Represents a keypair for use in the @code{crypto-box-} functions.

  The @racket[pk] field contains a public key, and the @racket[sk] field contains the
  corresponding private key.
}
@defproc[(make-crypto-box-keypair) crypto-box-keypair?]{
  Returns a new randomly generated keypair for use in the @code{crypto-box-} functions.
}
@defproc[(crypto-box-random-nonce) bytes?]{
  Returns a new randomly generated nonce for use in the @code{crypto-box-} functions.
}

@defproc[(crypto-box [msg bytes?] [nonce bytes?] [pk bytes?] [sk bytes?]) bytes?]{
  Encrypts and authenticates message @racket[msg] using the sender's secret key @racket[sk],
  the receiver's public key @racket[pk], and a nonce @racket[nonce]. Returns the ciphertext as a
  new byte string.
}
@defproc[(crypto-box-open [ciphertext bytes?] [nonce bytes?] [pk bytes?] [sk bytes?]) bytes?]{
  Verifies and decrypts @racket[ciphertext] using the receiver's secret key @racket[sk],
  the sender's public key @racket[pk], and a nonce @racket[nonce]. Returns the plaintext as a
  new byte string.

  Raises @racket[exn:fail:contract:racl] if ciphertext fails verification.
}

@defproc[(crypto-box-state? [v any/c]) boolean?]
@defproc[(crypto-box-precompute [pk bytes?] [sk bytes?]) crypto-box-state?]
@deftogether[
  (@defproc[(crypto-box* [msg bytes?] [nonce bytes?] [state crypto-box-state?]) bytes?]
   @defproc[(crypto-box-open* [ciphertext bytes?] [nonce bytes?] [state crypto-box-state?]) bytes?])]{
  Like @racket[crypto-box] and @racket[crypto-box-open], but takes a precomputed state instead of
  public and secret keys.
}


@subsection{Signatures}
@defstruct*[crypto-sign-keypair ([pk bytes?] [sk bytes?]) #:prefab]{
  Represents a keypair for use in the @code{crypto-sign-} functions.

  The @racket[pk] field contains a public key, and the @racket[sk] field contains the
  corresponding private key.
}

@defproc[(make-crypto-sign-keypair) crypto-sign-keypair?]{
  Returns a new randomly generated keypair for use in the @racket[crypto-sign] and
  @racket[crypto-sign-open] functions.
}
@defproc[(crypto-sign [msg bytes?] [sk bytes?]) bytes?]{
  Signs the message @racket[msg] using the signer's secret key @racket[sk]. Returns
  the signed message as a new byte string.
}
@defproc[(crypto-sign-open [smsg bytes?] [pk bytes?]) bytes?]{
  Verifies the signed message @racket[smsg] using the signer's public key @racket[pk]. Returns
  the original message as a new byte string.

  Raises @racket[exn:fail:contract:racl] if signature fails verification.
}




@section{Secret-key cryptography}


@subsection{Authenticated symmetric-key encryption}
@defproc[(crypto-secretbox-random-nonce) bytes?]{
  Returns a randomly generate nonce for use in the @racket[crypto-secretbox] and
  @racket[crypto-secretbox-open] functions.
}
@defproc[(crypto-secretbox [msg bytes?] [nonce bytes?] [key bytes?]) bytes?]{
  Encrypts and authenticates the message @racket[msg] using a secret key @racket[key] and
  a nonce @racket[nonce]. Returns the ciphertext as a new byte string.

  Raises @racket[exn:fail:contract:racl] if @racket[key] is not exactly @racket[32] bytes.
}
@defproc[(crypto-secretbox-open [ciphertext bytes?] [nonce bytes?] [key bytes?]) bytes?]{
  Verifies and decrypts the @racket[ciphertext] using a secret key @racket[key] and
  a nonce @racket[nonce]. Returns the plaintext as a new byte string.

  Raises @racket[exn:fail:contract:racl] if @racket[key] is not exactly @racket[32] bytes.
}


@subsection{Symmetric-key encryption}
@defproc[(crypto-stream-random-nonce) bytes?]{
  Returns a randomly generate nonce for use in the @code{crypto-stream-} functions.
}
@defproc[(crypto-stream [count exact-nonnegative-integer?] [nonce bytes?] [key bytes?]) bytes?]{
  Returns a byte string of length @racket[count] as a function of a secret key @racket[key] and
  a nonce @racket[nonce].

  Raises @racket[exn:fail:contract:racl] if @racket[key] is not exactly @racket[32] bytes.
}
@defproc[(crypto-stream! [out (and/c bytes? (not/c immutable?))] [nonce bytes?] [key bytes?]) bytes?]{
  Fills the contents @racket[out] with a function of a secret key @racket[key] and a nonce
  @racket[nonce]. Returns @racket[out].

  Raises @racket[exn:fail:contract:racl] if @racket[key] is not exactly @racket[32] bytes.
}
@defproc[(crypto-stream-xor [msg bytes?] [nonce bytes?] [key bytes?]) bytes?]{
  Encrypts message @racket[msg] using a secret key @racket[key] and a nonce @racket[nonce]. Returns
  the encrypted ciphertext as a new byte string. @racket[crypto-stream-xor] can be used to decrypt
  a ciphertext if applied with the same nonce and secret key.

  Raises @racket[exn:fail:contract:racl] if @racket[key] is not exactly @racket[32] bytes.
}
@defproc[(crypto-stream-xor! [out (and/c bytes? (not/c immutable?))] [msg bytes?] [nonce bytes?] [key bytes?]) bytes?]{
  Encrypts message @racket[msg] using a secret key @racket[key] and a nonce @racket[nonce]. Fills mutable
  byte string @racket[out]. Fills @racket[out] with the encrypted ciphertext. Returns @racket[out].
  @racket[crypto-stream-xor] can be used to decrypt a ciphertext if applied with the same nonce and secret key.

  Raises @racket[exn:fail:contract:racl] if @racket[key] is not exactly @racket[32] bytes, or if @racket[out]
  and @racket[msg] are not the same length.
}


@subsection{Authentication}
@defproc[(crypto-auth [msg bytes?] [key bytes?]) bytes?]{
  Authenticates a message @racket[msg] using a secret key @racket[k]. Returns an authenticator
  as a new byte string.

  Raises @racket[exn:fail:contract:racl] if @racket[key] is not exactly @racket[32] bytes.
}
@defproc[(crypto-auth-verify [authenticator bytes?] [msg bytes?] [key bytes?]) boolean?]{
  Returns @racket[#t] if @racket[authenticator] is a correct authenticator of message @racket[msg]
  under the secret key @racket[key], returns @racket[#f] otherwise.

  Raises @racket[exn:fail:contract:racl] if @racket[key] is not exactly @racket[32] bytes.
}


@subsection{One-time authentication}
@defproc[(crypto-onetimeauth [msg bytes?] [key bytes?]) bytes?]{
  Authenticates a message @racket[msg] using a secret key @racket[k]. Returns an authenticator
  as a new byte string.

  Raises @racket[exn:fail:contract:racl] if @racket[key] is not exactly @racket[32] bytes.
}
@defproc[(crypto-onetimeauth-verify [authenticator bytes?] [msg bytes?] [key bytes?]) boolean?]{
  Returns @racket[#t] if @racket[authenticator] is a correct authenticator of message @racket[msg]
  under the secret key @racket[key], returns @racket[#f] otherwise.

  Raises @racket[exn:fail:contract:racl] if @racket[key] is not exactly @racket[32] bytes.
}




@section{Key derivation}


@defproc[(bytes->crypto-sign-keypair [bs bytes?]) crypto-sign-keypair?]{
  Hashes the byte string @racket[bs], using the hash as the seed to generate a
  new keypair. Returns a @racket[crypto-sign-keypair] for use in the @racket[crypto-sign]
  and @racket[crypto-sign-open] functions.
}
@defproc[(seed->crypto-sign-keypair [seed bytes?]) crypto-sign-keypair?]{
  Generates a keypair from the given seed. Returns a @racket[crypto-sign-keypair] for use
  in the @racket[crypto-sign] and @racket[crypto-sign-open] functions.

  Raises @racket[exn:fail:contract:racl] if @racket[seed] is not exactly @racket[32] bytes.
}
@defproc[(bytes->crypto-box-keypair [bs bytes?]) crypto-box-keypair?]{
  Hashes the byte string @racket[bs], using the hash as the seed to generate a
  new keypair. Returns a @racket[crypto-box-keypair] for use in the @code{crypto-box-}
  functions.
}
@defproc[(crypto-box-sk->pk [sk bytes?]) bytes?]{
  Computes the corresponding public key for the secret key @racket[sk]. Returns the public
  key as a byte string for use in the @code{crypto-box-} functions.
}
