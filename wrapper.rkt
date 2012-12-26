#lang racket/base
;; Wrapper for the Networking and Cryptography Library, NaCL.

(require racket/include)
(require ffi/unsafe)
(require "ffi-lib.rkt")

(provide random-bytes

	 (struct-out crypto-box-keypair)
	 make-crypto-box-keypair
	 crypto-box-random-nonce
	 crypto-box
	 crypto-box-open

	 (struct-out crypto-box-state)
	 crypto-box-precompute
	 crypto-box*
	 crypto-box-open*

	 crypto-hash-bytes

	 crypto-stream-random-nonce
	 crypto-stream!
	 crypto-stream
	 crypto-stream-xor!
	 crypto-stream-xor

	 crypto-onetimeauth
	 crypto-onetimeauth-verify

	 crypto-auth
	 crypto-auth-verify

	 crypto-secretbox-random-nonce
	 crypto-secretbox
	 crypto-secretbox-open

	 (struct-out crypto-sign-keypair)
	 make-crypto-sign-keypair
	 crypto-sign
	 crypto-sign-open)

(struct crypto-box-keypair (pk sk) #:prefab)
(struct crypto-box-state (k)) ;; not even transparent

(struct crypto-sign-keypair (pk sk) #:prefab)

;;---------------------------------------------------------------------------
;; Random bytes

(define-nacl randombytes (_fun _bytes _uint64 -> _void))
(define (random-bytes count)
  (define bs (make-bytes count))
  (randombytes bs (bytes-length bs))
  bs)

;;---------------------------------------------------------------------------
;; Boxing

(define-nacl crypto_box_curve25519xsalsa20poly1305
  (_fun _bytes _bytes _uint64 _bytes _bytes _bytes -> _int))
(define-nacl crypto_box_curve25519xsalsa20poly1305_afternm
  (_fun _bytes _bytes _uint64 _bytes _bytes -> _int))
(define-nacl crypto_box_curve25519xsalsa20poly1305_beforenm
  (_fun _bytes _bytes _bytes -> _int))
(define-nacl crypto_box_curve25519xsalsa20poly1305_keypair
  (_fun _bytes _bytes -> _int))
(define-nacl crypto_box_curve25519xsalsa20poly1305_open
  (_fun _bytes _bytes _uint64 _bytes _bytes _bytes -> _int))
(define-nacl crypto_box_curve25519xsalsa20poly1305_open_afternm
  (_fun _bytes _bytes _uint64 _bytes _bytes -> _int))

(define (make-crypto-box-keypair)
  (define pk (make-bytes crypto_box_PUBLICKEYBYTES))
  (define sk (make-bytes crypto_box_SECRETKEYBYTES))
  (check-result (crypto_box_keypair pk sk))
  (crypto-box-keypair pk sk))

(define (crypto-box-random-nonce)
  (random-bytes crypto_box_NONCEBYTES))

(define (crypto-box msg nonce pk sk)
  (define m (zero-pad-left msg crypto_box_ZEROBYTES))
  (define c (make-zero-bytes (bytes-length m)))
  (check-nonce 'crypto-box nonce crypto_box_NONCEBYTES)
  (check-length 'crypto-box "pk" pk crypto_box_PUBLICKEYBYTES)
  (check-length 'crypto-box "sk" sk crypto_box_PUBLICKEYBYTES)
  (check-result (crypto_box c m (bytes-length m) nonce pk sk))
  (subbytes c crypto_box_BOXZEROBYTES))

(define (crypto-box-open ciphertext nonce pk sk)
  (define c (zero-pad-left ciphertext crypto_box_BOXZEROBYTES))
  (define m (make-zero-bytes (bytes-length c)))
  (check-nonce 'crypto-box-open nonce crypto_box_NONCEBYTES)
  (check-length 'crypto-box-open "pk" pk crypto_box_PUBLICKEYBYTES)
  (check-length 'crypto-box-open "sk" sk crypto_box_PUBLICKEYBYTES)
  (check-result (crypto_box_open m c (bytes-length c) nonce pk sk))
  (subbytes m crypto_box_ZEROBYTES))

(define (crypto-box-precompute pk sk)
  (define k (make-zero-bytes crypto_box_BEFORENMBYTES))
  (check-length 'crypto-box-precompute "pk" pk crypto_box_PUBLICKEYBYTES)
  (check-length 'crypto-box-precompute "sk" sk crypto_box_PUBLICKEYBYTES)
  (check-result (crypto_box_beforenm k pk sk))
  (crypto-box-state k))

(define (crypto-box* msg nonce state)
  (define m (zero-pad-left msg crypto_box_ZEROBYTES))
  (define c (make-zero-bytes (bytes-length m)))
  (check-nonce 'crypto-box* nonce crypto_box_NONCEBYTES)
  (check-result (crypto_box_afternm c m (bytes-length m) nonce (crypto-box-state-k state)))
  (subbytes c crypto_box_BOXZEROBYTES))

(define (crypto-box-open* ciphertext nonce state)
  (define c (zero-pad-left ciphertext crypto_box_BOXZEROBYTES))
  (define m (make-zero-bytes (bytes-length c)))
  (check-nonce 'crypto-box-open* nonce crypto_box_NONCEBYTES)
  (check-result (crypto_box_open_afternm m c (bytes-length c) nonce (crypto-box-state-k state)))
  (subbytes m crypto_box_ZEROBYTES))

;;---------------------------------------------------------------------------
;; Hashing

(define-nacl crypto_hash_sha512
  (_fun _bytes _bytes _uint64 -> _int))

(define (crypto-hash-bytes bs)
  (define out (make-zero-bytes crypto_hash_BYTES))
  (check-result (crypto_hash out bs (bytes-length bs)))
  out)

;;---------------------------------------------------------------------------
;; Symmetric-key encryption

(define-nacl crypto_stream_xsalsa20
  (_fun _bytes _uint64 _bytes _bytes -> _int))
(define-nacl crypto_stream_xsalsa20_xor
  (_fun _bytes _bytes _uint64 _bytes _bytes -> _int))

(define (crypto-stream-random-nonce)
  (random-bytes crypto_stream_NONCEBYTES))

(define (crypto-stream! out nonce key)
  (check-nonce 'crypto-stream! nonce crypto_stream_NONCEBYTES)
  (check-length 'crypto-stream! "key" key crypto_stream_KEYBYTES)
  (check-result (crypto_stream out (bytes-length out) nonce key))
  out)

(define (crypto-stream clen nonce key)
  (define out (make-bytes clen))
  (crypto-stream! out nonce key))

(define (crypto-stream-xor* out msg nonce key)
  ;; Check that (bytes-length out) == (bytes-length msg) must be done by caller
  (check-nonce 'crypto-stream-xor* nonce crypto_stream_NONCEBYTES)
  (check-length 'crypto-stream-xor* "key" key crypto_stream_KEYBYTES)
  (check-result (crypto_stream_xor out msg (bytes-length msg) nonce key))
  out)

(define (crypto-stream-xor! out msg nonce key)
  (check-length 'crypto-stream-xor! "output buffer" out (bytes-length msg))
  (crypto-stream-xor* out msg nonce key))

(define (crypto-stream-xor msg nonce key)
  (define out (make-bytes (bytes-length msg)))
  (crypto-stream-xor* out msg nonce key))

;;---------------------------------------------------------------------------
;; One-time authentication

(define-nacl crypto_onetimeauth_poly1305
  (_fun _bytes _bytes _uint64 _bytes -> _int))
(define-nacl crypto_onetimeauth_poly1305_verify
  (_fun _bytes _bytes _uint64 _bytes -> _int))

(define (crypto-onetimeauth msg key)
  (define a (make-bytes crypto_onetimeauth_BYTES))
  (check-length 'crypto-onetimeauth "key" key crypto_onetimeauth_KEYBYTES)
  (check-result (crypto_onetimeauth a msg (bytes-length msg) key))
  a)

(define (crypto-onetimeauth-verify authenticator msg key)
  (check-length 'crypto-onetimeauth-verify "key" key crypto_onetimeauth_KEYBYTES)
  (and (= (bytes-length authenticator) crypto_onetimeauth_BYTES)
       (zero? (crypto_onetimeauth_verify authenticator msg (bytes-length msg) key))))

;;---------------------------------------------------------------------------
;; Authentication

(define-nacl crypto_auth_hmacsha512256
  (_fun _bytes _bytes _uint64 _bytes -> _int))
(define-nacl crypto_auth_hmacsha512256_verify
  (_fun _bytes _bytes _uint64 _bytes -> _int))

(define (crypto-auth msg key)
  (define a (make-bytes crypto_auth_BYTES))
  (check-length 'crypto-auth "key" key crypto_auth_KEYBYTES)
  (check-result (crypto_auth a msg (bytes-length msg) key))
  a)

(define (crypto-auth-verify authenticator msg key)
  (check-length 'crypto-auth-verify "key" key crypto_auth_KEYBYTES)
  (and (= (bytes-length authenticator) crypto_auth_BYTES)
       (zero? (crypto_auth_verify authenticator msg (bytes-length msg) key))))

;;---------------------------------------------------------------------------
;; Authenticated symmetric-key encryption

(define-nacl crypto_secretbox_xsalsa20poly1305
  (_fun _bytes _bytes _uint64 _bytes _bytes -> _int))
(define-nacl crypto_secretbox_xsalsa20poly1305_open
  (_fun _bytes _bytes _uint64 _bytes _bytes -> _int))

(define (crypto-secretbox-random-nonce)
  (random-bytes crypto_secretbox_NONCEBYTES))

(define (crypto-secretbox msg nonce key)
  (define m (zero-pad-left msg crypto_secretbox_ZEROBYTES))
  (define c (make-zero-bytes (bytes-length m)))
  (check-nonce 'crypto-secretbox nonce crypto_secretbox_NONCEBYTES)
  (check-length 'crypto-secretbox "key" key crypto_secretbox_KEYBYTES)
  (check-result (crypto_secretbox c m (bytes-length m) nonce key))
  (subbytes c crypto_secretbox_BOXZEROBYTES))

(define (crypto-secretbox-open ciphertext nonce key)
  (define c (zero-pad-left ciphertext crypto_secretbox_BOXZEROBYTES))
  (define m (make-zero-bytes (bytes-length c)))
  (check-nonce 'crypto-secretbox-open nonce crypto_secretbox_NONCEBYTES)
  (check-length 'crypto-secretbox "key" key crypto_secretbox_KEYBYTES)
  (check-result (crypto_secretbox_open m c (bytes-length c) nonce key))
  (subbytes m crypto_secretbox_ZEROBYTES))

;;---------------------------------------------------------------------------
;; Signing

(define-nacl crypto_sign_edwards25519sha512batch_keypair
  (_fun _bytes _bytes -> _int))
(define-nacl crypto_sign_edwards25519sha512batch
  (_fun _bytes (smlen : (_ptr o _uint64)) _bytes _uint64 _bytes -> (status : _int)
	-> (values status smlen)))
(define-nacl crypto_sign_edwards25519sha512batch_open
  (_fun _bytes (mlen : (_ptr o _uint64)) _bytes _uint64 _bytes -> (status : _int)
	-> (values status mlen)))

(define (make-crypto-sign-keypair)
  (define pk (make-bytes crypto_sign_PUBLICKEYBYTES))
  (define sk (make-bytes crypto_sign_SECRETKEYBYTES))
  (check-result (crypto_sign_keypair pk sk))
  (crypto-sign-keypair pk sk))

(define (crypto-sign msg sk)
  (define sm (make-zero-bytes (+ (bytes-length msg) crypto_sign_BYTES)))
  (check-length 'crypto-sign "sk" sk crypto_sign_SECRETKEYBYTES)
  (define-values (status smlen) (crypto_sign sm msg (bytes-length msg) sk))
  (when (not (zero? status)) (error 'crypto-sign "error from nacl primitive"))
  (subbytes sm 0 smlen))

(define (crypto-sign-open signed-msg pk)
  (define m (make-zero-bytes (bytes-length signed-msg)))
  (check-length 'crypto-sign "pk" pk crypto_sign_PUBLICKEYBYTES)
  (define-values (status mlen) (crypto_sign_open m signed-msg (bytes-length signed-msg) pk))
  (when (not (zero? status)) (error 'crypto-sign-open "error from nacl primitive"))
  (subbytes m 0 mlen))

;;---------------------------------------------------------------------------
;; Implementation details from autogenerated subnacl/sexpdefs.ss file
;;
;; sexpdefs.ss contains terms in a little DSL for specifying various
;; aspects of the C library we will be linking against. Here, we
;; define a few macros for making sense of this DSL in terms of Racket
;; constructs. Then we include sexpdefs.ss itself.

;; TODO: this omission looks like an error in the upstream codebase
(define crypto_stream_xsalsa20_BEFORENMBYTES "error: nacl doesn't provide a binding for this")

(define-syntax-rule (define-constant c v)
  (begin (define c v)
	 (provide c)))

(define-syntax-rule (define-implementation op prim preferred)
  (void))

(define-syntax-rule (define-alias n1 n2)
  (begin (define n1 n2)
	 (provide n1)))

(define-syntax-rule (define-nacl-version v)
  (begin (define nacl-version v)
	 (provide nacl-version)))

;; Stubs for missing/not-yet-defined values
;; TODO: provide all of these for real
(define-syntax-rule (define-stub n v)
  (define (v . args)
    (error 'v "Not implemented")))

(define-stub crypto_hashblocks crypto_hashblocks_sha512) ;; No sensible way of using this yet

(define-stub crypto_stream_beforenm crypto_stream_xsalsa20_beforenm) ;; Missing from upstream
(define-stub crypto_stream_afternm crypto_stream_xsalsa20_afternm) ;; Missing from upstream
(define-stub crypto_stream_xor_afternm crypto_stream_xsalsa20_xor_afternm) ;; Missing from upstream

(include "subnacl/sexpdefs.ss")
