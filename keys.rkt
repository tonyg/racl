#lang racket/base
;; Derivation of keypairs from seeds.

(require ffi/unsafe)
(require "ffi-lib.rkt")
(require "wrapper.rkt")

(provide bytes->crypto-sign-keypair)

(define-nacl crypto_sign_keypair_from_raw_sk ;; defined in keys.c
  (_fun _bytes _bytes -> _int))

(define (bytes->crypto-sign-keypair bs)
  ;; Hash the bytes to get a secret key. This will be MODIFIED IN PLACE by the FFI call below.
  (define sk (subbytes (crypto-hash-bytes bs) 0 crypto_sign_SECRETKEYBYTES))
  ;; Allocate space for a public key.
  (define pk (make-bytes crypto_sign_PUBLICKEYBYTES))
  (check-result (crypto_sign_keypair_from_raw_sk pk sk))
  (crypto-sign-keypair pk sk))
