#lang racket/base
;; Derivation of keypairs from seeds.

(require ffi/unsafe)
(require "ffi-lib.rkt")
(require "wrapper.rkt")

(provide bytes->crypto-sign-keypair
	 seed->crypto-sign-keypair
	 bytes->crypto-box-keypair)

(define-nacl crypto_sign_keypair_from_raw_sk ;; defined in keys.c
  (_fun _bytes _bytes _bytes -> _int))

(define-nacl crypto_scalarmult_curve25519_base ;; part of subnacl proper
  (_fun _bytes _bytes -> _int))

(define (bytes->crypto-sign-keypair bs)
  ;; Hash the bytes and trim to required length to get a seed.
  (define seed (subbytes (crypto-hash-bytes bs) 0 (/ crypto_sign_SECRETKEYBYTES 2)))
  (seed->crypto-sign-keypair seed))

(define (seed->crypto-sign-keypair seed)
  (check-length 'seed->crypto-sign-keypair "seed" seed (/ crypto_sign_SECRETKEYBYTES 2))
  ;; Allocate space for public and private keys.
  (define pk (make-bytes crypto_sign_PUBLICKEYBYTES))
  (define sk (make-bytes crypto_sign_SECRETKEYBYTES))
  (check-result (crypto_sign_keypair_from_raw_sk pk sk seed))
  (crypto-sign-keypair pk sk))

(define (bytes->crypto-box-keypair bs)
  ;; Hash the bytes to get a secret key.
  (define sk (subbytes (crypto-hash-bytes bs) 0 crypto_box_SECRETKEYBYTES))
  ;; Allocate space for a public key.
  (define pk (make-bytes crypto_box_PUBLICKEYBYTES))
  (check-result (crypto_scalarmult_curve25519_base pk sk))
  (crypto-box-keypair pk sk))
