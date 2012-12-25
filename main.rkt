#lang racket/base
;; Wrapper for the Networking and Cryptography Library, NaCL.

(require ffi/unsafe)
(require ffi/unsafe/define)
(require racket/include)
(require setup/dirs)

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

	 crypto-stream!
	 crypto-stream
	 crypto-stream-xor!
	 crypto-stream-xor)

(struct crypto-box-keypair (pk sk) #:prefab)
(struct crypto-box-state (k)) ;; not even transparent

;;---------------------------------------------------------------------------
;; FFI

(define (local-lib-dirs)
  (list* "."
	 (with-handlers ((exn:fail? (lambda (e) ".")))
	   (collection-path "racl"))
	 (get-lib-search-dirs)))

(define nacl-lib (ffi-lib "nacl" #:get-lib-dirs local-lib-dirs))

(define-ffi-definer define-nacl nacl-lib
  #:default-make-fail make-not-available)

;;---------------------------------------------------------------------------
;; Utilities

(define (make-zero-bytes n)
  (make-bytes n 0))

(define (zero-pad-left bs padding-length)
  (define new-bs (make-zero-bytes (+ (bytes-length bs) padding-length)))
  (bytes-copy! new-bs padding-length bs)
  new-bs)

(define-syntax-rule (check-result (f arg ...))
  (when (not (zero? (f arg ...)))
    (error 'f "error from nacl primitive")))

(define (check-length f what thing expected-length)
  (when (not (= (bytes-length thing) expected-length))
    (error f "expected ~a of length ~v, got length ~v" what expected-length (bytes-length thing))))

(define (check-nonce f n expected-length)
  (check-length f "nonce" n expected-length))

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
  (check-result (crypto_box c m (bytes-length m) nonce pk sk))
  (subbytes c crypto_box_BOXZEROBYTES))

(define (crypto-box-open ciphertext nonce pk sk)
  (define c (zero-pad-left ciphertext crypto_box_BOXZEROBYTES))
  (define m (make-zero-bytes (bytes-length c)))
  (check-nonce 'crypto-box-open nonce crypto_box_NONCEBYTES)
  (check-result (crypto_box_open m c (bytes-length c) nonce pk sk))
  (subbytes m crypto_box_ZEROBYTES))

(define (crypto-box-precompute pk sk)
  (define k (make-zero-bytes crypto_box_BEFORENMBYTES))
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

(define-stub crypto_onetimeauth crypto_onetimeauth_poly1305)
(define-stub crypto_onetimeauth_verify crypto_onetimeauth_poly1305_verify)
(define-stub crypto_auth crypto_auth_hmacsha512256)
(define-stub crypto_auth_verify crypto_auth_hmacsha512256_verify)
(define-stub crypto_secretbox crypto_secretbox_xsalsa20poly1305)
(define-stub crypto_secretbox_open crypto_secretbox_xsalsa20poly1305_open)
(define-stub crypto_sign crypto_sign_edwards25519sha512batch)
(define-stub crypto_sign_open crypto_sign_edwards25519sha512batch_open)
(define-stub crypto_sign_keypair crypto_sign_edwards25519sha512batch_keypair)

(include "subnacl/sexpdefs.ss")
