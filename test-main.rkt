#lang racket/base

(require openssl/sha1)
(require racket/match)
(require "main.rkt")

(require rackunit)

(define (hex-string->bytes . strs) ;; grumble
  (define cleaned (bytes->string/utf-8 (regexp-replace* #rx"[^0-9a-fA-F]+"
							(apply bytes-append strs)
							"")))
  (define count (/ (string-length cleaned) 2))
  (define bs (make-bytes count 0))
  (for ((i (in-range count)))
    (bytes-set! bs i (string->number (substring cleaned (* i 2) (+ 2 (* i 2))) 16)))
  bs)

(define (iota-bytes count)
  (define bs (make-bytes count))
  (for ((i (in-range count))) (bytes-set! bs i i))
  bs)

;;---------------------------------------------------------------------------
;; Hashing

(check-equal? (crypto-hash-bytes #"")
	      (hex-string->bytes
	       #"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
	       #"47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"))

(check-equal? (crypto-hash-bytes #"The quick brown fox jumps over the lazy dog")
	      (hex-string->bytes
	       #"07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb64"
	       #"2e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"))

(check-equal? (crypto-hash-bytes #"The quick brown fox jumps over the lazy dog.")
	      (hex-string->bytes
	       #"91ea1245f20d46ae9a037a989f54f1f790f0a47607eeb8a14d12890cea77a1bb"
	       #"c6c7ed9cf205e67b7f2b8fd4c7dfd3a7a8617e45f3c463d481c7e586c39ac1ed"))

;;---------------------------------------------------------------------------
;; Symmetric-key encryption

(check-equal? (crypto-stream 16
			     (iota-bytes crypto_stream_NONCEBYTES)
			     (iota-bytes crypto_stream_KEYBYTES))
	      (hex-string->bytes #"7C B6 60 AF DD 9E C6 46 8F 57 DD 6D 24 33 F9 34"))

(check-equal? (crypto-stream-xor #"Hello, world!!!!"
				 (iota-bytes crypto_stream_NONCEBYTES)
				 (iota-bytes crypto_stream_KEYBYTES))
	      (hex-string->bytes #"34D30CC3B2B2E631E025B1090512D815"))

(check-equal? (crypto-stream-xor (hex-string->bytes #"34D30CC3B2B2E631E025B1090512D815")
				 (iota-bytes crypto_stream_NONCEBYTES)
				 (iota-bytes crypto_stream_KEYBYTES))
	      #"Hello, world!!!!")

;;---------------------------------------------------------------------------
;; Boxing

(define-values (pk1 sk1)
  (values (hex-string->bytes #"de1042928b74e9f96cf3f3e290c16cb4eba9c696e9a1e15c7f4d0514ddce1154")
	  (hex-string->bytes #"d54ff4b666a43070ab20937a92c49ecf65503583f8942350fc197c5023b015c3")))

(define pk1-hash (sha1 (open-input-bytes pk1)))
(check-equal? pk1-hash "69dcd04f5dfcda764b8920a90daac0e74495f6b2")

(match-define (crypto-box-keypair pk2 sk2) (make-crypto-box-keypair))

(let ((nonce (hex-string->bytes #"065114ca5a687e0544a88e6fc757b30afc70a0355854fd54"))
      (c (hex-string->bytes #"3bc95b7983622e8afb763723703e17c6739be9c316"))
      (k (crypto-box-precompute pk1 sk1)))
  (check-equal? (crypto-box-open c nonce pk1 sk1) #"hello")
  (check-equal? (crypto-box-open* c nonce k) #"hello")
  (check-equal? (crypto-box #"hello" nonce pk1 sk1) c)
  (check-equal? (crypto-box* #"hello" nonce k) c))

(define (round-trip msg)
  (define n (crypto-box-random-nonce))
  (define c (time (crypto-box msg n pk2 sk1)))
  (define m (time (crypto-box-open c n pk1 sk2)))
  (define ke (crypto-box-precompute pk2 sk1))
  (define kd (crypto-box-precompute pk1 sk2))
  (define c* (time (crypto-box* msg n ke)))
  (define m* (time (crypto-box-open* c* n kd)))
  (check-equal? m msg)
  (check-equal? m* msg))

(for ((i (in-range 8 21 4))) ;; 21 so we get 20 at the end
  (printf "round-tripping 2^~v random bytes\n" i)
  (round-trip (random-bytes (expt 2 i))))
