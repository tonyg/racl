#lang racket/base

(require racket/match)
(require "main.rkt")

(require rackunit)

(define (hex-string->bytes str) ;; grumble
  (define cleaned (bytes->string/utf-8 (regexp-replace* #rx"[^0-9a-fA-F]+" str "")))
  (define count (/ (string-length cleaned) 2))
  (define bs (make-bytes count 0))
  (for ((i (in-range count)))
    (bytes-set! bs i (string->number (substring cleaned (* i 2) (+ 2 (* i 2))) 16)))
  bs)

(define-values (pk1 sk1)
  (values (hex-string->bytes #"de1042928b74e9f96cf3f3e290c16cb4eba9c696e9a1e15c7f4d0514ddce1154")
	  (hex-string->bytes #"d54ff4b666a43070ab20937a92c49ecf65503583f8942350fc197c5023b015c3")))

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
