#lang racket/base

(require (only-in openssl/sha1 sha1 bytes->hex-string))
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
;; One-time authentication

(check-equal? (crypto-onetimeauth #"Hello, world!!!!" (iota-bytes crypto_onetimeauth_KEYBYTES))
	      (hex-string->bytes #"C3 F6 82 F3 4C C6 29 FA 85 3A 4A DF 57 8D 7A 1F"))

(check-equal? (crypto-onetimeauth-verify
	       (hex-string->bytes #"C3 F6 82 F3 4C C6 29 FA 85 3A 4A DF 57 8D 7A 1F")
	       #"Hello, world!!!!"
	       (iota-bytes crypto_onetimeauth_KEYBYTES))
	      #t)

;;---------------------------------------------------------------------------
;; Authentication

(check-equal? (crypto-auth #"Hello, world!!!!" (iota-bytes crypto_auth_KEYBYTES))
	      (hex-string->bytes
	       #"723E07B01AA6766473ED6D433F75E41CB0C524ED607814C16DC24B3E9A0D7AC4"))

(check-equal? (crypto-auth-verify
	       (hex-string->bytes
		#"723E07B01AA6766473ED6D433F75E41CB0C524ED607814C16DC24B3E9A0D7AC4")
	       #"Hello, world!!!!"
	       (iota-bytes crypto_auth_KEYBYTES))
	      #t)

;;---------------------------------------------------------------------------
;; Authenticated symmetric-key encryption

(check-equal? (crypto-secretbox #"Meet in the old churchyard at midnight."
				(iota-bytes crypto_secretbox_NONCEBYTES)
				(iota-bytes crypto_secretbox_KEYBYTES))
	      (hex-string->bytes
	       #"01440C4518408578F1348926E058E82B139A5D3BE7A3CC30CF54EA1E07E32EB7"
	       #"31CD33ADEF4D468E65C647F521E7CC88E7B59CB22DC4DB"))

(check-equal? (crypto-secretbox-open
	       (hex-string->bytes
		#"01440C4518408578F1348926E058E82B139A5D3BE7A3CC30CF54EA1E07E32EB7"
		#"31CD33ADEF4D468E65C647F521E7CC88E7B59CB22DC4DB")
	       (iota-bytes crypto_secretbox_NONCEBYTES)
	       (iota-bytes crypto_secretbox_KEYBYTES))
	      #"Meet in the old churchyard at midnight.")

;;---------------------------------------------------------------------------
;; Signing

(define-values (pks sks)
  (values (hex-string->bytes #"cfdfa9d055a2f69b8828d7aca7bae0256d735c8f9a8db28f920ddc269a86aaec")
	  (hex-string->bytes #"105cece5569cda0b3e1a06dcf3d95c7559b1c942d5f8fe0270377500172d306d"
			     #"cfdfa9d055a2f69b8828d7aca7bae0256d735c8f9a8db28f920ddc269a86aaec")))

(check-equal? (crypto-sign #"Hello, world" sks)
	      (hex-string->bytes #"3c1d5b10d8feef927e7633501a53e8ddc5dc4439055acea3"
				 #"b96cf23b5c941540d50721dbae65cde0fadaefd26d924e25"
				 #"b3d59116240119df18f96366e0a7760c48656c6c6f2c20776f726c64"))

(check-equal? (crypto-sign-open
	       (hex-string->bytes #"3c1d5b10d8feef927e7633501a53e8ddc5dc4439055acea3"
				  #"b96cf23b5c941540d50721dbae65cde0fadaefd26d924e25"
				  #"b3d59116240119df18f96366e0a7760c48656c6c6f2c20776f726c64")
	       pks)
	      #"Hello, world")

(check-exn (regexp "error from nacl primitive")
	   (lambda ()
	     (crypto-sign-open
	      (hex-string->bytes #"3c1d5b10d8feef927e7633501a53e8ddc5dc4439055acea3"
				 #"b96cf23b5c941540d50721dbae65cde0fadaefd26d924e25"
				 #"b3d59116240119df18f96366e0a7760c48656c6c6f2c20776f726c65") ;; !
	      pks)))

;;---------------------------------------------------------------------------
;; Signing with seeded keypair generation.

(let ((keys (bytes->crypto-sign-keypair #"This is my passphrase"))
      (signed-message (hex-string->bytes
		       #"dd13136c30516f8d6a679129e1b21cecd0d6c21e050f13a4"
		       #"8468641565a3458e5390d83a301f9b5ba238097a7b443966"
		       #"3c7f5fb34684e09801d25bd08439a70248656c6c6f2c20776f726c64")))
  (check-equal? (crypto-sign #"Hello, world" (crypto-sign-keypair-sk keys)) signed-message)
  (check-equal? (crypto-sign-open signed-message (crypto-sign-keypair-pk keys)) #"Hello, world"))

;;---------------------------------------------------------------------------
;; Boxing

(define-values (pk1 sk1)
  (values (hex-string->bytes #"de1042928b74e9f96cf3f3e290c16cb4eba9c696e9a1e15c7f4d0514ddce1154")
	  (hex-string->bytes #"d54ff4b666a43070ab20937a92c49ecf65503583f8942350fc197c5023b015c3")))

(define pk1-hash (sha1 (open-input-bytes pk1)))
(check-equal? pk1-hash "69dcd04f5dfcda764b8920a90daac0e74495f6b2")

(match-define (crypto-box-keypair pk2 sk2) (make-crypto-box-keypair))

(match-define (crypto-box-keypair pk-anon sk-anon)
  (bytes->crypto-box-keypair #""))

(write `((pk-anon ,(bytes->hex-string pk-anon))
	 (sk-anon ,(bytes->hex-string sk-anon))))
(newline)

(let ((nonce (hex-string->bytes #"065114ca5a687e0544a88e6fc757b30afc70a0355854fd54"))
      (c (hex-string->bytes #"3bc95b7983622e8afb763723703e17c6739be9c316"))
      (k (crypto-box-precompute pk1 sk1)))
  (check-equal? (crypto-box-open c nonce pk1 sk1) #"hello")
  (check-equal? (crypto-box-open* c nonce k) #"hello")
  (check-equal? (crypto-box #"hello" nonce pk1 sk1) c)
  (check-equal? (crypto-box* #"hello" nonce k) c))

(let ((nonce (hex-string->bytes #"065114ca5a687e0544a88e6fc757b30afc70a0355854fd54"))
      (c0 (hex-string->bytes #"3bc95b7983622e8afb763723703e17c6739be9c316"))
      (c1 (hex-string->bytes #"3bc95b7983622e0afb763723703e17c6739be9c316"))
      (c2 (hex-string->bytes #"3bc95b7983622e8afb763723703e37c6739be9c316"))
      (c3 (hex-string->bytes #"2bc95b7983622e8afb763723703e17c6739be9c316"))
      (c4 (hex-string->bytes #"3bc95b7983622e8afb763723703e17c6739be9c317"))
      (k (crypto-box-precompute pk1 sk1)))
  (check-equal? (crypto-box-open c0 nonce pk1 sk1) #"hello")
  (for-each (lambda (c)
	      (check-exn #px"crypto_box_open: error from nacl primitive"
			 (lambda ()
			   (crypto-box-open c nonce pk1 sk1) #"hello")))
	    (list c1 c2 c3 c4)))

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
