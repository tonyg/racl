#lang racket/base

(provide (struct-out exn:fail:contract:racl:session)

	 (struct-out certificate)
	 anonymous-keypair
	 anonymous-public-key?
	 make-certificate
	 certificate-subject-pk
	 certificate->spki-sexp
	 spki-sexp->certificate

	 encrypted-session-block-pad-multiple
	 encrypted-session-minimum-block-size

	 (struct-out sexp-from-peer)
	 (struct-out sexp-to-peer)
	 start-encrypted-session)

(require racket/set)
(require racket/match)
(require racket/async-channel)

(require "main.rkt")
(require "spki-sexp.rkt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Exceptions

(struct exn:fail:contract:racl:session exn:fail:contract:racl () #:transparent)

(define-syntax-rule (fail fmt arg ...)
  (raise (exn:fail:contract:racl:session (format fmt arg ...)
					 (current-continuation-marks))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Certificates and identities

;; A Certificate is a signed statement from some *issuer* vouching for
;; the ability of some *subject* to access a service, represented as a
;; (certificate PublicKey Nonce (Boxof PublicKey)), where the box is
;; encrypted by the issuer for the anonymous key and contains the
;; public-key of the subject.
;;
;; Certificates are intended to be chainable: if A grants B access,
;; and B grants C access, and A primitively has access, then C will be
;; allowed access when the certificate chain is checked.
(struct certificate (issuer-pk box-nonce subject-box) #:transparent)

;; The anonymous keypair is simply the keypair derived from the empty byte-string.
;; public-key: 20d2d5a2cdd64d78eeb5437b33d1cb848204f5f3a4665eb5e55e6623387a8667
;; secret-key: cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce
(define anonymous-keypair (bytes->crypto-box-keypair #""))
(define anonymous-pk (crypto-box-keypair-pk anonymous-keypair))
(define anonymous-sk (crypto-box-keypair-sk anonymous-keypair))
(define (anonymous-public-key? pk) (equal? pk anonymous-pk))

;; Constructs a certificate stating that an issuer grants access to
;; some service to a subject.
(define (make-certificate issuer-keypair subject-pk)
  (define-values (n box)
    (nonce-and-box subject-pk
		   (crypto-box-precompute anonymous-pk (crypto-box-keypair-sk issuer-keypair))))
  (certificate (crypto-box-keypair-pk issuer-keypair) n box))

;; Extracts the subject public-key contained in a certificate. If the
;; certificate is invalid or corrupt, returns #f. Only returns non-#f
;; when the certificate is valid.
(define (certificate-subject-pk c)
  (with-handlers [(exn:fail:contract:racl? (lambda (e) #f))]
    (crypto-box-open (certificate-subject-box c)
		     (certificate-box-nonce c)
		     (certificate-issuer-pk c)
		     anonymous-sk)))

;; Syntax checks on public-keys and box-nonces. TODO: move to main.rkt?
(define (valid-pk? bs) (and (bytes? bs) (= (bytes-length bs) crypto_box_PUBLICKEYBYTES)))
(define (valid-nonce? bs) (and (bytes? bs) (= (bytes-length bs) crypto_box_NONCEBYTES)))

;; Serialize a certificate.
(define (certificate->spki-sexp c)
  `(#"certificate"
    (#"issuer" ,(certificate-issuer-pk c))
    (#"subject-box"
     ,(certificate-box-nonce c)
     ,(certificate-subject-box c))))

;; Deserialize a certificate.
(define (spki-sexp->certificate s)
  (match s
    [`(#"certificate"
       (#"issuer" ,(? valid-pk? issuer-pk))
       (#"subject-box"
	,(? valid-nonce? box-nonce)
	,(? bytes? subject-box)))
     (certificate issuer-pk box-nonce subject-box)]
    [_ #f]))

;; PublicKey (Listof Certificate) (PublicKey (Setof PublicKey) -> Boolean) -> Void
;;
;; Computes a the set of all issuing keys that (transitively) vouch
;; for the given peer-identity-pk. Calls check-their-identity with the
;; identity to be checked and the set of all transitively-reachable
;; vouching issuers. Raises an exception if the peer identity check
;; fails.
;;
;; A check-their-identity function could check the intersection of the
;; set of reachable issuers and some set of trusted keys, for example.
(define (validate-peer! peer-identity-pk peer-certificates check-their-identity)
  ;; claims : (HashTable PublicKey (Setof PublicKey))
  ;; Maps each subject to the set of directly vouching issuers.
  (define claims (for/fold [(claims (hash))] [(cert peer-certificates)]
		   (define subject-pk (certificate-subject-pk cert))
		   (if (not subject-pk)
		       claims
		       (let ((issuers (hash-ref claims subject-pk (lambda () (set)))))
			 (hash-set claims subject-pk (set-add issuers
							      (certificate-issuer-pk cert)))))))
  ;; pks : (Setof PublicKey)
  ;; The collection of transitively-reachable vouching issuers, rooted
  ;; at peer-identity-pk. Built using simple breadth-first-search.
  (define pks
    (let loop ((pks (set)) (worklist (list peer-identity-pk)))
      (match worklist
	['() pks]
	[(cons pk rest)
	 (if (set-member? pks pk)
	     (loop pks rest)
	     (loop (set-add pks pk)
		   (append worklist (set->list (hash-ref claims pk (lambda () (set)))))))])))
  (when (not (check-their-identity peer-identity-pk pks))
    (fail "start-encrypted-session: Peer identity check failed")))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Packet protocol.

;; Each encrypted block will be padded to a multiple of this
;; parameter. This helps obscure differences in block content.
(define encrypted-session-block-pad-multiple (make-parameter 128))
;; Each encrypted block will be padded to at least this many bytes.
;; This helps obscure differences in block content.
(define encrypted-session-minimum-block-size (make-parameter 1))

;; Sexp PrecomputedCryptoBoxState -> Sexp
(define (encipher-sexp sexp precomputed-crypto-box-state)
  (define padded-cleartext (build-block (spki-sexp->bytes sexp)))
  (define-values (n ciphertext) (nonce-and-box padded-cleartext precomputed-crypto-box-state))
  (list n ciphertext))

;; Sexp PrecomputedCryptoBoxState -> Sexp
(define (decipher-sexp sexp precomputed-crypto-box-state)
  (match sexp
    [(list (? valid-nonce? nonce) (? bytes? ciphertext))
     (define padded-cleartext
       (with-handlers [(exn:fail:contract:racl? bad-packet)]
	 (crypto-box-open* ciphertext nonce precomputed-crypto-box-state)))
     (define cleartext (bytes->spki-sexp padded-cleartext))
     (unless (bytes? cleartext) (bad-packet))
     (bytes->spki-sexp cleartext)]
    [_ (bad-packet)]))

(define (bad-packet . args)
  (fail "start-encrypted-session: Received invalid encrypted packet"))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Sessions.

(struct sexp-from-peer (s) #:prefab)
(struct sexp-to-peer (s) #:prefab)

;; [BoxKeypair [(PublicKey (Setof PublicKey) -> Boolean)]]
;;    [#:certificates (Listof Certificate)]
;; -> (Values (Sexp -> Void)        ;; send sexp to peer
;;            (Sexp -> Void)        ;; handle network packets
;;            (Evtof (U (sexp-from-peer Sexp)
;;                      (sexp-to-peer Sexp)
;;                      Exn
;;                      False)))
;;
;; Produces three values.
;;  - A function accepting a sexp to be enciphered and delivered
;;    to the remote peer.
;;  - A function accepting a sexp received from the peer to be
;;    deciphered, handled, and perhaps delivered locally.
;;  - An event that when synchronised on yields either
;;     - a sexp from the peer, or
;;     - a sexp for delivery to the peer, or
;;     - an exception, or
;;     - #f.
;;
;; If the event yields an exception or #f, the session will no longer
;; accept input or produce further output. Exceptions signal some
;; problem detected by the session driver, and #f signals normal
;; session shutdown.
;;
;; To close down the session, pass #f into either of the functions
;; returned from start-encrypted-session.
;;
(define (start-encrypted-session [my-identity anonymous-keypair]
				 [check-their-identity (lambda (pk pks) #t)]
				 #:certificates [my-certificates '()])
  (define reply-ch (make-async-channel))

  (define session-thread
    (thread (lambda ()
	      (with-handlers [(exn? (lambda (e)
				      (async-channel-put reply-ch e)
				      (raise e)))]
		(session-thread-main reply-ch my-identity my-certificates check-their-identity)
		(async-channel-put reply-ch #f)))))

  (define (accept-user-sexp s)
    (thread-send session-thread (and s (cons 'user s)) #f))

  (define (accept-network-sexp s)
    (thread-send session-thread (and s (cons 'network s)) #f))

  (values accept-user-sexp
	  accept-network-sexp
	  reply-ch))


(define (session-thread-main reply-ch my-identity my-certificates check-their-identity)

  (define (send-to-peer! sexp)
    (async-channel-put reply-ch (sexp-to-peer sexp)))

  ;;---------------------------------------------------------------------------
  ;; States

  (define (wait-for-header buffered-user-sexps-rev)
    (match (thread-receive)
      [#f 'done]
      [(cons 'user s) (wait-for-header (cons s buffered-user-sexps-rev))]
      [(cons 'network s)
       (match s
	 [`(#"nacl"
	    (#"version" #"0")
	    (#"pk" ,(? valid-pk? peer-identity-pk))
	    (#"certificates" ,cert-sexp ...))
	  (define peer-certificates
	    (for/list [(c cert-sexp)]
	      (or (spki-sexp->certificate c)
		  (fail "start-encrypted-session: Received invalid certificate"))))
	  (validate-peer! peer-identity-pk peer-certificates check-their-identity)
	  (exchange-keys buffered-user-sexps-rev peer-identity-pk)]
	 [_ (fail "start-encrypted-session: Invalid protocol header")])]
      [x (fail "start-encrypted-session: Internal error: received unknown command ~a" x)]))

  (define (exchange-keys buffered-user-sexps-rev peer-identity-pk)
    (define my-session-keys (make-crypto-box-keypair))
    (send-to-peer! (encipher-sexp
		    `(#"newkey" ,(crypto-box-keypair-pk my-session-keys))
		    (crypto-box-precompute peer-identity-pk
					   (crypto-box-keypair-sk my-identity))))
    (wait-for-newkey buffered-user-sexps-rev peer-identity-pk my-session-keys))

  (define (wait-for-newkey buffered-user-sexps-rev peer-identity-pk my-session-keys)
    (match (thread-receive)
      [#f 'done]
      [(cons 'user s) (wait-for-newkey (cons s buffered-user-sexps-rev)
				       peer-identity-pk
				       my-session-keys)]
      [(cons 'network s)
       (match (decipher-sexp s (crypto-box-precompute peer-identity-pk
						      (crypto-box-keypair-sk my-identity)))
	 [`(#"newkey" ,(? valid-pk? peer-session-pk))
	  (define precomputed-crypto-box-state
	    (crypto-box-precompute peer-session-pk (crypto-box-keypair-sk my-session-keys)))
	  (send-buffered-sexps (reverse buffered-user-sexps-rev)
			       peer-identity-pk
			       precomputed-crypto-box-state)]
	 [_ (fail "start-encrypted-session: Invalid peer session key")])]
      [x (fail "start-encrypted-session: Internal error: received unknown command ~a" x)]))

  (define (send-buffered-sexps buf peer-identity-pk precomputed-crypto-box-state)
    (match buf
      ['()
       (main-session-loop peer-identity-pk precomputed-crypto-box-state)]
      [(cons s rest)
       (send-to-peer! (encipher-sexp s precomputed-crypto-box-state))
       (send-buffered-sexps rest peer-identity-pk precomputed-crypto-box-state)]))

  (define (main-session-loop peer-identity-pk precomputed-crypto-box-state)
    (match (thread-receive)
      [#f 'done]
      [(cons 'user s)
       (send-to-peer! (encipher-sexp s precomputed-crypto-box-state))
       (main-session-loop peer-identity-pk precomputed-crypto-box-state)]
      [(cons 'network s)
       (async-channel-put reply-ch (sexp-from-peer (decipher-sexp s precomputed-crypto-box-state)))
       (main-session-loop peer-identity-pk precomputed-crypto-box-state)]))

  ;;---------------------------------------------------------------------------
  ;; Enter state machine

  (send-to-peer! `(#"nacl"
		   (#"version" #"0")
		   (#"pk" ,(crypto-box-keypair-pk my-identity))
		   ,(cons #"certificates"
			  (map certificate->spki-sexp my-certificates))))

  (wait-for-header '()))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Utilities

(define (nonce-and-box m precomputed-crypto-box-state)
  (define n (crypto-box-random-nonce))
  (values n (crypto-box* m n precomputed-crypto-box-state)))

(define (build-block bs)
  (pad-block (bytes-append (string->bytes/latin-1 (number->string (bytes-length bs)))
			   #":"
			   bs)))

(define (pad-block bs0)
  (pad-to (pad-to bs0 (encrypted-session-minimum-block-size))
	  (encrypted-session-block-pad-multiple)))

(define (pad-to bs multiple)
  (define l (bytes-length bs))
  (define leftover (modulo l multiple))
  (if (zero? leftover) bs (bytes-append bs (make-bytes (- multiple leftover)))))

;; Given an async-channel, converts it to an (evt?) which can only be
;; used to read values from the channel, and which no longer gives
;; access to write values onto the channel.
(define (read-only-wrapper async-channel)
  (handle-evt async-channel values))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Tests

(module+ test
  (require rackunit)

  (define (make-logging-pipe name)
    (define-values (r1 w1) (make-pipe))
    (define-values (r2 w2) (make-pipe))
    (thread (lambda ()
	      (let loop ()
		(define s (read-spki-sexp r1))
		(log-info "~a: ~v" name (if (eof-object? s)
					    s
					    (let ((bs (spki-sexp->bytes s)))
					      (cons (bytes-length bs)
						    (bytes->string/latin-1 bs)))))
		(when (not (eof-object? s))
		  (write-spki-sexp s w2)
		  (flush-output w2)
		  (loop)))
	      (close-input-port r1)
	      (close-output-port w2)))
    (values r2 w1))

  (define a-kp (bytes->crypto-box-keypair #"a"))
  (define b-kp (bytes->crypto-box-keypair #"b"))
  (define c-kp (bytes->crypto-box-keypair #"c"))

  (define c-trusts-a (make-certificate c-kp (crypto-box-keypair-pk a-kp)))
  (define c-trusts-b (make-certificate c-kp (crypto-box-keypair-pk b-kp)))

  (log-info "c's pk is ~v" (crypto-box-keypair-pk c-kp))
  (define (trusted-by-c? pk pks)
    (log-info "trusted-by-c?: trust ~v if we trust any of ~v" pk pks)
    (set-member? pks (crypto-box-keypair-pk c-kp)))

  (define-values (a->b handle-b->a-packet a-evt)
    (start-encrypted-session a-kp trusted-by-c?
			     #:certificates (list c-trusts-a)))

  (define-values (b->a handle-a->b-packet b-evt)
    (start-encrypted-session b-kp trusted-by-c?
			     #:certificates (list c-trusts-b)))

  (define (shuffle from to other-from other-to)
    (let loop ()
      (sync (handle-evt from
			(match-lambda
			 [(sexp-from-peer s) s]
			 [(sexp-to-peer s) (to s) (loop)]
			 [(? exn? e) (raise e)]
			 [other other]))
	    (handle-evt other-from
			(match-lambda
			 [(sexp-from-peer s) (error 'shuffle "Unexpected ~a" s)]
			 [(sexp-to-peer s) (other-to s) (loop)]
			 [(? exn? e) (raise e)]
			 [other other])))))

  (define (a-wait) (shuffle a-evt handle-a->b-packet b-evt handle-b->a-packet))
  (define (b-wait) (shuffle b-evt handle-b->a-packet a-evt handle-a->b-packet))

  ;; (local-require racket/trace)
  ;; (trace a->b handle-b->a-packet a-wait)
  ;; (trace b->a handle-a->b-packet b-wait)

  (a->b #"Hello, b!")
  (check-equal? (b-wait) #"Hello, b!")
  (b->a #"Hi, a")
  (check-equal? (a-wait) #"Hi, a")
  (b->a #"What is up")
  (check-equal? (a-wait) #"What is up")

  (a->b #f)
  (check-equal? (a-wait) #f)

  (handle-a->b-packet #f)
  (check-equal? (b-wait) #f)
  )
