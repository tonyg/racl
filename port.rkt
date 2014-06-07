#lang racket/base

(require (only-in racket/bytes bytes-append*))
(require (only-in racket/port read-bytes-avail!-evt))
(require racket/set)
(require racket/match)

(require "main.rkt")
(require "spki-sexp.rkt")

(provide (struct-out exn:fail:contract:racl:port)

	 (struct-out certificate)
	 anonymous-keypair
	 anonymous-public-key?
	 make-certificate
	 certificate-subject-pk
	 certificate->spki-sexp
	 spki-sexp->certificate

	 encrypted-session-pipe-input-limit
	 encrypted-session-pipe-output-limit
	 encrypted-session-pipe-limit
	 encrypted-session-minimum-block-size
	 encrypted-session-block-interval-ms
	 encrypted-session-transfer-buffer-size

	 start-encrypted-session)

(struct exn:fail:contract:racl:port exn:fail:contract:racl () #:transparent)

(struct certificate (issuer-pk box-nonce subject-box) #:transparent)

(define anonymous-keypair (bytes->crypto-box-keypair #""))
(define anonymous-pk (crypto-box-keypair-pk anonymous-keypair))
(define anonymous-sk (crypto-box-keypair-sk anonymous-keypair))
(define (anonymous-public-key? pk) (equal? pk anonymous-pk))

(define (nonce-and-box m state)
  (define n (crypto-box-random-nonce))
  (values n (crypto-box* m n state)))

(define (make-certificate issuer-keypair subject-pk)
  (define-values (n box)
    (nonce-and-box subject-pk
		   (crypto-box-precompute anonymous-pk (crypto-box-keypair-sk issuer-keypair))))
  (certificate (crypto-box-keypair-pk issuer-keypair) n box))

(define (certificate-subject-pk c)
  (with-handlers [(exn:fail:contract:racl? (lambda (e) #f))]
    (crypto-box-open (certificate-subject-box c)
		     (certificate-box-nonce c)
		     (certificate-issuer-pk c)
		     anonymous-sk)))

(define (valid-pk? bs) (and (bytes? bs) (= (bytes-length bs) crypto_box_PUBLICKEYBYTES)))
(define (valid-nonce? bs) (and (bytes? bs) (= (bytes-length bs) crypto_box_NONCEBYTES)))

(define (certificate->spki-sexp c)
  `(#"certificate"
    (#"issuer" ,(certificate-issuer-pk c))
    (#"subject-box"
     ,(certificate-box-nonce c)
     ,(certificate-subject-box c))))

(define (spki-sexp->certificate s)
  (match s
    [`(#"certificate"
       (#"issuer" ,(? valid-pk? issuer-pk))
       (#"subject-box"
	,(? valid-nonce? box-nonce)
	,(? bytes? subject-box)))
     (certificate issuer-pk box-nonce subject-box)]
    [_ #f]))

(define encrypted-session-pipe-input-limit (make-parameter #f))
(define encrypted-session-pipe-output-limit (make-parameter #f))
(define encrypted-session-pipe-limit (make-parameter #f))
(define encrypted-session-block-pad-multiple (make-parameter 128))
(define encrypted-session-minimum-block-size (make-parameter #f))
(define encrypted-session-never-silent (make-parameter #f))
(define encrypted-session-block-interval-ms (make-parameter 50))
(define encrypted-session-transfer-buffer-size (make-parameter 32768))

(define (pad-to bs multiple)
  (define l (bytes-length bs))
  (define leftover (modulo l multiple))
  (if (zero? leftover) bs (bytes-append bs (make-bytes (- multiple leftover)))))

(define (build-block blocks-rev)
  (define len (foldr + 0 (map bytes-length blocks-rev)))
  (pad-block (bytes-append* (string->bytes/latin-1 (number->string len))
			    #":"
			    (reverse blocks-rev))))

(define (pad-block bs0)
  (define threshold (or (encrypted-session-minimum-block-size)
			(encrypted-session-block-pad-multiple)))
  (pad-to (pad-to bs0 threshold) (encrypted-session-block-pad-multiple)))

(define (send-sexp sexp state out-port)
  (send-block (pad-block (spki-sexp->bytes sexp)) state out-port))

(define (send-block bs state out-port)
  (define-values (n box) (nonce-and-box bs state))
  (write-spki-sexp (list n box) out-port)
  (flush-output out-port))

(define (recv-sexp state in-port)
  (define bs (recv-block state in-port))
  (if (bytes? bs)
      (bytes->spki-sexp bs)
      bs))

(define (recv-block state in-port)
  (match (read-spki-sexp in-port)
    [(? eof-object? x) x]
    [(list (? valid-nonce? nonce) (? bytes? box))
     (with-handlers [(exn:fail:contract:racl?
		      (lambda (e)
			(fail "start-encrypted-session: Could not open encrypted packet")))]
       (crypto-box-open* box nonce state))]
    [_ (fail "start-encrypted-session: Received invalid encrypted packet")]))

(define (relay-local->remote state local->remote-source local->remote-sink)
  (define transfer-buffer (make-bytes (encrypted-session-transfer-buffer-size)))
  (let loop ((blocks-rev '())
	     (deadline (+ (current-inexact-milliseconds) (encrypted-session-block-interval-ms))))
    (sync (handle-evt (port-closed-evt local->remote-sink)
		      (lambda dontcare
			(close-input-port local->remote-source)))
	  (handle-evt (alarm-evt deadline)
		      (lambda dontcare
			(when (or (pair? blocks-rev) (encrypted-session-never-silent))
			  (send-block (build-block blocks-rev) state local->remote-sink))
			(loop '() (+ deadline (encrypted-session-block-interval-ms)))))
	  (handle-evt (read-bytes-avail!-evt transfer-buffer local->remote-source)
		      (lambda (count-or-eof)
			(if (eof-object? count-or-eof)
			    (begin
			      (when (pair? blocks-rev)
				(send-block (build-block blocks-rev) state local->remote-sink))
			      (close-output-port local->remote-sink))
			    (loop (cons (subbytes transfer-buffer 0 count-or-eof) blocks-rev)
				  deadline)))))))

(define-syntax-rule (fail fmt arg ...)
  (raise (exn:fail:contract:racl:port (format fmt arg ...)
				      (current-continuation-marks))))

(define (relay-remote->local state remote->local-source remote->local-sink)
  (define (close-ports)
    (close-input-port remote->local-source)
    (close-output-port remote->local-sink))
  (with-handlers ((exn:fail? (lambda (e)
			       (close-ports)
			       (raise e))))
    (let loop ()
      (match (recv-sexp state remote->local-source)
	[(? eof-object?)
	 (close-ports)]
	[(? bytes? block)
	 (write-bytes block remote->local-sink)
	 (loop)]
	[_
	 (fail "relay-remote->local: Received invalid packet")]))))

(define (validate-peer! peer-identity-pk peer-certificates check-their-identity)
  (define claims (for/fold [(claims (hash))] [(cert peer-certificates)]
		   (define subject-pk (certificate-subject-pk cert))
		   (if (not subject-pk)
		       claims
		       (let ((issuers (hash-ref claims subject-pk (lambda () (set)))))
			 (hash-set claims subject-pk (set-add issuers
							      (certificate-issuer-pk cert)))))))
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

(define (start-encrypted-session in-port
				 out-port
				 [my-identity anonymous-keypair]
				 [check-their-identity (lambda (pk pks) #t)]
				 #:certificates [my-certificates '()])
  (write-spki-sexp `(#"nacl"
		     (#"version" #"0")
		     (#"pk" ,(crypto-box-keypair-pk my-identity))
		     ,(cons #"certificates" (map certificate->spki-sexp my-certificates)))
		   out-port)
  (flush-output out-port)

  (define-values (output-pipe-source output-pipe-sink)
    (make-pipe (or (encrypted-session-pipe-output-limit) (encrypted-session-pipe-limit))))
  (define-values (input-pipe-source input-pipe-sink)
    (make-pipe (or (encrypted-session-pipe-input-limit) (encrypted-session-pipe-limit))))

  (thread
   (lambda ()
     (with-handlers [(exn?
		      (lambda (e)
			(close-output-port input-pipe-sink)
			(close-input-port output-pipe-source)
			(close-output-port out-port)
			(close-input-port in-port)
			(raise e)))]
       (define peer-identity-pk
	 (match (read-spki-sexp in-port)
	   [`(#"nacl"
	      (#"version" #"0")
	      (#"pk" ,(? valid-pk? peer-identity-pk))
	      (#"certificates" ,cert-sexp ...))
	    (define peer-certificates
	      (for/list [(c cert-sexp)]
		(or (spki-sexp->certificate c)
		    (fail "start-encrypted-session: Received invalid certificate"))))
	    (validate-peer! peer-identity-pk peer-certificates check-their-identity)
	    peer-identity-pk]
	   [_ (fail "start-encrypted-session: Invalid protocol header")]))

       (define my-session-keys (make-crypto-box-keypair))
       (send-sexp `(#"newkey" ,(crypto-box-keypair-pk my-session-keys))
		  (crypto-box-precompute peer-identity-pk
					 (crypto-box-keypair-sk my-identity))
		  out-port)

       (define peer-session-pk
	 (match (recv-sexp (crypto-box-precompute peer-identity-pk
						  (crypto-box-keypair-sk my-identity))
			   in-port)
	   [`(#"newkey" ,(? valid-pk? peer-session-pk))
	    peer-session-pk]
	   [_ (fail "start-encrypted-session: Invalid peer session key")]))

       (define state
	 (crypto-box-precompute peer-session-pk (crypto-box-keypair-sk my-session-keys)))

       (thread (lambda () (relay-local->remote state output-pipe-source out-port)))
       (thread (lambda () (relay-remote->local state in-port input-pipe-sink))))))

  (values input-pipe-source output-pipe-sink))

(module+ test
  (require rackunit)
  (require (only-in racket/port with-output-to-bytes))

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

  (define-values (raw-a->b-source raw-a->b-sink) (make-logging-pipe "a->b"))
  (define-values (raw-b->a-source raw-b->a-sink) (make-logging-pipe "b->a"))

  (define-values (a-in a-out) (start-encrypted-session raw-b->a-source
						       raw-a->b-sink
						       a-kp
						       trusted-by-c?
						       #:certificates (list c-trusts-a)
						       ))
  (define-values (b-in b-out) (start-encrypted-session raw-a->b-source
						       raw-b->a-sink
						       b-kp
						       trusted-by-c?
						       #:certificates (list c-trusts-b)
						       ))

  (display "Hello, b!\n" a-out)
  (check-equal? (read-line b-in) "Hello, b!")
  (display "Hi, a\n" b-out)
  (check-equal? (read-line a-in) "Hi, a")
  (display "What is up\n" b-out)
  (check-equal? (read-line a-in) "What is up")
  (close-output-port b-out)
  (check-equal? (read-line a-in) eof)
  )
