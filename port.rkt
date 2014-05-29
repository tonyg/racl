#lang racket/base

(require (only-in racket/bytes bytes-append*))
(require (only-in racket/port read-bytes-avail!-evt))
(require racket/match)

(require "main.rkt")
(require "spki-sexp.rkt")

(provide encrypted-session-pipe-input-limit
	 encrypted-session-pipe-output-limit
	 encrypted-session-pipe-limit
	 encrypted-session-minimum-block-size
	 encrypted-session-block-interval-ms
	 encrypted-session-transfer-buffer-size

	 start-encrypted-session)

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
  (define bs0 (bytes-append* (string->bytes/latin-1 (number->string len))
			     #":"
			     (reverse blocks-rev)))
  (define bs (let* ((threshold (or (encrypted-session-minimum-block-size)
				   (encrypted-session-block-pad-multiple))))
	       (pad-to (pad-to bs0 threshold) (encrypted-session-block-pad-multiple))))
  bs)

(define (send-block bs state p)
  (define nonce (crypto-box-random-nonce))
  (define payload (crypto-box* bs nonce state))
  (write-spki-sexp `(#"data" ,nonce ,payload) p)
  (flush-output p))

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

(define (relay-remote->local state remote->local-source remote->local-sink)
  (define (close-ports)
    (close-input-port remote->local-source)
    (close-output-port remote->local-sink))
  (with-handlers ((exn:fail? (lambda (e)
			       (close-ports)
			       (raise e))))
    (let loop ()
      (match (read-spki-sexp remote->local-source)
	[(? eof-object?)
	 (close-ports)]
	[`(#"data" ,nonce ,payload)
	 (define bs (with-handlers ((exn:fail? (lambda () #f)))
		      (crypto-box-open* payload nonce state)))
	 (when (not bs) (error 'relay-remote->local "Could not open encrypted packet"))
	 (define block (read-spki-sexp (open-input-bytes bs)))
	 (write-bytes block remote->local-sink)
	 (loop)]
	[_
	 (error 'relay-remote->local "Received invalid packet")]))))

(define (start-encrypted-session in-port out-port)
  (define session-keys (make-crypto-box-keypair))
  (write-spki-sexp `(#"nacl"
		     (#"version" #"0")
		     (#"pk" ,(crypto-box-keypair-pk session-keys)))
		   out-port)
  (flush-output out-port)

  (define-values (output-pipe-source output-pipe-sink)
    (make-pipe (or (encrypted-session-pipe-output-limit) (encrypted-session-pipe-limit))))
  (define-values (input-pipe-source input-pipe-sink)
    (make-pipe (or (encrypted-session-pipe-input-limit) (encrypted-session-pipe-limit))))

  (thread
   (lambda ()
     (match (read-spki-sexp in-port)
       [`(#"nacl"
	  (#"version" #"0")
	  (#"pk" ,(? bytes? peer-pk)))
	(when (not (equal? (bytes-length peer-pk) crypto_box_PUBLICKEYBYTES))
	  (error 'start-encrypted-session "Invalid peer public-key"))
	(define state (crypto-box-precompute peer-pk (crypto-box-keypair-sk session-keys)))
	(thread (lambda () (relay-local->remote state output-pipe-source out-port)))
	(thread (lambda () (relay-remote->local state in-port input-pipe-sink)))]
       [other
	(close-output-port input-pipe-sink)
	(close-input-port output-pipe-source)
	(close-output-port out-port)
	(close-input-port in-port)
	(error 'start-encrypted-session "Invalid protocol header")])))

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
		(log-info "~a: ~v" name s)
		(when (not (eof-object? s))
		  (write-spki-sexp s w2)
		  (flush-output w2)
		  (loop)))
	      (close-input-port r1)
	      (close-output-port w2)))
    (values r2 w1))

  (define-values (raw-a->b-source raw-a->b-sink) (make-logging-pipe "a->b"))
  (define-values (raw-b->a-source raw-b->a-sink) (make-logging-pipe "b->a"))

  (define-values (a-in a-out) (start-encrypted-session raw-b->a-source raw-a->b-sink))
  (define-values (b-in b-out) (start-encrypted-session raw-a->b-source raw-b->a-sink))

  (display "Hello, b!\n" a-out)
  (check-equal? (read-line b-in) "Hello, b!")
  (display "Hi, a\n" b-out)
  (check-equal? (read-line a-in) "Hi, a")
  (display "What is up\n" b-out)
  (check-equal? (read-line a-in) "What is up")
  (close-output-port b-out)
  (check-equal? (read-line a-in) eof)
  )
