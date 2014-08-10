#lang racket/base

(require (only-in racket/bytes bytes-append*))
(require (only-in racket/port read-bytes-avail!-evt))
(require racket/set)
(require racket/match)

(require "main.rkt")
(require "spki-sexp.rkt")
(require "session.rkt")

(provide (all-from-out "session.rkt")

	 encrypted-session-pipe-input-limit
	 encrypted-session-pipe-output-limit
	 encrypted-session-pipe-limit
	 encrypted-session-never-silent
	 encrypted-session-packet-interval-ms
	 encrypted-session-transfer-buffer-size

	 encrypt-ports)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define encrypted-session-pipe-input-limit (make-parameter #f))
(define encrypted-session-pipe-output-limit (make-parameter #f))
(define encrypted-session-pipe-limit (make-parameter #f))
(define encrypted-session-never-silent (make-parameter #f))
(define encrypted-session-packet-interval-ms (make-parameter 50))
(define encrypted-session-transfer-buffer-size (make-parameter 32768))

(define (encrypt-ports in-port out-port session-maker)
  (define-values (local->remote handle-remote->local-packet session-evt) (session-maker))

  ;; output TO remote
  (define-values (output-pipe-source output-pipe-sink)
    (make-pipe (or (encrypted-session-pipe-output-limit) (encrypted-session-pipe-limit))))

  ;; input FROM remote
  (define-values (input-pipe-source input-pipe-sink)
    (make-pipe (or (encrypted-session-pipe-input-limit) (encrypted-session-pipe-limit))))

  (define (shutdown!)
    (close-output-port input-pipe-sink)
    (close-input-port output-pipe-source)
    (close-output-port out-port)
    (close-input-port in-port))

  (define (shutdown-and-raise! e)
    (shutdown!)
    (raise e))

  (thread
   (lambda ()
     (with-handlers [(exn? shutdown-and-raise!)]
       (let loop ()
	 (match (read-spki-sexp in-port)
	   [(? eof-object?)
	    (close-input-port in-port)
	    (handle-remote->local-packet #f)]
	   [packet
	    (handle-remote->local-packet packet)
	    (loop)])))))

  (thread
   (lambda ()
     (with-handlers [(exn? shutdown-and-raise!)]
       (define transfer-buffer (make-bytes (encrypted-session-transfer-buffer-size)))
       (let loop ((blocks-rev '())
		  (deadline (+ (current-inexact-milliseconds)
			       (encrypted-session-packet-interval-ms))))
	 (sync (handle-evt session-evt
			   (match-lambda
			    [(sexp-from-peer blocks)
			     (for [(block blocks)] (write-bytes block input-pipe-sink))
			     (loop blocks-rev deadline)]
			    [(sexp-to-peer packet)
			     (write-spki-sexp packet out-port)
			     (flush-output out-port)
			     (loop blocks-rev deadline)]
			    [(or #f (? exn?))
			     (close-output-port input-pipe-sink)
			     (close-input-port output-pipe-source)
			     (close-output-port out-port)]))
	       (handle-evt (alarm-evt deadline)
			   (lambda dontcare
			     (when (or (pair? blocks-rev) (encrypted-session-never-silent))
			       (local->remote (reverse blocks-rev)))
			     (loop '() (+ deadline (encrypted-session-packet-interval-ms)))))
	       (handle-evt (read-bytes-avail!-evt transfer-buffer output-pipe-source)
			   (match-lambda
			    [(? eof-object?)
			     (when (pair? blocks-rev)
			       (local->remote (reverse blocks-rev)))
			     (local->remote #f)
			     (loop '() deadline)]
			    [count
			     (loop (cons (subbytes transfer-buffer 0 count) blocks-rev)
				   deadline)])))))))

  (values input-pipe-source output-pipe-sink))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Tests

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

  (define-values (a-in a-out)
    (encrypt-ports raw-b->a-source raw-a->b-sink
		   (lambda ()
		     (start-encrypted-session a-kp trusted-by-c?
					      #:certificates (list c-trusts-a)))))

  (define-values (b-in b-out)
    (encrypt-ports raw-a->b-source raw-b->a-sink
		   (lambda ()
		     (start-encrypted-session b-kp trusted-by-c?
					      #:certificates (list c-trusts-b)))))

  (display "Hello, b!\n" a-out)
  (check-equal? (read-line b-in) "Hello, b!")
  (display "Hi, a\n" b-out)
  (check-equal? (read-line a-in) "Hi, a")
  (display "What is up\n" b-out)
  (check-equal? (read-line a-in) "What is up")
  (close-output-port b-out)
  (check-equal? (read-line a-in) eof)
  (check-equal? (read-line b-in) eof)
  )
