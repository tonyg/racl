#lang racket/base

(require racket/match)
(require racket/sandbox)

(provide repl-shell)

(struct user-state (name master-sandbox master-namespace) #:transparent)

(define *user-states* (make-hash))

(define (get-user-state username)
  (when (not (hash-has-key? *user-states* username))
    (let* ((sb (make-evaluator 'racket/base))
	   (ns (call-in-sandbox-context sb current-namespace)))
      (hash-set! *user-states* username
		 (user-state username
			     sb
			     ns))))
  (hash-ref *user-states* username))

(define (repl-shell username in out)
  (match-define (user-state _ master-sandbox master-namespace) (get-user-state username))
  (parameterize ((current-input-port in)
		 (current-output-port out)
		 (current-error-port out)
		 (sandbox-input in)
		 (sandbox-output out)
		 (sandbox-error-output out)
		 (sandbox-memory-limit 2) ;; megabytes
		 (sandbox-eval-limits #f)
		 (sandbox-namespace-specs (list (lambda () master-namespace))))
    (printf "Hello, ~a.\n" username)
    (define slave-sandbox (make-evaluator '(begin)))
    ;; ^^ uses master-namespace via sandbox-namespace-specs
    (parameterize ((current-namespace master-namespace)
		   (current-eval slave-sandbox))
      (read-eval-print-loop))
    (fprintf out "\nGoodbye!\n")
    (kill-evaluator slave-sandbox)
    (close-input-port in)
    (close-output-port out)))

(module+ main
  (require racket/cmdline)
  (require racket/tcp)
  (require "../tcp.rkt")

  (define port 2222)

  (command-line
   #:program "repl-server.rkt"
   #:once-each
   ["-p" port-number "TCP port number to listen on"
    (set! port (string->number port-number))])

  (log-info "Listening on port ~a" port)
  (define l (tcp-listen port 4 #t))
  (let loop ()
    (define-values (i o) (encrypted-tcp-accept l))
    (log-info "Got connection")
    (thread (lambda ()
	      (display "Enter your username> " o)
	      (flush-output o)
	      (repl-shell (read-line i) i o)))
    (loop)))
