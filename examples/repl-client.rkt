#lang racket/base

(require racket/cmdline)
(require racket/tcp)
(require racket/port)
(require "../tcp.rkt")

(define port 2222)

(command-line
 #:program "repl-client.rkt"
 #:once-each
 ["-p" port-number "TCP port number to connect to"
  (set! port (string->number port-number))])

(define-values (i o) (encrypted-tcp-connect "localhost" port))
(void (thread (lambda () (copy-port i (current-output-port)))))
(copy-port (current-input-port) o)
