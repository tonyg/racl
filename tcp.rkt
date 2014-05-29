#lang racket/base

(require racket/tcp)
(require "port.rkt")

(provide encrypted-tcp-accept
	 encrypted-tcp-connect)

(define (encrypted-tcp-accept listener)
  (define-values (i o) (tcp-accept listener))
  (start-encrypted-session i o))

(define (encrypted-tcp-connect . args)
  (define-values (i o) (apply tcp-connect args))
  (start-encrypted-session i o))
