#lang racket/base

(require racket/set)
(require racket/tcp)
(require "port.rkt")

(provide encrypted-tcp-accept
	 encrypted-tcp-connect)

(define ((check-peer trusted-peers) peer-pk peer-root-pks)
  (or (eq? trusted-peers #t)
      (not (set-empty? (set-intersect trusted-peers peer-root-pks)))))

(define (encrypted-tcp-accept
	 #:local-identity [local-identity anonymous-keypair]
	 #:local-certificates [local-certificates '()]
	 #:trusted-peers [trusted-peers #t]
	 #:validate-peer-identity [validate-peer-identity (check-peer trusted-peers)]
	 listener)
  (define-values (i o) (tcp-accept listener))
  (start-encrypted-session i o local-identity validate-peer-identity
			   #:certificates local-certificates))

(define (encrypted-tcp-connect
	 #:local-identity [local-identity anonymous-keypair]
	 #:local-certificates [local-certificates '()]
	 #:trusted-peers [trusted-peers #t]
	 #:validate-peer-identity [validate-peer-identity (check-peer trusted-peers)]
	 . args)
  (define-values (i o) (apply tcp-connect args))
  (start-encrypted-session i o local-identity validate-peer-identity
			   #:certificates local-certificates))
