#lang racket/base
;; Loads the dynamic library.

(require ffi/unsafe)
(require ffi/unsafe/define)
(require setup/dirs)

(provide nacl-lib
	 define-nacl

	 make-zero-bytes
	 zero-pad-left
	 check-result
	 check-length
	 check-nonce)

;;---------------------------------------------------------------------------
;; FFI

(define (local-lib-dirs)
  (list* "."
	 (with-handlers ((exn:fail? (lambda (e) ".")))
	   (collection-path "racl"))
	 (get-lib-search-dirs)))

(define nacl-lib (ffi-lib "nacl" #:get-lib-dirs local-lib-dirs))

(define-ffi-definer define-nacl nacl-lib
  #:default-make-fail make-not-available)

;;---------------------------------------------------------------------------
;; Utilities

(define (make-zero-bytes n)
  (make-bytes n 0))

(define (zero-pad-left bs padding-length)
  (define new-bs (make-zero-bytes (+ (bytes-length bs) padding-length)))
  (bytes-copy! new-bs padding-length bs)
  new-bs)

(define-syntax-rule (check-result (f arg ...))
  (when (not (zero? (f arg ...)))
    (error 'f "error from nacl primitive")))

(define (check-length f what thing expected-length)
  (when (not (= (bytes-length thing) expected-length))
    (error f "expected ~a of length ~v, got length ~v" what expected-length (bytes-length thing))))

(define (check-nonce f n expected-length)
  (check-length f "nonce" n expected-length))
