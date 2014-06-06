#lang racket/base
;; Loads the dynamic library.

(require ffi/unsafe)
(require ffi/unsafe/define)
(require setup/dirs)

(provide nacl-lib
	 define-nacl

	 (struct-out exn:fail:contract:racl)
	 make-zero-bytes
	 zero-pad-left
	 check-result
	 check-length
	 check-nonce)

;;---------------------------------------------------------------------------
;; FFI

(define (local-lib-dirs)
  (list (build-path (collection-path "racl")
		    "private"
		    "compiled"
		    "native"
		    (system-library-subpath))))

(define nacl-lib (ffi-lib "racl-nacl" #:get-lib-dirs local-lib-dirs))

(define-ffi-definer define-nacl nacl-lib
  #:default-make-fail make-not-available)

;;---------------------------------------------------------------------------
;; Utilities

(struct exn:fail:contract:racl exn:fail:contract () #:transparent)

(define (make-zero-bytes n)
  (make-bytes n 0))

(define (zero-pad-left bs padding-length)
  (define new-bs (make-zero-bytes (+ (bytes-length bs) padding-length)))
  (bytes-copy! new-bs padding-length bs)
  new-bs)

(define-syntax-rule (check-result (f arg ...))
  (when (not (zero? (f arg ...)))
    (raise (exn:fail:contract:racl (format "~a: error from nacl primitive" 'f)
				   (current-continuation-marks)))))

(define (check-length f what thing expected-length)
  (when (not (= (bytes-length thing) expected-length))
    (raise (exn:fail:contract:racl (format "~a: expected ~a of length ~v, got length ~v"
					   f what expected-length (bytes-length thing))
				   (current-continuation-marks)))))

(define (check-nonce f n expected-length)
  (check-length f "nonce" n expected-length))
