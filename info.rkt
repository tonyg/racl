#lang setup/infotab

(define name "racl")
(define blurb
  (list
   `(p "Racket bindings for "
       (a ((href "http://nacl.cr.yp.to/")) "NaCl")
       ", a cryptographic library.")))
(define homepage "https://github.com/tonyg/racl")
(define primary-file "main.rkt")
(define categories '(misc))
(define repositories '("4.x"))

(define pre-install-collection "private/install.rkt")
(define compile-omit-files '("private/install.rkt"))

(define deps '("srfi-lite-lib"
               "base" "dynext-lib" "sandbox-lib" "rackunit-lib"))

(define scribblings '(("scribblings/racl.scrbl" ())))
