#lang racket/base

(require (only-in racket/port with-output-to-bytes with-input-from-bytes))

(provide (struct-out display-hint)
	 write-spki-sexp
	 read-spki-sexp
	 spki-sexp->bytes
	 bytes->spki-sexp
	 spki-sexp-digit-limit
	 spki-sexp-bytes-limit
	 spki-sexp-list-limit)

(define spki-sexp-digit-limit (make-parameter 10))
(define spki-sexp-bytes-limit (make-parameter #f))
(define spki-sexp-list-limit (make-parameter #f))

(struct display-hint (hint body) #:prefab)

(define (write-spki-sexp x [p (current-output-port)])
  (define (wb bs)
    (display (bytes-length bs) p)
    (display #\: p)
    (display bs p))
  (let w ((x x))
    (cond
     ((bytes? x)
      (wb x))
     ((list? x)
      (display #\( p)
      (for-each w x)
      (display #\) p))
     ((display-hint? x)
      (when (or (not (bytes? (display-hint-hint x)))
		(not (bytes? (display-hint-body x))))
	(error 'write-spki-sexp "Bad SPKI SEXP display-hint ~v" x))
      (display #\[ p)
      (wb (display-hint-hint x))
      (display #\] p)
      (wb (display-hint-body x)))
     (else (error 'write-spki-sexp "Bad SPKI SEXP ~v" x)))))

(define (read-simple-string buffer p)
  (let loop ((buffer buffer) (digit-count (length buffer)))
    (define b (read-byte p))
    (if (eof-object? b)
	b
	(let ((c (integer->char b)))
	  (cond
	   ((eqv? c #\:)
	    (define len (string->number (list->string (reverse buffer))))
	    (when (and (spki-sexp-bytes-limit) (> len (spki-sexp-bytes-limit)))
	      (error 'read-spki-sexp "Input rejected: byte string length ~v exceeds limit ~v"
		     len
		     (spki-sexp-bytes-limit)))
	    (define bs (read-bytes len p))
            (cond
	     ((eof-object? bs) bs)
	     ((< (bytes-length bs) len) eof)
	     (else bs)))
	   ((char-numeric? c)
	    (define new-count (+ digit-count 1))
	    (when (> new-count (spki-sexp-digit-limit))
	      (error 'read-spki-sexp "Input rejected: byte string length has more than ~v digits"
		     (spki-sexp-digit-limit)))
	    (loop (cons c buffer) new-count))
	   (else
	    (error 'read-spki-sexp "Syntax error: bad simple string length ~v" c)))))))

(define (read-sexp-list p)
  (define limit (spki-sexp-list-limit))
  (let loop ((len 0) (acc '()))
    (when (and limit (> len limit))
      (error 'read-spki-sexp "Input rejected: list length exceeds limit ~v" limit))
    (let ((v (read-sexp-inner p)))
      (cond
       ((eof-object? v) v)
       ((eq? v 'end-of-list-marker) (reverse acc))
       (else (loop (+ len 1) (cons v acc)))))))

(define (read-sexp-inner p)
  (let ((b (read-byte p)))
    (if (eof-object? b)
	b
	(let ((c (integer->char b)))
	  (cond
	   ((eqv? c #\() (read-sexp-list p))
	   ((eqv? c #\)) 'end-of-list-marker)
	   ((eqv? c #\[)
	    (let ((hint (read-simple-string '() p)))
	      (define closeparen-byte (read-byte p))
	      (cond
	       ((eof-object? closeparen-byte) closeparen-byte)
	       ((not (eqv? closeparen-byte (char->integer #\])))
		(error 'read-spki-sexp "Syntax error: display-hint"))
	       (else
		(define body (read-simple-string '() p))
		(if (eof-object? body)
		    body
		    (display-hint hint body))))))
	   ((char-numeric? c) (read-simple-string (list c) p))
	   ((char-whitespace? c) (read-sexp-inner p)) ;; convenience for testing
	   (else (error 'read-spki-sexp "Syntax error: bad character ~v" c)))))))

(define (read-spki-sexp [p (current-input-port)])
  (let ((v (read-sexp-inner p)))
    (if (eq? v 'end-of-list-marker)
	(error 'read-spki-sexp "Syntax error: unexpected end-of-list")
	v)))

(define (spki-sexp->bytes s) (with-output-to-bytes (lambda () (write-spki-sexp s))))
(define (bytes->spki-sexp bs) (with-input-from-bytes bs read-spki-sexp))

(module+ test
  (require rackunit)
  (require (only-in racket/port with-output-to-string with-input-from-string))
  (define (R s) (bytes->spki-sexp (string->bytes/utf-8 s)))
  (define (W t) (bytes->string/utf-8 (spki-sexp->bytes t)))
  (check-equal? (R "") eof)
  (check-equal? (R "(") eof)
  (check-equal? (R "()") '())
  (check-exn #px"Syntax error: unexpected end-of-list" (lambda () (R ")")))
  (check-equal? (R "[") eof)
  (check-exn #px"Syntax error: bad character #\\\\\\]" (lambda () (R "]"))) ;; lolregex
  (check-exn #px"Syntax error: bad simple string length #\\\\\\]" (lambda () (R "[]")))
  (check-equal? (R "0") eof)
  (check-equal? (R "01") eof)
  (check-equal? (R "012:abcdefabcdef") #"abcdefabcdef")
  (check-equal? (R "0000000012:abcdefabcdef") #"abcdefabcdef")
  (check-exn #px"Input rejected: byte string length has more than 10 digits"
	     (lambda () (R "00000000012:abcdefabcdef")))
  (check-exn #px"Input rejected: byte string length 12 exceeds limit 4"
	     (lambda ()
	       (parameterize ((spki-sexp-bytes-limit 4))
		 (R "12:abcdefabcdef"))))
  (check-equal? (R "4:") eof)
  (check-equal? (R "4:ab") eof)
  (check-exn #px"read-spki-sexp: Syntax error: bad simple string length #\\\\q" (lambda () (R "1q")))
  (check-equal? (R "(()(") eof)
  (check-equal? (R "(()())") '(()()))
  (check-equal? (R "0:") #"")
  (check-equal? (R "[1:a]1:b") (display-hint #"a" #"b"))
  (check-exn #px"Syntax error: display-hint" (lambda () (R "[1:]1:b")))
  (check-equal? (R "[1") eof)
  (check-equal? (R "[1:") eof)
  (check-equal? (R "[1:a") eof)
  (check-equal? (R "[1:a]") eof)
  (check-equal? (R "[1:a]1") eof)
  (check-equal? (R "[1:a]1:") eof)
  (check-equal? (R "(1:a1:b1:c)") (list #"a" #"b" #"c"))
  (check-equal? (R "(1:a 1:b 1:c)") (list #"a" #"b" #"c"))
  (check-equal? (R "  (  1:a 1:b 1:c  )  ") (list #"a" #"b" #"c"))
  (check-equal? (R "(1:a((1:b))1:c)") (list #"a" (list (list #"b")) #"c"))
  (check-exn #px"Syntax error: bad simple string length #\\\\\\(" (lambda () (R "[1:a]()")))
  (check-exn #px"Syntax error: bad simple string length #\\\\\\(" (lambda () (R "[1:a](1:b)")))

  (check-equal? (W #"") "0:")
  (check-equal? (W #"abc") "3:abc")
  (check-equal? (W '()) "()")
  (check-equal? (W '(#"")) "(0:)")
  (check-equal? (W '(#"a" #"b" #"c")) "(1:a1:b1:c)")
  (check-equal? (W '(#"a" ((#"b")) #"c")) "(1:a((1:b))1:c)")
  (check-equal? (W '(()())) "(()())")
  (check-equal? (W (display-hint #"a" #"b")) "[1:a]1:b")
  (check-exn #px"Bad SPKI SEXP display-hint '#s\\(display-hint #\"a\" \\(\\)\\)"
	     (lambda () (W (display-hint #"a" '()))))
  (check-exn #px"Bad SPKI SEXP display-hint '#s\\(display-hint #\"a\" \\(#\"b\"\\)\\)"
	     (lambda () (W (display-hint #"a" '(#"b")))))

  (check-exn #px"Bad SPKI SEXP 'x" (lambda () (W 'x)))
  (check-exn #px"Bad SPKI SEXP 123" (lambda () (W 123)))

  (check-equal? (R "(0:0:0:0:)") (list #"" #"" #"" #""))
  (check-equal? (parameterize ((spki-sexp-list-limit 6))
		  (R "(0:0:0:0:)"))
		(list #"" #"" #"" #""))
  (check-exn #px"Input rejected: list length exceeds limit 2"
	     (lambda ()
	       (parameterize ((spki-sexp-list-limit 2))
		 (R "(0:0:0:0:)"))))
  )
