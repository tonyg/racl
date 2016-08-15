#lang racket/base

(require racket/system)
(require racket/file)
(require dynext/file)
(require dynext/link)
(require (only-in srfi/13 string-prefix? string-suffix-ci? string-contains))
(require (only-in racket/string string-trim string-replace))

(provide pre-installer)

(define NACLVERSION "20110221+Ed25519-20130419")
(define NACLUNPACKED (string-append "nacl-"NACLVERSION))

(define (build-subnacl unpacked-path subnacl-path)
  ;; Half-port, half-rewrite of Brian Warner's PyNaCl import.py script.
  (define include-path (build-path subnacl-path "include"))

  (make-directory* subnacl-path)
  (make-directory* include-path)

  (define (slurp relpath) (file->lines (build-path unpacked-path relpath)))

  (define MACROS (slurp "MACROS"))

  (define sexpdefs '())

  (define (push-sexpdef! str)
    (set! sexpdefs (cons str sexpdefs)))

  (define (with-output-to-include-file guard-def-name path thunk)
    (with-output-to-file (build-path include-path path)
      (lambda ()
	(printf "#ifndef ~a_H\n" guard-def-name)
	(printf "#define ~a_H\n" guard-def-name)
	(newline)
	(thunk)
	(newline)
	(displayln "#endif"))))

  (for ([op (slurp "OPERATIONS")])
    (when (not (string-prefix? "crypto_" op))
      (error 'build-subnacl "Operation from OPERATIONS doesn't start with \"crypto\": ~v" op))
    (define opname (substring op (string-length "crypto_")))
    (define opdir (build-path unpacked-path op))
    (define opmacros (filter (lambda (m) (or (string=? m op)
					     (string-prefix? (string-append op"_") m)))
			     MACROS))

    (for ([prim (map path->string (directory-list opdir))])
      (define primdir (build-path opdir prim))
      (define op_h (string-append op".h"))
      (define op_prim (string-append op"_"prim))
      (define op_prim_ (string-append op"_"prim"_"))
      (define op_prim_h (string-append op_prim".h"))

      (define (best-implementation)
	(define implementations (filter (lambda (impl)
					  (file-exists? (build-path primdir impl "api.h")))
					(map path->string (directory-list primdir))))
	(cond
	 [(member "ref" implementations) "ref"]
	 [(member "portable" implementations) "portable"]
	 [else (log-warning "Cannot find reference implementation of ~v/~v in ~v"
			    op prim implementations)
	       #f]))

      (define (copy-c-file source target)
	(display-lines-to-file
	 (for/list ([line (file->lines source)])
	   (if (string-prefix? "#include" (string-trim line))
	       (string-replace line op_h op_prim_h #:all? #t)
	       (for/fold ([line line]) ([m opmacros])
		 ;; From import.py: "when processing crypto_hash,
		 ;; replace crypto_hash() with crypto_hash_sha256()
		 ;; and crypto_hash_BYTES with
		 ;; crypto_hash_sha256_BYTES, but leave
		 ;; crypto_hashblocks_OTHER alone"
		 (string-replace line
				 (pregexp (string-append "\\b"m"\\b"))
				 (string-replace m op op_prim)))))
	 target))

      (define (copy-implementation preferred impldir targetdir)
	(for ([filename (directory-list impldir)])
	  (define source (build-path impldir filename))
	  (define target (build-path targetdir filename))
	  (when (directory-exists? source)
	    (error 'copy-implementation "Cannot handle subdirectories: ~v" source))
	  (if (string-suffix-ci? ".c" (path->string filename))
	      (copy-c-file source target)
	      (copy-file source target)))

	(with-output-to-include-file op_prim op_prim_h
	  (lambda ()
	    (for ([line (file->lines (build-path impldir "api.h"))])
	      (when (positive? (string-length (string-trim line)))
		(define new-line (string-replace line "CRYPTO_" op_prim_))
		(displayln new-line)
		(push-sexpdef! (string-append (string-trim (string-replace new-line
									   "#define"
									   "(define-constant"))
					      ")"))))

	    (for ([line (slurp "PROTOTYPES.c")]
		  #:when (or (string-contains line (string-append op"("))
			     (string-contains line (string-append op"_"))))
	      (displayln (string-replace line op op_prim)))

	    (printf "#define ~a_IMPLEMENTATION \"~a/~a/~a\"\n" op_prim op prim preferred)
	    (push-sexpdef! (format "(define-implementation ~a ~a ~s)" op prim preferred))
	    (printf "#define ~a_VERSION \"-\"\n" op_prim))))

      (define (build-generic-header)
	(with-output-to-include-file op op_h
	  (lambda ()
	    (printf "#include ~s\n" op_prim_h)
	    (newline)

	    (for [(m opmacros)]
	      (define m_prim (string-replace m op op_prim))
	      (printf "#define ~a ~a\n" m m_prim)
	      (push-sexpdef! (format "(define-alias ~a ~a)" m m_prim)))

	    (printf "#define ~a_PRIMITIVE ~s\n" op prim)
	    (printf "#define ~a_IMPLEMENTATION ~a_IMPLEMENTATION\n" op op_prim)
	    (printf "#define ~a_VERSION ~a_VERSION\n" op op_prim))))

      ;; From import.py we learn that nacl marks directories with
      ;; files to indicate their status. "used" indicates that a
      ;; directory is to be included in builds; "selected" means it is
      ;; a default.
      (when (file-exists? (build-path primdir "used"))
	;; It's not to be ignored.
	;; "api.h" files indicate implementation subdirectories.
	(define preferred (best-implementation))
	(when preferred
	  (displayln (list op prim preferred))

	  (define impldir (build-path primdir preferred))
	  (define targetdir (build-path subnacl-path (string-append opname"_"prim)))
	  (make-directory* targetdir)

	  (copy-implementation preferred impldir targetdir)
	  (when (file-exists? (build-path primdir "selected"))
	    (build-generic-header))
	  (push-sexpdef! "")))))

  (push-sexpdef! (format "(define-nacl-version ~s)"
			 (string-trim (file->string (build-path unpacked-path "version")))))
  (display-lines-to-file (reverse sexpdefs)
			 (build-path subnacl-path "sexpdefs"))

  (with-output-to-include-file "randombytes" "randombytes.h"
    (lambda ()
      (printf "extern void randombytes(unsigned char *, unsigned long long);\n")))

  (for* ([intkind '("uint" "int")]
	 [intsize '("32" "64")])
    (define T (string-append intkind intsize))
    (with-output-to-include-file (string-append "crypto_"T) (string-append "crypto_"T".h")
      (lambda ()
	(printf "#include <stdint.h>\n")
	(printf "typedef ~a_t crypto_~a;\n" T T))))

  (make-directory* (build-path subnacl-path "randombytes"))
  (copy-file (build-path unpacked-path "randombytes" "devurandom.c")
	     (build-path subnacl-path "randombytes" "devurandom.c")))

(define (pre-installer collections-top-path racl-path)
  (define private-path (build-path racl-path "private"))

  (parameterize ((current-directory private-path))
    (define unpacked-path (build-path private-path NACLUNPACKED))
    (define subnacl-path (build-path private-path "subnacl"))
    (define shared-object-target-path (build-path private-path
						  "compiled"
						  "native"
						  (system-library-subpath)))
    (define shared-object-target (build-path shared-object-target-path
					     (append-extension-suffix "racl-nacl")))

    (when (not (file-exists? shared-object-target))
      (when (not (directory-exists? subnacl-path))
	(when (not (directory-exists? unpacked-path))
	  ;; file/untgz didn't work on the .tar.gz I build from the
	  ;; distribution .tar.bz2, so I'm shelling out to tar instead.
	  (system (string-append "tar -jxf "NACLUNPACKED".tar.bz2")))
	(build-subnacl NACLUNPACKED subnacl-path)
	(delete-directory/files unpacked-path))

      (define c-sources
	(cons (build-path private-path "keys.c")
	      (find-files (lambda (p) (string-suffix-ci? ".c" (path->string p)))
			  subnacl-path)))

      (make-directory* shared-object-target-path)
      (parameterize ((current-extension-linker-flags
		      (append (current-extension-linker-flags)
			      (list "-O3" "-fomit-frame-pointer" "-funroll-loops"
				    "-I" "subnacl/include"))))
	(link-extension #f ;; not quiet
			c-sources
			shared-object-target)))))
