#lang racket/base

(require racket/system)
(require racket/file)
(require dynext/file)
(require dynext/link)

(require (only-in srfi/13 string-suffix-ci?))

(provide pre-installer)

(define NACLVERSION "20110221")
(define NACLUNPACKED (string-append "nacl-"NACLVERSION))

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
	(system (string-append "python import.py "NACLUNPACKED))
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
