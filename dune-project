(lang dune 3.0)
(name nullsec_classify)
(version 1.0.0)
(generate_opam_files true)
(license proprietary)
(authors "bad-antics")
(maintainers "bad-antics")
(homepage "https://github.com/bad-antics/nullsec-classify")
(bug_reports "https://github.com/bad-antics/nullsec-classify/issues")
(documentation "https://github.com/bad-antics/nullsec-classify")

(package
 (name nullsec_classify)
 (synopsis "Hardened Malware Classification Engine")
 (description "Type-safe malware classifier using OCaml's strong static typing, algebraic data types, and pattern matching")
 (depends
  (ocaml (>= 4.14))
  dune
  str
  unix))
