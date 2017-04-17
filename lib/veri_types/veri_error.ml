open Core_kernel.Std
open Bap.Std

type kind = [
  | `Unsound_sema (** instruction execution mismatches with trace  *)
  | `Unknown_sema (** instruction semantic is unknown for lifter   *)
  | `Disasm_error (** error with disassembling                     *)
] [@@deriving bin_io, compare, sexp]

type t = kind * Error.t [@@deriving bin_io, compare, sexp]
type error = t [@@deriving bin_io, compare, sexp]


let pp fmt (kind, er) =
  Format.fprintf fmt "%s:%s\n"
    (Sexp.to_string (sexp_of_kind kind))
    (Error.to_string_hum er)
