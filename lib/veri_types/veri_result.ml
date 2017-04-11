open Core_kernel.Std
open Bap.Std

type sema_error = [
  | `Unsound_sema (** instruction execution mismatches with trace  *)
  | `Unknown_sema (** instruction semantic is unknown for lifter   *)
] [@@deriving bin_io, compare, sexp]

type error_kind = [
  | `Disasm_error (** error with disassembling                     *)
  | sema_error
] [@@deriving bin_io, compare, sexp]

type kind = [ `Success | error_kind ] [@@deriving bin_io, compare, sexp]
type error = error_kind * Error.t [@@deriving bin_io, compare, sexp]

module Error = struct
  type t = error [@@deriving bin_io, compare, sexp]
  let pp fmt (kind, er) =
    Format.fprintf fmt "%s:%s\n"
      (Sexp.to_string (sexp_of_error_kind kind))
      (Error.to_string_hum er)
end
