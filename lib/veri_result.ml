open Core_kernel.Std

type error_kind = [
  | `Disasm_error (** error with disassembling                     *)
  | `Unsound_sema (** instruction execution mismatches with trace  *)
  | `Unknown_sema (** instruction semantic is unknown for lifter   *)
] [@@deriving bin_io, compare, sexp]

type success = [ `Success ]
[@@deriving bin_io, compare, sexp]

type result_kind = [ success | error_kind ]
[@@deriving bin_io, compare, sexp]

type attr = [
  | `Name of string
  | `Diff of Veri_policy.result list
] [@@deriving bin_io, compare, sexp]

type error_info = Error.t * attr list
[@@deriving bin_io, compare, sexp]

type error = error_kind * error_info
[@@deriving bin_io, compare, sexp]

type t = [ success | `Error of error]
[@@deriving bin_io, compare, sexp]
