open Core_kernel.Std

type kind = [
  | `Disasm_error (** error with disassembling                     *)
  | `Unsound_sema (** instruction execution mismatches with trace  *)
  | `Unknown_sema (** instruction semantic is unknown for lifter   *)
] [@@deriving bin_io, compare, sexp]

type attr = [
  | `Name of string
  | `Diff of Veri_policy.result list
] [@@deriving bin_io, compare, sexp]

type t = kind * Error.t * attr list
[@@deriving bin_io, compare, sexp]
