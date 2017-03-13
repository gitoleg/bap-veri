open Core_kernel.Std
open Bap.Std
open Regular.Std
open Bap_traces.Std

type sema_error = [
  | `Unsound_sema (** instruction execution mismatches with trace  *)
  | `Unknown_sema (** instruction semantic is unknown for lifter   *)
] [@@deriving bin_io, compare, sexp]

type error_kind = [
  | `Disasm_error (** error with disassembling                     *)
  | sema_error
] [@@deriving bin_io, compare, sexp]

type success = [ `Success ] [@@deriving bin_io, compare, sexp]

module Kind : sig
  type t =  [
    | success
    | error_kind
  ] [@@deriving bin_io, compare, sexp]

  include Regular.S with type t := t
end

type kind = Kind.t  [@@deriving bin_io, compare, sexp]

type t = {
  kind : kind;
  dict : dict;
} [@@deriving bin_io, compare, sexp]

include Regular.S with type t := t

type diff = Veri_policy.result list [@@deriving bin_io, compare, sexp]
type events = Trace.event list [@@deriving bin_io, compare, sexp]

val bytes : string tag
val error : Error.t tag
val insn  : Insn.t tag
val diff  : diff tag
val real  : events tag
val ours  : events tag
