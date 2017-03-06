open Core_kernel.Std
open Bap.Std
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

type kind = [
  | success
  | error_kind
] [@@deriving bin_io, compare, sexp]

type t = {
  kind : kind;
  dict : dict;
} [@@deriving bin_io, compare, sexp]

let bytes = Value.Tag.register ~name:"bytes"
    ~uuid:"26e4bf85-5b1c-4bf9-98ab-32428c9e66e7"
    (module String)

let error = Value.Tag.register ~name:"error"
    ~uuid:"802dc20b-9a98-4998-9a57-48ab9ff291bb"
    (module Error)

let insn = Value.Tag.register ~name:"instruction"
    ~uuid:"fd176d5c-9402-4d6d-849a-50a09c44b13b"
    (module Insn)

type diff = Veri_policy.result list [@@deriving bin_io, compare, sexp]
type events = Trace.event list [@@deriving bin_io, compare, sexp]

module Diff = struct
  type t = diff [@@deriving bin_io, compare, sexp]
  let ppr fmt (r, m) =
    Format.fprintf fmt "%a:%a\n" Veri_rule.pp r
      Veri_policy.Matched.pp m
  let pp fmt rs = List.iter ~f:(ppr fmt) rs
end

module Events = struct
  type t = events [@@deriving bin_io, compare, sexp]
  let pp fmt rs = List.iter ~f:(Value.pp fmt) rs
end

let diff = Value.Tag.register ~name:"diff"
    ~uuid:"dc14589f-2fe5-40e9-8a47-b0961d96b827"
    (module Diff)

let real = Value.Tag.register ~name:"real"
    ~uuid:"8f7e3b18-70bd-4c03-885a-da975782b03d"
    (module Events)

let ours = Value.Tag.register ~name:"ours"
    ~uuid:"e3fa1d96-40fb-464d-bad0-da4b82271991"
    (module Events)
