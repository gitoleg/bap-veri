open Core_kernel.Std
open Bap.Std
open Bap_traces.Std
open Regular.Std

type event = Trace.event [@@deriving bin_io, compare, sexp]
type matched = Veri_policy.matched [@@deriving bin_io, compare, sexp]
type rule = Veri_rule.t [@@deriving bin_io, compare, sexp]

type t [@@deriving bin_io, sexp]
include Regular.S with type t := t

val create :
  bil:Bap.Std.bil ->
  insn:string ->
  code:string ->
  left:event list ->
  right:event list ->
  data:Veri_policy.result list -> t

val bil  : t -> bil
val code : t -> string
val insn : t -> string
val left : t -> Trace.event list
val right: t -> Trace.event list
val data : t -> (Veri_policy.rule * Veri_policy.matched) list
