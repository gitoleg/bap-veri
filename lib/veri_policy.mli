open Core_kernel.Std
open Bap.Std
open Bap_traces.Std

(** rule = ACTION : INSN : EVENT : EVENT  *)
type rule
type t = rule list
type event = Trace.event
type events = Value.Set.t
type action

type matched =
  | Left of event
  | Right of event
  | Both of event * event

val skip : action
val deny : action
val pp_rule: Format.formatter -> rule -> unit

val make_rule:
  ?insn:string -> ?left:string -> ?right:string -> action -> rule

val match_events: rule -> string -> events -> events -> matched list

val denied: t -> string -> events -> events -> (rule * matched list) list
