open Core_kernel.Std
open Bap.Std
open Bap_traces.Std

(** rule = ACTION : INSN : EVENT : EVENT  *)

type t
type event = Trace.event
type events = Value.Set.t
type set_pair = events * events
type action

val skip : action
val deny : action

val create:
  ?insn:string -> ?left:string -> ?right:string -> action -> t

val match_events: t -> string -> events -> events -> 
  (event option * event option) list

(** type [deny_error] list all events that matches to deny rule *)
type deny_error = set_pair

type r = (set_pair, deny_error) Result.t

(** [process t insn events events] - returns 
    either successful filtered events, either
    events that was denied *)
val process: t -> string -> events -> events -> r
