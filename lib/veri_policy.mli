open Core_kernel.Std
open Bap.Std
open Bap_traces.Std

(** rule = ACTION : INSN : EVENT : EVENT  *)

type t
type event = Trace.event
type events = Value.Set.t
type action

val skip : action
val deny : action

val create:
  ?insn:string -> ?left:string -> ?right:string -> action -> t

val match_events: t -> string -> events -> events -> 
  (event option * event option) list

(** type [deny_error] list all events that matches to deny rule *)
type deny_error = events * events

type r = (events * events, deny_error) Result.t

(** [process t insn events events] - returns 
    either successful filtered events, either
    events that was denied *)
val process: t -> string -> events -> events -> r
