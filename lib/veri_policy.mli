open Core_kernel.Std
open Bap.Std
open Bap_traces.Std
open Regular.Std

type event = Trace.event
type events = Value.Set.t

(** rule = ACTION : INSN : EVENT : EVENT  *)
module Rule : sig

  type t [@@deriving bin_io, sexp]
  type action [@@deriving bin_io, sexp]

  val skip : action
  val deny : action

  val create:
    ?insn:string -> ?left:string -> ?right:string -> action -> t

  include Regular with type t := t
end

type matched =
  | Left of event
  | Right of event
  | Both of event * event
[@@deriving bin_io, sexp]

type rule = Rule.t [@@deriving bin_io, sexp]
type t 

val empty : t
val add : t -> rule -> t
val match_events: rule -> string -> events -> events -> matched list
val denied: t -> string -> events -> events -> (rule * matched list)  list
