open Bap.Std
open Bap_traces.Std

type t
type event = Trace.event
type events = event list

module Action : sig
  type t
  val of_string: string -> t
  val is: t -> t -> bool
end

type action = Action.t 

module Rule : sig
  type t

  val create: 
    ?insn:string -> ?left:string -> ?right:string -> action -> t
end

type rule = Rule.t

val create : rule -> t

(** [match_events t insn_name events events'] *)
val match_events: 
  t -> string -> events -> events -> (event option * event option) list

val skip : action
val deny : action

