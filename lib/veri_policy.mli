open Bap.Std
open Bap_traces.Std

type t
type event = Trace.event
type events = event list
type action

val skip : action
val deny : action

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


