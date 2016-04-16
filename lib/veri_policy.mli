open Bap.Std
open Bap_traces.Std

module Rule : sig
  type action
  type t
  
  val create: 
    ?insn:string -> ?left:string -> ?right:string -> action -> t

  val skip : action
  val deny : action
  val is_deny: t -> bool
  val is_skip: t -> bool
end

type t
type event = Trace.event
type rule = Rule.t

val create : rule -> t

(** [match_events t insn_name events events'] *)
val match_events: 
  t -> string -> event list -> event list -> (event option * event option) list


