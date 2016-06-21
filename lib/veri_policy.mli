open Core_kernel.Std
open Bap.Std
open Bap_traces.Std
open Regular.Std

type event = Trace.event
type events = Value.Set.t

module Field : sig
  type t [@@deriving bin_io, compare, sexp] 
  
  val of_string: string -> t
  val any: t
  val empty: t
end

type field = Field.t [@@deriving bin_io, compare, sexp]

(** rule = ACTION : INSN : EVENT : EVENT  *)
module Rule : sig

  type t [@@deriving bin_io, sexp]
  type action [@@deriving bin_io, sexp]

  val skip : action
  val deny : action

  val create:
    ?insn:string -> ?left:string -> ?right:string -> action -> t

  val create':
    insn:field -> ?left:field -> ?right:field -> action -> t
    
  val insn  : t -> string
  val left  : t -> string
  val right : t -> string

  include Regular with type t := t
end

module Matched : sig
  type t = event list * event list [@@deriving bin_io, compare, sexp]
  include Regular with type t := t
end

type matched = Matched.t [@@deriving bin_io, compare, sexp]
type rule = Rule.t [@@deriving bin_io, compare, sexp]
type t 

val empty : t
val add : t -> rule -> t
val match_events: rule -> string -> events -> events -> matched option
val denied: t -> string -> events -> events -> (rule * matched) list
