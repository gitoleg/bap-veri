(** rule = ACTION : INSN : EVENT : EVENT  *)

open Core_kernel.Std
open Bap.Std
open Regular.Std

type t [@@deriving bin_io, compare, sexp]
type action [@@deriving bin_io, compare, sexp]
type field
include Regular with type t := t

(** [create ~insn ~left ~right action] - returns a rule,
    if all of fields {insn, left, right} either contains 
    correct regular expression, either plain string, either
    are an empty strings. If some field is not given, it's 
    that an empty string fits well for this field. *)
val create:
  ?insn:string -> ?left:string -> ?right:string -> action -> t Or_error.t

(** [of_string_err str] - return a rule, if string contains exactly 4 string
    representation of fields:
    - action (with only two possible values: SKIP | DENY)
    - instruction name or correct regular expression
    - one of the following:
       correct regular expression for left part and empty string for right part;
       empty string for left part and correct regular expression for right part;
       correct regular expression for both left and right parts. *)
val of_string_err : string -> t Or_error.t

val skip : action
val deny : action

val action : t -> action
val insn   : t -> field
val left   : t -> field
val right  : t -> field

val is_empty : field -> bool

module Match : sig
  type m = t -> string -> bool
  val insn  : m
  val both  : m
  val left  : m
  val right : m
end
