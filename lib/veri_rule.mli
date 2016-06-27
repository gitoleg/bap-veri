(** rule = ACTION : INSN : EVENT : EVENT  *)

open Core_kernel.Std
open Bap.Std
open Regular.Std

type t [@@deriving bin_io, compare, sexp]

include Regular with type t := t

type action [@@deriving bin_io, compare, sexp]

val action : t -> action
val skip : action
val deny : action

val create:
  ?insn:string -> ?left:string -> ?right:string -> action -> t Or_error.t

val is_empty_insn  : t -> bool
val is_empty_left  : t -> bool
val is_empty_right : t -> bool

val of_string_err : string -> t Or_error.t

module Match : sig

  type m = t -> string -> bool

  val insn  : m
  val both  : m
  val left  : m
  val right : m

end


