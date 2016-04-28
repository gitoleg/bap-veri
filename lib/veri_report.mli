open Core_kernel.Std
open Bap.Std
open Bap_traces.Std
open Regular.Std

open Veri_policy

type t [@@deriving bin_io, sexp]
type call = (rule * matched) list  [@@deriving bin_io, sexp]
type bind = string * call list  [@@deriving bin_io, sexp]

val create: unit -> t
val update: t -> string -> call -> t
val binds : t -> bind list
val notify: t -> Veri_error.t -> t
val errors: t -> Veri_error.t list

include Regular with type t := t

