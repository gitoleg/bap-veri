open Core_kernel.Std
open Bap.Std
open Bap_traces.Std
open Regular.Std

open Veri_policy
module Rules = Rule.Map

type t [@@deriving bin_io, sexp]
type frame = matched list Rules.t [@@deriving bin_io, sexp]

val create: unit -> t
val update: t -> string -> rule -> matched -> t
val frames: t -> (string * frame) list
val notify: t -> Veri_error.t -> t
val errors: t -> Veri_error.t list

include Regular with type t := t

