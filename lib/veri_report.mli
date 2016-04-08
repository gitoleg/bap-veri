open Core_kernel.Std
open Bap.Std
open Bap_traces.Std
open Regular.Std

type t [@@deriving bin_io, sexp]

type events = Value.Set.t

(** events that occurred only on the left and only on the right *)
type frame_diff = events * events [@@deriving bin_io, compare, sexp]

val create: unit -> t
val update: t -> string -> frame_diff -> t
val frames: t -> (string * frame_diff list) list
val notify: t -> Veri_error.t -> t
val errors: t -> Veri_error.t list

include Regular with type t := t

