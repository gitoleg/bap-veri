open Core_kernel.Std
open Bap.Std
open Bap_future.Std
open Veri_types.Std

type t
type proj = t

module Backend : sig
  type info = Veri_exec.Info.t
  type run = proj -> info stream -> unit future -> unit

  val register : string -> ?on_exit:(unit -> unit) -> run -> unit
  val registered : unit -> string list
  val on_exit : unit -> unit
end

val create : ?backend:string -> Uri.t -> Veri_rule.t list -> t Or_error.t
val run : t -> unit Or_error.t

val meta : t -> dict
val uri : t -> Uri.t
val rules : t -> Veri_rule.t list
