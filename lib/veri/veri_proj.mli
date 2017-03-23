open Core_kernel.Std
open Bap.Std
open Bap_future.Std
open Veri_types.Std

type t
type proj = t

module Backend : sig
  type info = Veri_exec.Info.t
  type run = proj -> unit

  val register : ?on_exit:(unit -> unit) -> run -> unit
  val on_exit : unit -> unit
end

val create : ?backend:string -> Uri.t -> Veri_rule.t list -> t Or_error.t
val run : t -> unit Or_error.t

val uri   : t -> Uri.t
val meta  : t -> dict
val info  : t -> Veri_exec.Info.t stream * unit Future.t
val rules : t -> Veri_rule.t list
