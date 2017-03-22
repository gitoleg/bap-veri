open Core_kernel.Std
open Bap_future.Std


type info = Veri_exec.Info.t

module type S = sig
  val run : string -> info stream -> unit future -> unit
  val on_exit : unit -> unit
end


val register : string -> (module S) -> unit
val registered : string list

val call : string -> info stream -> unit future -> unit
val on_exit : unit -> unit
