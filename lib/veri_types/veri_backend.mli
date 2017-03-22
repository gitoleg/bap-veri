open Core_kernel.Std
open Bap_future.Std

type info = Veri_exec.Info.t

type run = string -> info stream -> unit future -> unit

val register : string -> ?on_exit:(unit -> unit) -> run -> unit
val registered : unit -> string list

val run : string -> info stream -> unit future -> unit
val on_exit : unit -> unit
