(**

           info                                dynamic_data
 +-------------------+                    +-----------------------+
 | * Id       : Int  |<---+               | * Id_task      : Int  |<--+
 |-------------------|    |               | * Id_insn      : Int  |<--|
 |   Kind     : Text |    |               |-----------------------|   |
 |   Name     : Text |    |               |   Successful   : Int  |   |
 |   Date     : Text |    |               |   Undisasmed   : Int  |   |
 |   Bap      : Text |    |               |   Unsound_sema : Int  |   |
 |   Arch     : Text |    |               |   Unknown_sema : Int  |   |
 |   Comp_ops : Text |    |               +-----------------------+   |
 +-------------------+    |                                           |
                          |                                           |
                          |       task               task_insn        |             insn_place
                          |  +------------+     +-----------------+   |        +-----------------+
                          +-<| * Id : Int |>-->>| * Id_task : Int |>--|------->| * Id_task : Int |
                          |  +------------+  +<<| * Id_insn : Int |>--+------->| * Id_insn : Int |
      dynamic_info        |                  |  +-----------------+            | * Pos     : Int |
 +-------------------+    |                  |                                 |-----------------|
 | * Id       : Int  |<---+                  |                                 |   Addr    : Int |
 |-------------------|    |                  |         insn                    +-----------------+
 |   Obj_ops  : Text |    |                  |  +-----------------+
 |   Policy   : Text |    |                  +->| * Id     : Int  |
 +-------------------+    |                     |-----------------|
                          |                     |   Bytes  : Text |
       bin_info           |                     |   Name   : Text |
 +------------------+     |                     |   Asm    : Text |
 | * Id_task : Int  |<----+                     |   Bil    : Text |
 | * Id      : Int  |                           +-----------------+
 |------------------|
 | Min_addr  : Int  |
 | Max_addr  : Int  |
 +------------------+

*)

open Core_kernel.Std
open Bap.Std
open Bap_traces.Std
open Veri.Std

type kind = [ `Trace | `Static ]
type task
type t = task
type insn_id

val create : string -> kind -> t Or_error.t
val write : t -> [ `Start | `End ] -> unit Or_error.t
val write_stat : t -> unit Or_error.t

(** [add_info t task_id kind arch name] *)
val add_info : t -> ?comp_ops:string -> arch -> string -> unit Or_error.t

(** [add_dyn_info t task_id rules]  *)
val add_dyn_info : task -> ?obj_ops:string -> Rule.t list -> unit Or_error.t

(** [add_insn t bytes addr insn]  *)
val add_insn : t -> string -> Insn.t option -> (t * insn_id) Or_error.t

(** [add_insn t bytes addr index]  *)
val add_insn_place : t -> insn_id -> addr -> int -> unit Or_error.t

(** [add_insn_dyn t  insn_id result]  *)
val add_insn_dyn : task -> insn_id -> Result.error option -> t Or_error.t

(** [add_exec_info t ranges]  *)
val add_exec_info : task -> (addr * addr) list -> unit Or_error.t

val close : t -> unit
