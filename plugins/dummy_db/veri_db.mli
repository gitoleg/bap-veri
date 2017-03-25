(**

           info                                dynamic_data
 +-------------------+                    +-----------------------+
 | * Id_task  : Int  |<---+               | * Id_task      : Int  |<--+
 |-------------------|    |               | * Id_insn      : Int  |<--|
 |   Kind     : Text |    |               |-----------------------|   |
 |   Name     : Text |    |               |   Indexes      : Text |   |
 |   Date     : Text |    |               |   Successful   : Int  |   |
 |   Bap      : Text |    |               |   Undisasmed   : Int  |   |
 |   Arch     : Text |    |               |   Unsound_sema : Int  |   |
 |   Comp_ops : Text |    |               |   Unknown_sema : Int  |   |
 +-------------------+    |               +-----------------------+   |
                          |                                           |
                          |       task               task_insn        |             insn_place
                          |  +------------+     +-----------------+   |        +-----------------+
                          +-<| * Id : Int |>-->>| * Id_task : Int |>--|------->| * Id_task : Int |
                          |  +------------+  +<<| * Id_insn : Int |>--+------->| * Id_insn : Int |
      dynamic_info        |                  |  +-----------------+            | * Index   : Int |
 +-------------------+    |                  |                                 |-----------------|
 | * Id_task  : Int  |<---+                  |                                 |   Addr    : Int |
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

type kind = [`Static | `Trace] [@@deriving sexp]
type 'a task
type t = kind task
type trace_task = [`Trace] task
type static_task = [`Static] task
type insn_id

val create : string -> kind -> t Or_error.t
val write : t -> t Or_error.t

(** [add_info t task_id kind arch name] *)
val add_info : t -> ?comp_ops:string -> arch -> string -> t

(** [add_dyn_info t task_id rules]  *)
val add_dyn_info : trace_task -> ?obj_ops:string -> Rule.t list -> trace_task

(** [add_insn t bytes addr insn]  *)
val add_insn : t -> string -> Insn.t option -> t * insn_id

(** [add_insn t bytes addr index]  *)
val add_insn_place : t -> insn_id -> addr -> int -> t

(** [add_insn_dyn t  insn_id result]  *)
val add_insn_dyn : trace_task -> insn_id -> Result.error option -> trace_task

(** [add_exec_info t ranges]  *)
val add_exec_info : static_task -> (addr * addr) list -> static_task
