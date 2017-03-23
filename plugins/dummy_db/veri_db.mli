(**

           info                                dynamic_data
 +-------------------+                    +-----------------------+
 | * Task_id  : Int  |<---+               | * Id_task      : Int  |<--+
 |-------------------|    |               | * Id_insn      : Int  |<--|
 |   Kind     : Text |    |               |-----------------------|   |
 |   Name     : Text |    |               |   Indexes      : Text |   |
 |   Date     : Text |    |               |   Successful   : Int  |   |
 |   Bap      : Text |    |               |   Undisasmed   : Int  |   |
 |   Arch     : Text |    |               |   Unsound_sema : Int  |   |
 |   Comp_ops : Text |    |               |   Unknown_sema : Int  |   |
 |   Extra    : Text |    |               +-----------------------+   |
 +-------------------+    |                                           |
                          |       task               task_insn        |
                          |  +------------+     +-----------------+   |
                          +-<| * Id : Int |>-->>| * Task_id : Int |>--|
                          |  |------------|  +<<| * Insn_id : Int |>--+
      dynamic_info        |  | Name : Text|  |  +-----------------+
 +-------------------+    |  +------------+  |
 | * Task_id  : Int  |<---+                  |
 |-------------------|                       |         insn
 |   Obj_ops  : Text |                       |  +-----------------+
 |   Policy   : Text |                       +->| * Id     : Int  |
 +-------------------+                          |-----------------|
                                                |   Bytes  : Text |
                                                |   Name   : Text |
                                                |   Asm    : Text |
                                                |   Bil    : Text |
                                                +-----------------+
*)

open Core_kernel.Std
open Bap.Std
open Bap_traces.Std
open Veri.Std

type t
type task_id
type kind = [`Static | `Trace] [@@deriving sexp]

val open_db : string -> t Or_error.t
val close_db : t -> unit
val write : t -> unit Or_error.t

val add_task : t -> string -> task_id Or_error.t

(** [add_info t task_id kind arch name] *)
val add_info : t -> task_id -> ?comp_ops:string -> kind -> arch -> string -> t

(** [add_dyn_info db task_id rules]  *)
val add_dyn_info : t -> task_id -> ?obj_ops:string -> Rule.t list -> t

(** [add_insns db task_id insns], where insn = addr * bytes * insn *)
val add_trace_insns : t -> task_id -> (addr * string * insn) seq -> t

val add_static_insn : t -> task_id -> (addr * string * insn) seq -> (addr * addr) list -> t

(** [update_with_trace trace rules numbers db] - saves
    results in SQLite with name [db] *)
(* val update_with_trace : *)
(*   ?compiler_ops:string list -> *)
(*   ?object_ops:string list -> *)
(*   ?extra:string -> *)
(*   ?trace_name:string -> *)
(*   Trace.t -> *)
(*   Veri_rule.t list -> *)
(*   Veri_numbers.t -> *)
(*   string -> unit Or_error.t *)

(** [update_with_static arch ~name mems insns db]  *)
val update_with_static :
  ?compiler_ops:string list ->
  ?extra:string ->
  name:string ->
  arch ->
  (addr * addr) list ->
  (mem * insn) seq ->
  string -> unit Or_error.t
