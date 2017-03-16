(**

           info                                dynamic_data
 +-------------------+                    +-----------------------+
 | * Task_id  : Int  |<---+               | * Id_task      : Int  |<<-+
 |-------------------|    |               | * Id_insn      : Int  |<<-|
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
                          |  |------------|  +-<| * Insn_id : Int |>--+
      dynamic_info        |  | Name : Text|  |  +-----------------+
 +-------------------+    |  +------------+  |
 | * Task_id  : Int  |<---+                  |
 |-------------------|                       |         insn
 |   Obj_ops  : Text |                       |  +-----------------+
 |   Policy   : Text |                       +>>| * Id     : Int  |
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


(** [update_with_trace trace rules numbers db] - saves
    results in SQLite with name [db] *)
val update_with_trace :
  ?compiler_ops:string list ->
  ?object_ops:string list ->
  ?extra:string ->
  ?trace_name:string ->
  Trace.t ->
  Veri_rule.t list ->
  Veri_numbers.t ->
  string -> unit Or_error.t

(** [update_with_static arch ~name mems insns db]  *)
val update_with_static :
  ?compiler_ops:string list ->
  ?extra:string ->
  name:string ->
  arch ->
  (addr * addr) list ->
  (mem * insn) seq ->
  string -> unit Or_error.t
