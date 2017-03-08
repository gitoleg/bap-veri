(**

         instruction                                total
    +--------------------+                   +--------------------+
    | Id_task : Int64    |<----+       +---->| Id_task : Int64    |
    | Id_insn : Int      |     |       |     |--------------------|
    |--------------------|     |       |     | Total        : Int |
    | Name : TEXT        |     |       |     | Successful   : Int |
    | Asm  : TEXT        |     |       |     | Unsound_sema : Int |
    | Successful   : Int |     |       |     | Unknown_sema : Int |
    | Unsound_sema : Int |     |       |     | Undisasmed   : Int |
    | Unknown_sema : Int |     |       |     +--------------------+
    +--------------------+     |       |
                               |       |
                               |       |
           task                |       |             env
    +--------------------+     |       |     +--------------------+
    | Id_task : Int64    |-----+-------+---->| Id_task : Int64    |
    |--------------------|                   |--------------------|
    | Name : TEXT        |                   | Date     : TEXT    |
    +--------------------+                   | Bap      : TEXT    |
                                             | Arch     : TEXT    |
                                             | Comp_ops : TEXT    |
                                             | Obj_ops  : TEXT    |
                                             | Policy   : TEXT    |
                                             | Extra    : TEXT    |
                                             +--------------------+

*)

open Core_kernel.Std
open Bap.Std
open Bap_traces.Std

(** [update_db trace rules numbers database] - saves
    results in SQLite [database] *)
val update_db :
  ?compiler_ops:string list ->
  ?object_ops:string list ->
  ?extra:string ->
  Trace.t ->
  Veri_rule.t list ->
  Veri_numbers.t ->
  string -> unit Or_error.t
