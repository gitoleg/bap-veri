(**


                                       binary_obj
             info                 +-------------------+
    +-------------------+         | * Id_obj  : Int   |>>--------+
    | * Id       : Int  |<<---+-<<| * Id_info : Int   |          |
    |-------------------|     |   +-------------------+          |
    |   Name     : Text |     |                                  |
    |   Date     : Text |     |                                  |
    |   Bap      : Text |     |                                  |
    |   Arch     : Text |     |                                  |
    |   Comp_ops : Text |     |                                  |
    |   Extra    : Text |     |             task                 |
    +-------------------+     |     +---------------------+      |
                              +---<<| * Id_info     : Int |      |
                            +-----<<| * Id_dyn_info : Int |      |
                            |   +-<<| * Id_task     : Int |      |
                            |   |   +---------------------+      |
         dynamic_info       |   |                                |
    +-------------------+   |   |                                |
    | * Id       : Int  |<<-+   |           binary_insn          |
    |-------------------|       |      +------------------+      |
    |   Obj_ops  : Text |       |      | * Id_obj  : Int  |<<----+
    |   Policy   : Text |       |      | * Id_insn : Int  |>>----+
    +-------------------+       |      +------------------+      |
                                |                                |
                                |                                |
         dynamic_data           |                                |
    +-----------------------+   |              insn              |
    | * Id_task      : Int  |<<-+      +------------------+      |
    | * Id_insn      : Int  |>>------>>| * Id_insn : Int  |<<----+
    |-----------------------|          |------------------|
    |   Indexes      : Text |          |   Bytes   : Text |
    |   Successful   : Int  |          |   Name    : Text |
    |   Undisasmed   : Int  |          |   Asm     : Text |
    |   Unsound_sema : Int  |          |   Bil     : Text |
    |   Unknown_sema : Int  |          +------------------+
    +-----------------------+


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
  Trace.t ->
  Veri_rule.t list ->
  Veri_numbers.t ->
  string -> unit Or_error.t

(** [update_insns : ~db:db_name arch ~bin:binary_name insns]  *)
val update_with_binary :
  db:string ->
  ?compiler_ops:string list ->
  arch ->
  bin:string -> (mem * insn) seq -> unit Or_error.t
