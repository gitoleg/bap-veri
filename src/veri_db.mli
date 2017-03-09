(**


                                 task
                         +--------------------+
    +-------------------<| * Id_task : Int    |>-----------------+
    |                    |--------------------|                  |
    |                    | Name : Text        |                  |
    |                    +--------------------+                  |
    |                                                            |
    |           instruction                     env              |
    |     +--------------------+        +------------------+     |
    +---->| * Id_task : Int    |        | * Id_task : Int  |<----+
          | * Id_insn : Int    |        |------------------|
          |--------------------|        | Date     :  Text |
          | Bytes : Text       |        | Bap      :  Text |
          | Name  : Text       |        | Arch     :  Text |
          | Asm   : Text       |        | Comp_ops :  Text |
          | Bil   : Text       |        | Obj_ops  :  Text |
          | Indexes : Text     |        | Policy   :  Text |
          | Successful   : Int |        | Extra    :  Text |
          | Undisasmed   : Int |        +------------------+
          | Unsound_sema : Int |
          | Unknown_sema : Int |
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
