open Core_kernel.Std
open Veri_policy

(** grammar: ACTION INSN LEFT RIGHT 
    ACTION is mandatory field and could be either SKIP either DENY. 
    If field contains a space, e.g. RAX => .*, then necessary to 
    put it in quotes: "RAX => .*". Single quotes also supported. 
    Comments are available with // at the beginnig of string. *)

(** [read fname] - read rules from a given file *)
val read: string -> Rule.t Or_error.t list
