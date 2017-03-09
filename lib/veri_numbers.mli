open Core_kernel.Std
open Bap.Std
open Bap_traces.Std

type t

type query = Veri_result.kind

val cases : Veri_info.test_case array
val t_of_values : value array -> t Or_error.t

(** [abs t query] - returns a number of occurrences in a trace
    according to a [query] *)
val number : t -> [`Total_number | query] -> int

(** [insns t query] - returns a Insn.t list for specified [query] *)
val insns  : t -> query -> Insn.t list

(** [insnsi t query] - returns a Insn.t list for specified [query]
    with a number of occurrences of each insn in a trace *)
val insnsi : t -> query -> (Insn.t * int) list

(** [bytes t query] - returns a bytes list for specified [query] *)
val bytes  : t -> query -> string list

(** [bytesi t query b] - returns a number of occurrences of bytes [b]
    in a trace according to a [query] *)
val bytesi : t -> query -> (string * int) list

(** [bytes_number t query bytes] - the same as {number} but
    for specified [bytes] *)
val bytes_number : t -> query -> string -> int

(** [find_insn t ~query bytes] - returns an Insn.t if it occures in
    a trace. And if a [query] is provided, check that insn satisfies
    to it. *)
val find_insn : t -> ?query:query -> string -> Insn.t option

(** [find_indexes t ~query bytes] - returns a list of indexes of the
    given [bytes]. If [query] is provided then returns indexes
    according to a query only. *)
val find_indexes : t -> ?query:query -> string -> int list
