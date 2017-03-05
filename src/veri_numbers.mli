open Core_kernel.Std
open Bap_traces.Std

type t

module Q : sig

  type query = Veri_result.kind

  type int_query = [
    | `Total_number
    | query
  ]

  val total : t -> int_query -> int
  val relat : t -> query -> float
end

val run : Trace.t -> Veri_policy.t -> t Or_error.t
