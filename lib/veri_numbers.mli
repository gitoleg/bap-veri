open Core_kernel.Std
open Bap.Std
open Bap_traces.Std

type t

module Q : sig

  type query = Veri_result.kind
  type insn_query = [ Veri_result.success | Veri_result.sema_error]

  val total : t -> int
  val relat : t -> query -> float
  val abs   : t -> [`Total_number | query] -> int

  val insn   : t -> Insn.t -> insn_query -> int
  val insns  : t -> insn_query -> Insn.t list
  val insnsi : t -> insn_query -> (Insn.t * int) list

end

val empty : t
val merge : t -> t -> t
val add : t -> Veri_result.t -> t
val run : Trace.t -> Veri_policy.t -> t Or_error.t
