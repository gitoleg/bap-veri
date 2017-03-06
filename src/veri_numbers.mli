open Core_kernel.Std
open Bap.Std
open Bap_traces.Std

type t

module Q : sig

  type query = Veri_result.kind
  type insn_query = [ Veri_result.success | Veri_result.sema_error]
  type int_query = [`Total_number | query]

  val total : t -> int
  val relat : t -> query -> float
  val abs   : t -> int_query -> int

  val insn   : t -> Insn.t -> insn_query -> int
  val insns  : t -> insn_query -> Insn.t list
  val insnsi : t -> insn_query -> (Insn.t * int) list

end

val run : Trace.t -> Veri_policy.t -> t Or_error.t
