open Core_kernel.Std
open Bap.Std
open Bap_traces.Std

module Insn_freq : sig
  type t
  val create : unit -> t
  val feed   : t -> insn -> t
  val print : t -> unit
end

module Binary : sig
  type 'a u = 'a Bil.Result.u
  type insns = insn seq

  module Base : sig
    class context : insns -> object ('s)
        method next_insn  : ('s * insn) option
        method with_insns : insns -> 's
      end

    class ['a] t : object
      constraint 'a = #context
      method eval_insn  : insn -> 'a u
      method eval_insns : insns -> 'a u
    end
  end


  class context : insns -> object ('s)
      inherit Base.context
      method add_insn : insn -> 's
      method freq : Insn_freq.t
    end

  class ['a] t : object
    constraint 'a = #context
    inherit ['a] Base.t
  end
end

module Trace : sig
  class context : trace -> object('s)
      inherit Veri_chunki.context
      method freq  : Insn_freq.t
      method order : insn list
    end
end

module Error : sig

  (* module Test_case : sig *)
  (*   type t *)
  (*   val is_succeed : t *)
  (*   val is_unsound : t *)
  (*   val is_incomplete : t *)
  (*   val is_undisasmed : t *)
  (* end *)

  (* type case = Test_case.t *)

  type result = Veri.result
  type policy = Veri_policy.t

  val eval : trace -> policy
    -> init:'a -> f:(result -> int -> 'a -> 'a) -> 'a Or_error.t

end
