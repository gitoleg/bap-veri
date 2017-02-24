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

  type result = Veri_result.t
  type policy = Veri_policy.t

  module Test_case : sig
    type t
    type kind = Veri_result.result_kind
    type 'a error_test = Veri_result.error_info -> int -> 'a -> 'a

    val success     : (int -> 'a -> 'a) -> 'a -> 'a tag -> t
    val unsound_sema : 'a error_test -> 'a -> 'a tag -> t
    val unknown_sema : 'a error_test -> 'a -> 'a tag -> t
    val disasm_error : 'a error_test -> 'a -> 'a tag -> t
    val custom_case : (result -> int -> 'a -> 'a) -> 'a -> 'a tag -> t

  end

  type case = Test_case.t

  val eval : trace -> policy -> case list -> value list Or_error.t

end
