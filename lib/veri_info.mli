open Core_kernel.Std
open Bap.Std
open Bap_traces.Std

module Insn_freq : sig
  type t
  val create : unit -> t
  val insns  : t -> int Insn.Map.t
  val feed   : t -> insn -> t
  val pp : Format.formatter -> t -> unit
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

module Test_case : sig
  type t
  type 'a error_test = dict -> int -> 'a -> 'a

  (** [custom ~f ~init ~tag] - describes a custom test, where
      [f] is applied to result of verification, index of
      instruction in a trace, and to result of previous calls
      of [f]. *)
  val custom : (Veri_result.t -> int -> 'a -> 'a) -> init:'a -> 'a tag -> t

  val success     : (int -> 'a -> 'a) -> init:'a -> 'a tag -> t
  val unsound_sema : 'a error_test -> init:'a -> 'a tag -> t
  val unknown_sema : 'a error_test -> init:'a -> 'a tag -> t
  val disasm_error : 'a error_test -> init:'a -> 'a tag -> t

  val eval : trace -> Veri_policy.t -> t array -> value array Or_error.t
end
