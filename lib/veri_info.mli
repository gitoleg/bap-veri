open Core_kernel.Std
open Bap.Std
open Bap_traces.Std

type insn_freq = int Insn.Map.t

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
      method freq : insn_freq
    end

  class ['a] t : object
    constraint 'a = #context
    inherit ['a] Base.t
  end
end

module Trace : sig
  type order = insn Queue.t

  val fold : trace -> init:'a -> f:('a -> int -> insn -> 'a) -> 'a Or_error.t
  val info : trace -> (order * insn_freq) Or_error.t
end

module Test_case : sig
  type t

  (** [custom ~f ~init ~tag] - describes a custom test, where
      [f] is applied to result of verification, index of
      instruction in a trace, and to result of previous calls
      of [f]. *)
  val custom : (Veri_result.t -> int -> 'a -> 'a) -> init:'a -> 'a tag -> t

  (** a few predefined test cases *)
  type 'a test = dict -> int -> 'a -> 'a

  val success      : 'a test -> init:'a -> 'a tag -> t
  val unsound_sema : 'a test -> init:'a -> 'a tag -> t
  val unknown_sema : 'a test -> init:'a -> 'a tag -> t
  val disasm_error : 'a test -> init:'a -> 'a tag -> t

  val eval : trace -> Veri_policy.t -> t array -> value array Or_error.t

  val fold : trace -> Veri_policy.t -> init:'a -> f:('a -> Veri_result.t -> 'a) -> 'a Or_error.t
  val iter : trace -> Veri_policy.t -> f:(Veri_result.t -> unit) -> unit Or_error.t

  val foldi : trace -> Veri_policy.t -> init:'a ->
    f:('a -> Veri_result.t -> int -> 'a) -> 'a Or_error.t

  val iteri : trace -> Veri_policy.t -> f:(Veri_result.t -> int -> unit) -> unit Or_error.t

end
