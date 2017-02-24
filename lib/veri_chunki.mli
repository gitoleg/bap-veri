open Core_kernel.Std
open Bap.Std
open Bap_traces.Std

module Disasm : sig
  module Dis = Disasm_expert.Basic
  open Dis
  type t = (asm, kinds) Dis.t
  type insn = Dis.full_insn
end

type 'a u = 'a Bil.Result.u

class context: Trace.t -> object('s)
    inherit Veri_traci.context

    method notify_error : Veri_result.error option -> 's
    method update_insn  : Disasm.insn option -> 's
    method update_bil   : bil -> 's

    method error : Veri_result.error option
    method insn  : Disasm.insn option
    method bil   : bil
  end

class ['a] t : arch -> Disasm.t -> object('s)
    constraint 'a = #context
    inherit ['a] Veri_traci.t
  end
