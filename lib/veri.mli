open Core_kernel.Std
open Bap.Std
open Regular.Std
open Bap_traces.Std
open Bap_future.Std

module Disasm : sig
  module Dis = Disasm_expert.Basic
  open Dis
  type t = (asm, kinds) Dis.t
end

class context: Veri_policy.t -> Trace.t -> object('s)
    inherit Veri_traci.context
    method split  : 's
    method merge  : 's
    method other  : 's option
    method save   : 's -> 's
    method switch : 's
    method code   : Chunk.t option
    method events : Value.Set.t
    method register_event : Trace.event -> 's
    method discard_event  : (Trace.event -> bool) -> 's
    method notify_error   : Veri_error.t -> 's
    method notify_success : 's
    method set_bil  : bil -> 's
    method set_code : Chunk.t -> 's
    method set_insn : string -> 's
    method drop_pc  : 's
    method cleanup  : 's
  end

class ['a] t : arch -> Disasm.t -> object('s)
    constraint 'a = #context
    inherit ['a] Veri_traci.t
  end


class verbose_context: Veri_stat.t -> Veri_policy.t -> Trace.t -> object('s)
    inherit context
    method update_stat : Veri_stat.t -> 's
    method stat : Veri_stat.t
    method reports : Veri_report.t stream
  end
