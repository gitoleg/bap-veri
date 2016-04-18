open Core_kernel.Std
open Bap.Std
open Bap_traces.Std

type error = Veri_error.t
type policy = Veri_policy.t

module Disasm : sig
  module Dis = Disasm_expert.Basic
  open Dis
  type t = (asm, kinds) Dis.t
end

class context: policy list -> Veri_report.t -> Trace.t -> object('s)
    inherit Veri_traci.context
    method split : 's
    method merge : 's
    method register_event : Trace.event -> 's
    method events : Value.Set.t
    method other  : 's option
    method replay : 's 
    method report: Veri_report.t
    method set_description: string -> 's
    method notify_error: error -> 's
    method backup: 's -> 's
  end

class ['a] t : arch -> Disasm.t -> (Trace.event -> bool) -> object('s)
    constraint 'a = #context
    inherit ['a] Veri_traci.t
  end
