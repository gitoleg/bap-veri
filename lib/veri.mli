open Core_kernel.Std
open Bap.Std
open Bap_traces.Std
open Bap_future.Std

class context: Veri_policy.t -> Trace.t -> object('s)
    inherit Veri_chunki.context
    method split  : 's
    method merge  : 's
    method other  : 's option
    method save   : 's -> 's
    method code   : Chunk.t option
    method switch : 's
    method events : Value.Set.t
    method register_event : Trace.event -> 's
    method discard_event  : (Trace.event -> bool) -> 's
    method update_result  : Veri_result.t -> 's
    method drop_pc  : 's
    method set_code : Chunk.t -> 's
    method cleanup : 's
    method dict : dict
    method with_dict : dict -> 's
  end

class ['a] t : arch -> Veri_chunki.Disasm.t -> object('s)
    constraint 'a = #context
    inherit ['a] Veri_chunki.t
  end
