open Core_kernel.Std
open Bap.Std
open Bap_traces.Std
open Bap_future.Std

type result = Veri_result.t

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
    method update_result  : result -> 's
    method drop_pc  : 's
    method set_code : Chunk.t -> 's
    method cleanup : 's
  end

class ['a] t : arch -> Veri_chunki.Disasm.t -> object('s)
    constraint 'a = #context
    inherit ['a] Veri_chunki.t
  end

class verbose_context: Veri_stat.t -> Veri_policy.t -> Trace.t -> object('s)
    inherit context
    method update_stat : Veri_stat.t -> 's
    method stat : Veri_stat.t
    method reports : Veri_report.t stream
    method make_report : Veri_result.error -> Veri_report.t option
  end
