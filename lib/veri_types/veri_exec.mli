open Core_kernel.Std
open Bap.Std
open Bap_traces.Std
open Bap_future.Std

type event = Trace.event

module Info : sig
  type t

  val addr : t -> addr
  val insn : t -> Insn.t option
  val real : t -> event list
  val ours : t -> event list
  val diff : t -> Veri_policy.result list
  val index : t -> int
  val bytes : t -> string
  val error : t -> Veri_error.t option
end

class context: Veri_policy.t -> Trace.t -> object('s)
    inherit Veri_chunki.context
    method split  : 's
    method merge  : 's
    method other  : 's option
    method save   : 's -> 's
    method code   : Chunk.t option
    method switch : 's
    method events : Value.Set.t
    method register_event : event -> 's
    method discard_event  : (event -> bool) -> 's
    method drop_pc  : 's
    method set_code : Chunk.t -> 's
    method cleanup  : 's
    method info     : Info.t stream * unit Future.t
  end

class ['a] t : arch -> Veri_chunki.Disasm.t -> object('s)
    constraint 'a = #context
    inherit ['a] Veri_chunki.t
  end
