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

module Report : sig
  type t [@@deriving bin_io, sexp]
  include Regular with type t := t
  val bil  : t -> bil
  val code : t -> string
  val insn : t -> string
  val left : t -> Trace.event list
  val right: t -> Trace.event list
  val data : t -> (Veri_policy.rule * Veri_policy.matched) list
end

class context: Veri_policy.t -> Trace.t -> object('s)
    inherit Veri_traci.context
    method split : 's
    method merge : 's
    method other  : 's option
    method stat : Veri_stat.t
    method code : Chunk.t option
    method events : Value.Set.t
    method reports : Report.t stream
    method register_event : Trace.event -> 's
    method discard_event : (Trace.event -> bool) -> 's
    method notify_error: Veri_error.t -> 's
    method set_description: string -> 's
    method set_bil : bil -> 's
    method set_code : Chunk.t -> 's 
  end

class ['a] t : arch -> Disasm.t -> (Trace.event -> bool) -> object('s)
    constraint 'a = #context
    inherit ['a] Veri_traci.t
  end
