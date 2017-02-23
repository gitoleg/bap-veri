open Core_kernel.Std
open Bap.Std

type insn_info
type 'a freq

module Insn_info : sig
  type t = insn_info
  val of_bytes : string -> t
  val of_instr : Insn.t -> t
  val to_instr : t -> Insn.t option
  val to_bytes : t -> string option
  val index : t -> int
end

module Frequency : sig
  type 'a t = 'a freq
  val all : 'a t -> ('a * int) list
  val count : 'a t -> f:('a -> bool) -> int
end

module type S = sig
  type t
  val freq : t -> insn_info freq
  val feed : t -> insn_info -> t
end

module Static_info : sig
  include S
  val of_path : string -> t
end

module Trace_info : sig
  include S
  val of_seq : event Seq.t -> t
  val events : t -> insn_info list
end

module Errors_info : sig
  type t
  type kind = Disassembler | Semantic_soundness | Semantic_completness
  val freq : t -> kind freq
  val feed : insn_info -> Error.t -> kind -> t
  val list : t -> (insn_info * kind * Error.t) list
end
