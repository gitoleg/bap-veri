open Core_kernel.Std
open Bap.Std
open Bap_traces.Std
open Bap_future.Std

module Report : sig
  type t [@@deriving bin_io, sexp]
  val bil  : t -> bil
  val code : t -> string
  val insn : t -> string
  val left : t -> Trace.event list
  val right: t -> Trace.event list
  val data : t -> (Veri_policy.rule * Veri_policy.matched) list
  val pp : Format.formatter -> t -> unit
end

module Stat : sig
  type t [@@deriving bin_io, sexp]
  type stat = t [@@deriving bin_io, sexp]

  val empty : t
  val merge : t list -> t
  val notify : t -> Veri_result.error_kind -> dict -> t
  val success : t -> string -> t
  val pp_summary: Format.formatter -> t -> unit
  val pp : Format.formatter -> t -> unit

  (** Terms:
      successed       - instructions, that were successfuly lifted and evaluted
                        without any divergence from trace at least once (or more);
      misexecuted     - instructions, that were successfuly lifted and evaluted
                        with divergence from trace at least once (or more);
      mislifted       - instructions, that weren't recognized by lifter;
      undisasmed      - errors in disassembling;
      total           - whole count of cases above *)

  (** absolute counts  *)
  module Abs : sig
    type t = stat -> int
    val successed       : t
    val misexecuted     : t
    val undisasmed      : t
    val mislifted       : t
    val total           : t
  end

  (** relative to total count *)
  module Rel : sig
    type t = ?as_percents:bool -> stat -> float
    val successed       : t
    val misexecuted     : t
    val undisasmed      : t
    val mislifted       : t
  end

  (** instruction names  *)
  module Names : sig
    type t = stat -> string list
    val successed       : t
    val misexecuted     : t
    val mislifted       : t
  end
end

class context: Stat.t -> Veri_policy.t -> Trace.t -> object('s)
    inherit Veri.context
    method update_stat : Stat.t -> 's
    method stat : Stat.t
    method reports : Report.t stream
    method make_report : Veri_policy.result list -> Report.t option
  end
