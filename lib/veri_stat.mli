open Regular.Std
type t [@@deriving bin_io, sexp]
type stat = t [@@deriving bin_io, sexp]

val empty : t
val merge : t list -> t
val notify : t -> Veri_error.t -> t
val success : t -> string -> t

val pp_summary: Format.formatter -> t -> unit

include Regular.S with type t := t

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
