
open Regular.Std
type t [@@deriving bin_io, sexp]

val create : unit -> t
val notify : t -> Veri_error.t -> t
val failbil : t -> string -> t
val success : t -> string -> t

include Regular with type t := t

module Summary : sig
  type t
  include Regular with type t := t
end

val make_summary: t -> Summary.t
