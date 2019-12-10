
type t

val create : string list -> t

val add_row : t -> string list -> t

val pp : Format.formatter -> t -> unit
