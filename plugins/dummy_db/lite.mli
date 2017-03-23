open Core_kernel.Std

type t
type db = t

module Tab : sig
  type t
  type typ = Int | Text
  type traits = Not_null | Key
  type col

  val col : ?key:bool -> ?not_null:bool -> string  -> typ -> col
  val create : string -> col list -> t
  val add : db -> t -> unit Or_error.t
  val exists : db -> string -> bool Or_error.t
  val add_if_absent : db -> t -> unit Or_error.t
  val insert : db -> t -> string list -> unit Or_error.t
  val get_max : db -> t -> string -> string option Or_error.t
end

val open_db : string -> t Or_error.t
val close_db : t -> unit
