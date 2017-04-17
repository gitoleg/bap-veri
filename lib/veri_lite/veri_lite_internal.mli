open Core_kernel.Std

type t
type db = t

module Tab : sig
  type t
  type typ = Int | Text
  type col

  val create : string -> col list -> t
  val name : t -> string
  val exists : db -> string -> bool Or_error.t
  val insert : db -> t -> ?ignore_:bool -> string list -> unit Or_error.t
  val col : ?key:bool -> ?not_null:bool -> ?unique:bool -> string  -> typ -> col
  val add : db -> t -> unit Or_error.t
  val get_max : db -> t -> string -> string option Or_error.t
  val add_if_absent : db -> t -> unit Or_error.t

  val increment : db -> t -> ?where:(string * string) list -> string ->
    unit Or_error.t

  val select : db -> t -> ?where:(string * string) list -> string list ->
    string option Or_error.t

end

val open_db  : string -> t Or_error.t
val close_db : t -> unit

val start_transaction : t -> unit Or_error.t
val commit_transaction : t -> unit Or_error.t
