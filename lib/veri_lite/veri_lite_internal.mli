open Core_kernel.Std

type t
type db = t

module Tab : sig
  type t
  type typ = Int | Text
  type col

  (** pairs (field_name, value) *)
  type where = (string * string) list

  (** [create name columns]  *)
  val create : string -> col list -> t

  val name : t -> string

  (** [exists db table_name]  *)
  val exists : db -> string -> bool Or_error.t

  (** [insert db tab ~ignore data]  *)
  val insert : db -> t -> ?ignore_:bool -> string list -> unit Or_error.t

  (** [col ~key ~not_null ~unique col_name typ]   *)
  val col : ?key:bool -> ?not_null:bool -> ?unique:bool -> string -> typ -> col

  (** [add db table]  *)
  val add : db -> t -> unit Or_error.t

  (** [add_if_absent db table]  *)
  val add_if_absent : db -> t -> unit Or_error.t

  (** [increment db table ~where field] *)
  val increment : db -> t -> ?where:where -> string -> unit Or_error.t

  (** [select db table ~where fields] *)
  val select : db -> t -> ?where:where -> string list -> string option Or_error.t

  (** [last_inserted db] - returns last inserted row id *)
  val last_inserted : db -> int64

end

val open_db  : string -> t Or_error.t
val close_db : t -> unit

val start_transaction : t -> unit Or_error.t
val commit_transaction : t -> unit Or_error.t
