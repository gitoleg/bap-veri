
(** rule = ACTION : INSN : EVENT : EVENT *)

type rule
type action
type field = string

val any   : field
val empty : field
val skip : action
val deny : action
val is_deny: rule -> bool
val is_skip: rule -> bool

val make_rule: ?insn:field -> ?left:field -> ?right:field -> action -> rule
