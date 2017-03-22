open Core_kernel.Std
open Bap.Std
open Bap_traces.Std
open Bap_future.Std
open Regular.Std

module Std : sig

  type 'a u = 'a Bil.Result.u
  type event = Trace.event

  module Disasm : sig
    module Dis = Disasm_expert.Basic
    open Dis
    type t = (asm, kinds) Dis.t
    type insn = Dis.full_insn
  end

  module Traci : sig
    class context : Trace.t -> object('s)
        inherit Bili.context
        method next_event: ('s * event) option
        method with_events: Trace.t -> 's
      end

    class ['a] t: arch -> object('s)
        constraint 'a = #context
        inherit ['a] Bili.t
        method eval_trace : Trace.t -> 'a u
        method eval_event : event -> 'a u
        method eval_memory_load  : addr move -> 'a u
        method eval_memory_store : addr move -> 'a u
        method eval_register_read : var move -> 'a u
        method eval_register_write : var move -> 'a u
        method eval_exec : chunk -> 'a u
        method eval_pc_update : addr -> 'a u
        method eval_context_switch : int -> 'a u
        method eval_syscall : syscall -> 'a u
        method eval_exn : exn -> 'a u
        method eval_call : call -> 'a u
        method eval_return : return -> 'a u
        method eval_modload : modload -> 'a u
      end
  end


  module Result : sig
    type sema_error = [
      | `Unsound_sema (** instruction execution mismatches with trace  *)
      | `Unknown_sema (** instruction semantic is unknown for lifter   *)
    ] [@@deriving bin_io, compare, sexp]

    type error_kind = [
      | `Disasm_error (** error with disassembling                     *)
      | sema_error
    ] [@@deriving bin_io, compare, sexp]

    type kind = [ `Success | error_kind ] [@@deriving bin_io, compare, sexp]
    type error = error_kind * Error.t [@@deriving bin_io, compare, sexp]
  end


  module Chunki : sig
    class context: Trace.t -> object('s)
        inherit Traci.context

        method notify_error : Result.error option -> 's
        method update_insn  : Disasm.insn Or_error.t -> 's
        method update_bil   : bil Or_error.t -> 's
        method error : Result.error option
        method insn  : Disasm.insn option
        method bil   : bil
      end

    class ['a] t : arch -> Disasm.t -> object('s)
        constraint 'a = #context
        inherit ['a] Traci.t
      end
  end


  module Rule : sig
    (** rule = ACTION : INSN : EVENT : EVENT  *)

    type t [@@deriving bin_io, compare, sexp]
    type action [@@deriving bin_io, compare, sexp]
    type field
    include Regular.S with type t := t

    (** [create ~insn ~left ~right action] - returns a rule,
        if all of fields {insn, left, right} either contains
        correct regular expression, either plain string, either
        are an empty strings. If some field is not given, it's
        assumed that an empty string fits well for this field. *)
    val create :
      ?insn:string -> ?left:string -> ?right:string -> action -> t Or_error.t

    exception Bad_field of string

    (** [create_exn ~insn ~left ~right action] - the same as above, but raises
        Bad_field exception if fields contains errors in regular expressions *)
    val create_exn : ?insn:string -> ?left:string -> ?right:string -> action -> t

    (** [of_string_err str] - return a rule, if string contains exactly 4 fields:
        - action (with only two possible values: SKIP | DENY)
        - instruction name or correct regular expression
        - one of the following:
           correct regular expression for left part and empty string for right part;
           empty string for left part and correct regular expression for right part;
           correct regular expression for both left and right parts. *)
    val of_string_err : string -> t Or_error.t

    val skip : action
    val deny : action
    val action : t -> action
    val insn   : t -> field
    val left   : t -> field
    val right  : t -> field
    val is_empty : field -> bool

    (** [match_field t field str] - match a given string with a field. *)
    val match_field: t -> [`Insn | `Left | `Right | `Both] -> string -> bool

    module Reader : sig
      val of_path : string -> t list
    end
  end


  module Policy : sig
    type events = Value.Set.t

    type rule = Rule.t [@@deriving bin_io, compare, sexp]

    module Matched : sig
      type t = event list * event list [@@deriving bin_io, compare, sexp]
      include Regular.S with type t := t
    end

    type matched = Matched.t [@@deriving bin_io, compare, sexp]
    type t [@@deriving bin_io, compare, sexp]

    type result = rule * matched
    [@@deriving bin_io, compare, sexp]

    val empty : t
    val default : t
    val add : t -> rule -> t

    (** [match events rule insn left right] *)
    val match_events: rule -> string -> events -> events -> matched option

    (** [denied policy insn left right] *)
    val denied: t -> string -> events -> events -> result list
  end


  module Info : sig
    type t

    val addr : t -> addr
    val insn : t -> Insn.t option
    val real : t -> event list
    val ours : t -> event list
    val diff : t -> Policy.result list
    val index : t -> int
    val bytes : t -> string
    val error : t -> Result.error option
  end


  module Exec : sig
    class context: Policy.t -> Trace.t -> object('s)
        inherit Chunki.context
        method split  : 's
        method merge  : 's
        method other  : 's option
        method save   : 's -> 's
        method code   : Chunk.t option
        method switch : 's
        method events : Value.Set.t
        method register_event : event -> 's
        method discard_event  : (event -> bool) -> 's
        method drop_pc  : 's
        method set_code : Chunk.t -> 's
        method cleanup  : 's
        method info     : Info.t stream * unit Future.t
      end

    class ['a] t : arch -> Disasm.t -> object('s)
        constraint 'a = #context
        inherit ['a] Chunki.t
      end
  end


  module Backend : sig
    module type S = sig
      val run : string -> Info.t stream -> unit future -> unit
      val on_exit : unit -> unit
    end

    val register : string -> (module S) -> unit
    val registered : unit -> string list
    val call : string -> Info.t stream -> unit future -> unit
    val on_exit : unit -> unit
  end
end
