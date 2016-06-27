open Core_kernel.Std
open Bap.Std
open Regular.Std

type trial = Pcre.regexp
type action = Skip | Deny [@@deriving bin_io, compare, sexp] 
type field = trial * string

type t = {
  action : action;
  insn   : field;
  both   : field;
  left   : field;
  right  : field;
}

let sep = " : "
let empty = ""
let is_empty s = s = empty

let action t = t.action
let skip = Skip
let deny = Deny

let string_of_action = function
  | Skip -> "Skip"
  | Deny -> "Deny"

let trial_exn s = Pcre.regexp ~flags:[`ANCHORED] s
let field_exn s = trial_exn s, s

let field_opt s =
  try
    Some (field_exn s)
  with Pcre.Error _ -> None

let field_err s = 
  try
    Ok (field_exn s)
  with Pcre.Error _ -> 
    let s = Printf.sprintf "error in field %s" s in
    Error (Error.of_string s)

let is_backreferenced = 
  let rex = Pcre.regexp "\\[0-9]" in
  fun s -> Pcre.pmatch ~rex s

let make_right_part s = 
  if is_backreferenced s then
    Ok (trial_exn empty, s)
  else field_err s

let create ?insn ?left ?right action =
  let open Result in
  let of_opt = Option.value_map ~default:empty ~f:ident in 
  let both = String.concat ~sep [of_opt left; of_opt right] in    
  field_err (of_opt insn) >>= fun insn ->
  field_err both >>= fun both ->
  field_err (of_opt left) >>= fun left ->
  make_right_part (of_opt right) >>= fun right ->    
  Ok ({action; insn; both; left; right;})

let is_empty_field field = is_empty (snd field)
let is_empty_insn  t = is_empty_field t.insn
let is_empty_left  t = is_empty_field t.left
let is_empty_right t = is_empty_field t.right

let to_string t = 
  Printf.sprintf "%s %s %s %s"
    (string_of_action t.action) (snd t.insn) (snd t.left) (snd t.right)

module Match = struct

  type m = t -> string -> bool
    
  let match_field field s = Pcre.pmatch ~rex:(fst field) s
  let insn t  = match_field t.insn
  let both t  = match_field t.both
  let left t  = match_field t.left
  let right t = match_field t.right

end

module Of_string = struct

  let rex = Pcre.regexp "'.*?'|\".*?\"|\\S+"
  let is_quote c = c = '\"' || c = '\''
  let unquote s = String.strip ~drop:is_quote s
  let er s = Error (Error.of_string s) 

  (** Not_found could be raised here  *)
  let fields_exn str = 
    Pcre.exec_all ~rex str |>
    Array.fold ~init:[] ~f:(fun acc ar ->
        let subs = Pcre.get_substrings ar in
        acc @ Array.to_list subs) |>
    List.map ~f:unquote

  let fields_opt str = 
    try
      match fields_exn str with 
      | [action; insn; left; right] -> Some (action, insn, left, right)
      | _ -> None
    with Not_found -> None

  let fields_err str = 
    match fields_opt str with
    | Some fields -> Ok fields
    | None -> 
      er (Printf.sprintf "String %s doesn't match to rule grammar" str)

  let action_err = function 
    | "SKIP" -> Ok Skip
    | "DENY" -> Ok Deny
    | s -> er (Printf.sprintf "only SKIP | DENY actions should be used: %s" s)

  let make_rule s = 
    let open Or_error in
    fields_err s >>= fun (action, insn, left, right) ->
    action_err action >>= fun action' ->
    create ~insn ~left ~right action'

end

let of_string_err = Of_string.make_rule

module S : Stringable with type t = t = struct
  type nonrec t = t
  let of_string str = ok_exn (Of_string.make_rule str)
  let to_string = to_string
end

include Sexpable.Of_stringable(S)
include Binable.Of_stringable(S)
include (S : Stringable with type t := t)

include Regular.Make(struct
    type nonrec t = t [@@deriving bin_io, compare, sexp]
    let compare = compare
    let hash = Hashtbl.hash
    let module_name = Some "Veri_rule"
    let version = "0.1"

    let pp fmt t = 
      Format.fprintf fmt "%s %s %s %s"
        (string_of_action t.action) (snd t.insn) (snd t.left) (snd t.right)
  end)
