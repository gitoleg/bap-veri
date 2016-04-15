open Core_kernel.Std
open Bap.Std
open Bap_traces.Std

module Expect = Veri_expect

type event = Trace.event
type events = Value.Set.t
type expect = Expect.t

let expect_of_string s = Expect.create [s;]

(** we use a two representation in order to 
    simplify matching *)
module Action = struct
  type t = {
    string : string;
    action : expect;
  }
    
  let create s = {string = s; action = expect_of_string s;}
  let is act act' = Expect.all_matches act.action [act'.string;] = `Yes
end

module Field = struct  
  type t = string
  let create = ident
end

type action = Action.t
type field = Field.t

type rule = {
  action : action;
  insn   : field;
  left   : field;
  right  : field;
}

let skip  = Action.create "SKIP"
let deny  = Action.create "DENY"
let empty = Field.create ""
let any   = Field.create " *"
let is_skip t = Action.is skip t.action
let is_deny t = Action.is deny t.action
let is_empty x = x = empty

let make_rule ?insn ?left ?right action = 
  let of_opt v = 
    Option.value_map v ~default:empty ~f:ident in
  { action; 
    insn  = of_opt insn; 
    left  = of_opt left; 
    right = of_opt right; }

let string_of_event e = Value.pps () e
let match_event exp ev = Expect.all_matches exp [string_of_event ev]

let match_events exp evs = 
  List.filter evs 
    ~f:(fun ev -> match_event (expect_of_string exp) ev = `Yes)

let match_events2 exp exp' evs evs' = 
  let to_str = string_of_event in
  let expect = Expect.create [exp; exp'] in
  List.cartesian_product evs evs' |>
  List.filter ~f:(fun (e,e') -> 
      Expect.all_matches expect [to_str e; to_str e'] = `Yes) |>
  List.fold_left ~init:([],[])
    ~f:(fun (acc, acc') (ev, ev') -> ev :: acc, ev' :: acc')

let exists ev where = List.exists ~f:(fun ev' -> ev = ev') where 

let remove from what =
  List.fold_left from ~init:[]
    ~f:(fun acc e -> if exists e what then acc
           else e :: acc)

let solve_skip left right events events' = 
  if is_empty left then
    let evs' = match_events right events' in
    events, remove events' evs'
  else if is_empty right then 
    let evs = match_events left events in
    remove events evs, events'
  else 
    let evs, evs' = match_events2 left right events events' in
    remove events evs, remove events evs'

let () = 
  let expect = Expect.create [" *"] in
  let insn = "mov" in
  let s = 
    match Expect.all_matches expect [insn] with
    | `Yes -> "ok"
    | `Missed _ -> "misses" in
  Printf.printf "%s\n" s
