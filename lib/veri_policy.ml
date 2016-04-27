open Core_kernel.Std
open Graph
open Bap.Std
open Bap_traces.Std
open Regular.Std

module Field = struct
  type t = string [@@deriving bin_io, compare, sexp]
  let of_string = ident
  let empty = ""
  let is_empty x = x = empty
end

type field = Field.t [@@deriving bin_io, compare, sexp]

module Rule = struct
  type action = Skip | Deny [@@deriving bin_io, compare, sexp]

  type t = {
    action : action;
    insn   : field;
    left   : field;
    right  : field;
  } [@@deriving bin_io, compare, fields, sexp]

  let skip = Skip
  let deny = Deny

  let create ?insn ?left ?right action  = 
    let of_opt = 
      Option.value_map ~default:Field.empty ~f:ident in {
      action; 
      insn  = of_opt insn; 
      left  = of_opt left; 
      right = of_opt right; 
    }

  type s = t [@@deriving bin_io, compare, sexp]
  include Regular.Make(struct
      type t = s [@@deriving bin_io, compare, sexp]
      let compare = compare
      let hash = Hashtbl.hash
      let module_name = Some "Veri_policy.Rule"
      let version = "0.1"

      let pp fmt rule = 
        let act = match rule.action with
          | Skip -> "Skip"
          | Deny -> "Deny" in
        Format.fprintf fmt "%s : %s : %s : %s ;" 
          act rule.insn rule.left rule.right
    end)
end

type event = Trace.event [@@deriving bin_io, sexp]
type events = Value.Set.t
type rule = Rule.t [@@deriving bin_io, compare, sexp]
type trial = Pcre.regexp

type matched = 
  | Left of event list
  | Right of event list 
  | Both of (event * event) list 
  [@@deriving bin_io, sexp]

type entry = {
  insn_trial : trial;
  left_trial : trial;
  right_trial: trial;
  both_trial : trial;
  rule  : rule;
}

type t = entry list

let make_trial s = Pcre.regexp ~flags:[`ANCHORED] s

let sep = " : "

let make_both_trial rule = 
  let s = String.concat ~sep [Rule.left rule; Rule.right rule] in
  make_trial s

let make_entry rule = {
  insn_trial = make_trial (Rule.insn rule);
  left_trial = make_trial (Rule.left rule);
  right_trial = make_trial (Rule.right rule);
  both_trial = make_both_trial rule;
  rule;
}

let empty = []
let add t rule : t = make_entry rule :: t
let sat rex s = Pcre.pmatch ~rex s
let sat_event e ev = sat e (Value.pps () ev) 

let string_of_events ev ev' = 
  String.concat ~sep [Value.pps () ev; Value.pps () ev']
  
let sat_events e ev ev' =
  Value.typeid ev = Value.typeid ev' &&
  sat e (string_of_events ev ev')

module G = struct
  type t = trial * event array * event array
  module V = struct
    type t = Source | Sink | Person of int | Task of int [@@deriving compare]
    let hash = Hashtbl.hash
    let equal x y = compare x y = 0
  end
  module E = struct
    type label = unit

    type t = {src : V.t; dst : V.t} [@@deriving fields]
    let make src dst = {src; dst}
    let label _ = ()
  end
  type dir = Succ | Pred

  let iter dir f (expect, workers, jobs) v = 
    match v,dir with
    | V.Source,Pred -> ()
    | V.Source,Succ ->
      Array.iteri workers ~f:(fun i _  ->
          f @@ E.make V.Source (V.Person i))
    | V.Sink,Pred ->
      Array.iteri jobs ~f:(fun i _ ->
          f @@ E.make (V.Task i) V.Sink)
    | V.Sink,Succ -> ()
    | V.Person i as p,Pred ->
      f @@ E.make V.Source p
    | V.Person i as p,Succ ->
      Array.iteri jobs ~f:(fun j job ->
          if sat_events expect workers.(i) job
          then f (E.make p (V.Task j)))
    | V.Task j as t,Succ ->
      f @@ E.make t V.Sink
    | V.Task j as t,Pred ->
      Array.iteri workers ~f:(fun i worker ->
          if sat_events expect worker jobs.(j)
          then f (E.make (V.Person i) t))

  let iter_succ_e = iter Succ
  let iter_pred_e = iter Pred
end

module F = struct
  type t = int
  type label = unit
  let max_capacity () = 1
  let min_capacity () = 0
  let flow () = min_capacity ()
  let add = (+)
  let sub = (-)
  let zero = 0
  let compare = Int.compare
end

module FFMF = Flow.Ford_Fulkerson(G)(F)

let single_match trial events =
  List.filter ~f:(sat_event trial) (Set.to_list events)

let match_right t events = 
  match single_match t.right_trial events with 
  | [] -> None
  | ms -> Some (Right ms)  

let match_left t events = 
  match single_match t.left_trial events with 
  | [] -> None
  | ms -> Some (Left ms)  

let match_both t left right = 
  let workers = Set.to_array left in      
  let jobs = Set.to_array right in
  let (flow,_) = FFMF.maxflow (t.both_trial, workers, jobs) G.V.Source G.V.Sink  in
  Array.foldi workers ~init:[] 
    ~f:(fun i acc w ->   
        match Array.findi jobs ~f:(fun j e ->
            flow (G.E.make (G.V.Person i) (G.V.Task j)) <> 0) with
        | None -> acc 
        | Some (_,e) -> (w, e) :: acc) |> function 
  | [] -> None
  | ms -> Some (Both ms)

let is_empty_insn  t = Field.is_empty (Rule.insn t.rule)
let is_empty_left  t = Field.is_empty (Rule.left t.rule)
let is_empty_right t = Field.is_empty (Rule.right t.rule)
let is_sat_insn t insn = not (is_empty_insn t) && sat t.insn_trial insn

let match_events' t insn events events' =
  match is_sat_insn t insn with
  | false -> None
  | true -> 
    let left = Set.diff events events' in
    let right = Set.diff events' events in
    match is_empty_left t, is_empty_right t with
    | true, _ -> match_right t right
    | _, true -> match_left t left
    | _ -> match_both t left right

let match_events rule insn events events' =
  match_events' (make_entry rule) insn events events'

let remove what from = 
  let not_exists e = not (List.exists what ~f:(fun e' -> e = e')) in
  Set.filter ~f:not_exists from 

let remove_matched events events' = function
  | Left evs -> remove evs events, events'
  | Right evs -> events, remove evs events'
  | Both pairs -> 
    let evs, evs' = List.unzip pairs in
    remove evs events, remove evs' events'

let denied entries insn events events' =   
  let entries = List.rev entries in
  let rec loop acc entries (evs,evs') = match entries with
    | [] -> acc
    | e :: es ->
      match match_events' e insn evs evs' with
      | None -> loop acc es (evs,evs')
      | Some matched -> 
        let acc' = match Rule.action e.rule with
          | Rule.Skip -> acc
          | Rule.Deny -> (e.rule, matched) :: acc in
        remove_matched evs evs' matched |> 
        loop acc' es in
  loop [] entries (events, events') 
