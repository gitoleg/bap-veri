open Core_kernel.Std
open Graph
open Bap.Std
open Bap_traces.Std

module Field = struct
  type t = string
  let of_string = ident
  let empty = ""
  let is_empty x = x = empty
end

type field = Field.t
type event = Trace.event
type events = Value.Set.t
type action = Skip | Deny

type matched = 
  | Left of event
  | Right of event
  | Both of event * event

type trial = {
  regexp : Re.re;
  field  : Field.t
}

type rule = {
  action : action;
  insn   : trial;
  left   : trial;
  right  : trial;
} [@@deriving fields]

type t = rule list

let skip = Skip
let deny = Deny

let make_trial s = 
  let field = match s with 
    | None -> Field.empty
    | Some s -> s in {
    regexp = Re.compile (Re_posix.re field);
    field;
  }

let make_rule ?insn ?left ?right action  = {
  action; 
  insn  = make_trial insn; 
  left  = make_trial left; 
  right = make_trial right; 
}

let sat e s = Re.execp e.regexp s
let sat_event e ev = sat e (Value.pps () ev)
let sat_events (e, ev) (e', ev') = sat_event e ev && sat_event e' ev'

module G = struct
  type g = trial * event array
  type t = g * g
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

  let iter dir f ((expect, workers), (expect', jobs)) v = 
    match v,dir with
    | V.Source,Pred -> ()
    | V.Source,Succ ->
      Array.iteri workers ~f:(fun i _  ->
          f @@ E.make V.Source (V.Person i))
    | V.Sink,Pred ->
      Array.iteri jobs ~f:(fun i _ ->
          f @@ E.make (V.Person i) V.Sink)
    | V.Sink,Succ -> ()
    | V.Person i as p,Pred ->
      f @@ E.make V.Source p
    | V.Person i as p,Succ ->
      Array.iteri jobs ~f:(fun j job ->
          if sat_events (expect,workers.(i)) (expect', job) 
          then f (E.make p (V.Task j)))
    | V.Task j as t,Succ ->
      f @@ E.make t V.Sink
    | V.Task j as t,Pred ->
      Array.iteri workers ~f:(fun i worker ->
          if sat_events (expect, worker) (expect', jobs.(j)) 
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

let is_empty_insn  t = Field.is_empty t.insn.field
let is_empty_left  t = Field.is_empty t.left.field
let is_empty_right t = Field.is_empty t.right.field
let is_sat_insn t insn = not (is_empty_insn t) && sat t.insn insn

let match_events t insn events events' =
  match is_sat_insn t insn with
  | false -> []
  | true -> 
    let left = Set.diff events events' in
    let right = Set.diff events' events in
    match is_empty_left t, is_empty_right t with
    | true, _ -> List.map ~f:(fun e -> Right e) (single_match t.right right)
    | _, true -> List.map ~f:(fun e -> Left e)  (single_match t.left left)
    | _ -> 
      let workers = t.left, Set.to_array left in      
      let jobs = t.right, Set.to_array right in
      let (flow,_) = FFMF.maxflow (workers, jobs) G.V.Source G.V.Sink  in
      Array.foldi (snd workers) ~init:[] 
        ~f:(fun i acc w ->   
            match Array.findi (snd jobs) ~f:(fun j e ->
                flow (G.E.make (G.V.Person i) (G.V.Task j)) <> 0) with
            | None -> acc 
            | Some (_,e) -> Both (w,e) :: acc)  

let denied ts insn events events' = 
  let rec loop acc ts (evs,evs') = match ts with
    | [] -> acc
    | t :: ts' ->
      let res = match_events t insn evs evs' in
      match t.action with
      | Skip -> 
        List.fold res ~init:(evs, evs')
          ~f:(fun (evs, evs') -> function
              | Left e -> Set.remove evs e, evs'
              | Right e' -> evs, Set.remove evs' e'
              | Both (e, e') -> Set.remove evs e, Set.remove evs' e') |> 
        loop acc ts'
      | Deny -> (t, res)  :: acc in 
  loop [] ts (events, events') 
