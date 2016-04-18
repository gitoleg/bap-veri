open Core_kernel.Std
open Graph
open Bap.Std
open Bap_traces.Std

module Action = struct
  type t = string
  let of_string = ident
  let is act act' = String.compare act act' = 0
end

type action = Action.t

let skip = Action.of_string "SKIP"
let deny = Action.of_string "DENY"

module Field = struct
  type t = string
  let of_string = ident
  let empty = ""
  let is_empty x = x = empty
end

type field = Field.t

module Rule = struct
  
  type t = {
    action : action;
    insn   : field;
    left   : field;
    right  : field;
  } [@@deriving fields]

  let create ?insn ?left ?right action = 
    let of_opt v = 
      Option.value_map v ~default:Field.empty ~f:ident in {
      action; 
      insn  = of_opt insn; 
      left  = of_opt left; 
      right = of_opt right; 
    }
end

type rule = Rule.t

type trial = Re.re

type t = {
  insn_trial  : trial;
  left_trial  : trial;
  right_trial : trial;
  rule        : rule;
}

type event = Trace.event
type events = event list

let make_trial s = Re.compile (Re_posix.re s)

let create rule = {
  insn_trial = make_trial (Rule.insn rule);
  left_trial = make_trial (Rule.left rule);
  right_trial = make_trial (Rule.right rule);
  rule = rule;
}

let sat e s = Re.execp e s

let sat_event e ev = Re.execp e (Value.pps () ev)

let sat_events (e, ev) (e', ev') = 
  sat_event e ev && sat_event e' ev'

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
          if sat_events (expect,workers.(i)) (expect', job) then 
            f (E.make p (V.Task j)))
    | V.Task j as t,Succ ->
      f @@ E.make t V.Sink
    | V.Task j as t,Pred ->
      Array.iteri workers ~f:(fun i worker ->
          if sat_events (expect, worker) (expect', jobs.(j)) then 
            f (E.make (V.Person i) t))

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
  List.filter ~f:(sat_event trial) events

let is_empty_insn  t = Field.is_empty (Rule.insn t.rule)
let is_empty_left  t = Field.is_empty (Rule.left t.rule)
let is_empty_right t = Field.is_empty (Rule.right t.rule)
let is_sat_insn t insn = not (is_empty_insn t) && sat t.insn_trial insn

let match_events t insn events events' =
  match is_sat_insn t insn with
  | false -> []
  | true -> 
    match is_empty_left t, is_empty_right t with
    | true, _ ->
      single_match t.right_trial events' |>
      List.map ~f:(fun e -> None, Some e)
    | _, true -> 
      single_match t.left_trial events |>
      List.map ~f:(fun e -> Some e, None)
    | _ -> 
      let workers = t.left_trial, Array.of_list events in      
      let jobs = t.right_trial, Array.of_list events' in
      let (flow,_) = FFMF.maxflow (workers, jobs) G.V.Source G.V.Sink  in
      Array.foldi (snd workers) ~init:[] 
        ~f:(fun i acc w ->   
            match Array.findi (snd jobs) ~f:(fun j e ->
                flow (G.E.make (G.V.Person i) (G.V.Task j)) <> 0) with
            | None -> acc 
            | Some (_,e) -> (Some w, Some e) :: acc)  

