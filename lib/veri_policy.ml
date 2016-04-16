open Core_kernel.Std
open Graph
open Bap.Std
open Bap_traces.Std

module Rule = struct
  type action = string

  type t = {
    action : action;
    insn   : string;
    left   : string;
    right  : string;
  }

  let skip = "SKIP"
  let deny = "DENY"
  let empty_field = ""
  let is_skip t = t.action = skip
  let is_deny t = t.action = deny
  let is_empty_field x = x = empty_field

  let create ?insn ?left ?right action = 
    let of_opt v = 
      Option.value_map v ~default:empty_field ~f:ident in {
      action; 
      insn  = of_opt insn; 
      left  = of_opt left; 
      right = of_opt right; 
    }
end

open Rule 
type rule = Rule.t

type trial = {
  regexp : Re.re;
  string : string;
}

type t = {
  insn_trial  : trial;
  left_trial  : trial;
  right_trial : trial;
}

type expect = trial array
type event = Trace.event
type res = (event option * event option) list

let make_trial s = {
  regexp = Re.compile (Re_posix.re s);
  string = s;
}

let create rule = {
  insn_trial = make_trial rule.insn;
  left_trial = make_trial rule.left;
  right_trial = make_trial rule.right;
}

let sat e ev = Re.execp e.regexp (Value.pps () ev)
let sat2 (e, ev) (e', ev') = sat e ev && sat e' ev'

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
          if sat2 (expect,workers.(i)) (expect', job) then 
            f (E.make p (V.Task j)))
    | V.Task j as t,Succ ->
      f @@ E.make t V.Sink
    | V.Task j as t,Pred ->
      Array.iteri workers ~f:(fun i worker ->
          if sat2 (expect, worker) (expect', jobs.(j)) then 
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

let single_source_match trial events =
  List.filter ~f:(sat trial) events

let is_empty_insn  t = is_empty_field t.insn_trial.string
let is_empty_left  t = is_empty_field t.left_trial.string
let is_empty_right t = is_empty_field t.right_trial.string
let is_sat_insn t insn = 
  not (is_empty_field t.insn_trial.string) && sat t.insn_trial insn

let match_events t insn events events' =
  match is_sat_insn t insn with
  | false -> []
  | true -> 
    match is_empty_left t, is_empty_right t with
    | true, _ ->
      single_source_match t.right_trial events' |>
      List.map ~f:(fun e -> None, Some e)
    | _, true -> 
      single_source_match t.left_trial events |>
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





