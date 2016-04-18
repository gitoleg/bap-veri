open Core_kernel.Std
open Graph
open Bap.Std
open Bap_traces.Std

module Action = struct
  type t = string
  let of_string = ident
  let is act act' = String.compare act act' = 0
end

module Field = struct
  type t = string
  let of_string = ident
  let empty = ""
  let is_empty x = x = empty
end

type field = Field.t
type action = Action.t

let skip = Action.of_string "SKIP"
let deny = Action.of_string "DENY"
let is_skip = Action.is skip
let is_deny = Action.is deny

type trial = {
  regexp : Re.re;
  field  : Field.t
}

type t = {
  action : action;
  insn   : trial;
  left   : trial;
  right  : trial;
} [@@deriving fields]

let make_trial s = 
  let field = match s with 
    | None -> Field.empty
    | Some s -> s in {
    regexp = Re.compile (Re_posix.re field);
    field;
  }

let create ?insn ?left ?right action : t = {
  action; 
  insn  = make_trial insn; 
  left  = make_trial left; 
  right = make_trial right; 
}

type event = Trace.event
type events = Value.Set.t

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
  List.filter ~f:(sat_event trial) (Set.to_list events)

let is_empty_insn  t = Field.is_empty t.insn.field
let is_empty_left  t = Field.is_empty t.left.field
let is_empty_right t = Field.is_empty t.right.field
let is_sat_insn t insn = not (is_empty_insn t) && sat t.insn insn

let match_events t insn events events' =
  match is_sat_insn t insn with
  | false -> []
  | true -> 
    match is_empty_left t, is_empty_right t with
    | true, _ ->
      single_match t.right events' |>
      List.map ~f:(fun e -> None, Some e)
    | _, true -> 
      single_match t.left events |>
      List.map ~f:(fun e -> Some e, None)
    | _ -> 
      let workers = t.left, Set.to_array events in      
      let jobs = t.right, Set.to_array events' in
      let (flow,_) = FFMF.maxflow (workers, jobs) G.V.Source G.V.Sink  in
      Array.foldi (snd workers) ~init:[] 
        ~f:(fun i acc w ->   
            match Array.findi (snd jobs) ~f:(fun j e ->
                flow (G.E.make (G.V.Person i) (G.V.Task j)) <> 0) with
            | None -> acc 
            | Some (_,e) -> (Some w, Some e) :: acc)  


type deny_error = events * events
type r = (events * events, deny_error) Result.t

let remove what from = 
  List.fold_left ~init:from ~f:Set.remove what

let process t insn events events' : r = 
  match match_events t insn events events' with 
  | [] -> Ok (events, events')
  | res ->
    let evs, evs' = List.fold_left ~init:([],[]) res
        ~f:(fun (evs, evs')  -> function
            | Some e, Some e' -> e :: evs, e' :: evs'
            | Some e, None -> e :: evs, evs'
            | None, Some e' -> evs, e' :: evs'
            | None, None -> evs, evs') in
  if is_skip t.action then
    let events = remove evs events in
    let events' = remove evs' events' in
    Ok (events, events')
  else
    Error (Value.Set.of_list evs, Value.Set.of_list evs')

    
