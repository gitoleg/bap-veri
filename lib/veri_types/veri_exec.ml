open Core_kernel.Std
open Bap.Std
open Bap_traces.Std
open Bap_future.Std


module Dis = Disasm_expert.Basic

module SM = Monad.State
open SM.Monad_infix

type event = Trace.event [@@deriving bin_io, compare, sexp]
type 'a u = 'a Bil.Result.u
type 'a r = 'a Bil.Result.r
type 'a e = (event option, 'a) SM.t

let unsound_semantic name results  =
  let er = Error.of_string (sprintf "%s: unsound semantic" name) in
  `Unsound_sema, (er, [`Name name; `Diff results])

let create_move_event tag cell' data' =
  Value.create tag Move.({cell = cell'; data = data';})

let find tag evs cond =
  let open Option in
  List.find evs ~f:(fun ev -> match Value.get tag ev with
      | None -> false
      | Some mv -> cond mv) >>| fun ev -> Value.get_exn tag ev

let create_mem_store = create_move_event Event.memory_store
let create_mem_load  = create_move_event Event.memory_load
let create_reg_read  = create_move_event Event.register_read
let create_reg_write = create_move_event Event.register_write
let find_reg_read  = find Event.register_read
let find_reg_write = find Event.register_write
let find_mem_load  = find Event.memory_load
let find_mem_store = find Event.memory_store
let value = Bil.Result.value

module Events = Value.Set

type diff = Veri_policy.result list
[@@deriving bin_io, compare, sexp]

module Diff = struct
  type t = diff [@@deriving bin_io, compare, sexp]
  let ppr fmt (r, m) =
    Format.fprintf fmt "%a:%a\n" Veri_rule.pp r
      Veri_policy.Matched.pp m
  let pp fmt rs = List.iter ~f:(ppr fmt) rs
end


let bytes = Value.Tag.register ~name:"bytes"
    ~uuid:"3e02c0e1-6eab-41af-843c-aaf702a942d6"
    (module String)

let error = Value.Tag.register ~name:"error"
    ~uuid:"9189054d-6e7c-480e-8a92-a211440bc134"
    (module Veri_error)

let insn = Value.Tag.register ~name:"instruction"
    ~uuid:"e0e96dd9-204c-4a5b-bdff-d54de9d2e725"
    (module Insn)

let index = Value.Tag.register ~name:"index"
    ~uuid:"e42f59d5-ea60-47b9-98c2-a8de9d2e10b3"
    (module Int)

let diff = Value.Tag.register ~name:"diff"
    ~uuid:"42713daf-7226-4330-9363-9ef8729dcb85"
    (module Diff)

let addr = Value.Tag.register ~name:"insn address"
    ~uuid:"c1bc450a-a435-4181-bcaf-9cbdf222757c"
    (module Addr)


module Info = struct
  type t = {
    real : event list;
    ours : event list;
    veri : event list;
  }

  let create real ours veri = {real; ours; veri}
  let get t tag = List.find_map ~f:(Value.get tag) t.veri
  let get_exn t tag = Option.value_exn (List.find_map ~f:(Value.get tag) t.veri)
  let addr t = get_exn t addr
  let insn t = get t insn
  let real t = t.real
  let ours t = t.ours
  let diff t = Option.value_map ~default:[] ~f:ident (get t diff)
  let index t = get_exn t index
  let bytes t = get_exn t bytes
  let error t = get t error
end

let add_event tag v evs = Value.create tag v :: evs

let add_unsound evs name diff_res =
  let er = Error.of_string @@ sprintf "%s: unsound semantic" name in
  add_event error (`Unsound_sema, er) evs |>
  add_event diff diff_res

let add_insn evs bil = function
  | None -> evs
  | Some x ->
    add_event insn (Insn.of_basic ~bil x) evs

class context policy trace = object(self:'s)
  inherit Veri_chunki.context trace as super

  val events = Events.empty
  val other : 's option = None
  val code : Chunk.t option = None
  val veri_events : value list = []
  val info_stream = Stream.create ()
  val finish = Future.create ()
  val mutable finished = false
  val pos = 0

  method! next_event =
    let next = super#next_event in
    if next = None then finished <- true;
    next

  method cleanup =
    let s = {< other = None; veri_events = []; pos = pos + 1;
               events = Events.empty;  code = None; >} in
    s#drop_pc

  method merge =
    let other = Option.value_exn self#other in
    let veri_events = add_insn veri_events self#bil self#insn in
    let veri_events = add_event index pos veri_events in
    let real = other#events in
    let ours = self#events in
    let veri = match self#error with
      | Some er ->
        Value.create error er :: veri_events
      | None -> match self#insn with
        | None -> veri_events
        | Some insn ->
          let name = Dis.Insn.name insn in
          match Veri_policy.denied policy name real ours with
          | [] -> veri_events
          | diff -> add_unsound veri_events name diff in
    let i = Info.create (Set.to_list real) (Set.to_list ours) veri in
    Signal.send (snd info_stream) i;
    if finished then
      Promise.fulfill (snd finish) ();
    self#cleanup

  method discard_event: (event -> bool) -> 's = fun f ->
    let fneg x = not (f x) in
    {< events = Set.filter events ~f:fneg >}

  method split =
    let s = {< other = Some self; events = Events.empty; >} in
    s#drop_pc

  method info = fst info_stream, fst finish
  method code  = code
  method other = other
  method events  = events
  method register_event ev = {< events = Set.add events ev; >}
  method save s  = {< other = Some s >}
  method switch  = (Option.value_exn other)#save self
  method drop_pc = self#with_pc Bil.Bot
  method set_code c =
    let evs = add_event addr (Chunk.addr c) veri_events |>
              add_event bytes (Chunk.data c) in
    {< code = Some c; veri_events = evs; >}

end

let mem_of_arch arch =
  let module Target = (val target_of_arch arch) in
  Target.CPU.mem

let other_events c = match c#other with
  | None -> []
  | Some c -> Set.to_list c#events

let is_previous_mv tag test ev =
  match Value.get tag ev with
  | None -> false
  | Some mv -> Move.cell mv = test

let is_previous_write = is_previous_mv Event.register_write
let is_previous_store = is_previous_mv Event.memory_store
let self_events c = Set.to_list c#events
let same_var  var  mv = Var.name var = Var.name (Move.cell mv)
let same_addr addr mv = addr = Move.cell mv

let find_move_data probes =
  List.find_map probes ~f:(fun (probe, x) -> match probe () with
      | None -> None
      | Some mv -> Some (Move.data mv, x))

class ['a] t arch dis = object(self)

  constraint 'a = #context
  inherit ['a] Veri_chunki.t arch dis as super

  method private update_event ev =
    SM.update (fun c -> c#register_event ev)

  (** [find_var_data var] - returns a result, bound with [var].
      Sequence of searches is the following:
      1) among write events that occured at current step in the same context,
         with the same variable; we don't need to emit event in this case
      2) among read events that occured at current step in the same context,
         with the same variable; will emit register read in this case
      3) among read events that occures at current step, in other context,
         with the same variable; will emit register read in this case *)
  method private find_var_data var =
    SM.get () >>= fun ctxt ->
    let searches = [
      (fun () -> find_reg_write (self_events ctxt)  (same_var var)), false;
      (fun () -> find_reg_read  (self_events ctxt)  (same_var var)), true;
      (fun () -> find_reg_read  (other_events ctxt) (same_var var)), true;
    ] in
    SM.return (find_move_data searches)

  method! lookup var : 'a r =
    SM.get () >>= fun ctxt ->
    self#find_var_data var >>= function
    | None -> super#lookup var
    | Some (data, need_emit) ->
      self#eval_exp (Bil.int data) >>= fun r ->
      if not (Var.is_virtual var) && need_emit then
        self#update_event (create_reg_read var data) >>= fun () ->
        SM.return r
      else SM.return r

  method! update var result : 'a u =
    super#update var result >>= fun () ->
    match value result with
    | Bil.Imm data ->
      if not (Var.is_virtual var) then
        SM.update (fun c -> c#discard_event (is_previous_write var)) >>= fun () ->
        self#update_event (create_reg_write var data)
      else SM.return ()
    | Bil.Mem _ | Bil.Bot -> SM.return ()

  method! eval_store ~mem ~addr data endian size =
    super#eval_store ~mem ~addr data endian size >>= fun r ->
    self#eval_exp addr >>= fun addr ->
    self#eval_exp data >>= fun data ->
    match value addr, value data with
    | Bil.Imm addr, Bil.Imm data ->
      SM.update (fun c -> c#discard_event (is_previous_store addr)) >>= fun () ->
      let ev = create_mem_store addr data in
      self#update_event ev >>= fun () -> SM.return r
    | _ -> SM.return r

  (** [find_addr_data addr] - returns a move data, bound with [addr].
      Sequence of searches is the following:
      1) among store events that occured at current step, in the same context,
         with the same address; we don't need to emit event in this case
      2) among load events that occured at current step, in the same context,
         with the same address; will emit memory_load event
      3) among load events that occures at current step, in other context,
         with the same address; will emit memory_load event *)
  method private find_addr_data addr =
    SM.get () >>= fun ctxt ->
    let searches = [
      (fun () -> find_mem_store (self_events ctxt)  (same_addr addr)), false;
      (fun () -> find_mem_load  (self_events ctxt)  (same_addr addr)), true;
      (fun () -> find_mem_load  (other_events ctxt) (same_addr addr)), true;
    ] in
    SM.return (find_move_data searches)

  method! eval_load ~mem ~addr endian size =
    SM.get () >>= fun ctxt ->
    self#eval_exp addr >>= fun addr_res ->
    match value addr_res with
    | Bil.Bot | Bil.Mem _ -> super#eval_load ~mem ~addr endian size
    | Bil.Imm addr' ->
      self#find_addr_data addr' >>= function
      | None ->
        begin
          super#eval_load ~mem ~addr endian size >>= fun r ->
          match value r with
          | Bil.Imm data ->
            self#update_event (create_mem_load addr' data) >>= fun () ->
            SM.return r
          | _ -> SM.return r
        end
      | Some (data, need_emit) ->
        super#eval_store ~mem ~addr (Bil.int data) endian size >>= fun _ ->
        super#eval_load ~mem ~addr endian size >>= fun r ->
        if need_emit then
          self#update_event (create_mem_load addr' data) >>= fun () ->
          SM.return r
        else SM.return r

  method private add_pc_update =
    SM.get () >>= fun ctxt ->
    match ctxt#pc with
    | Bil.Mem _ | Bil.Bot -> SM.return ()
    | Bil.Imm pc ->
      let pc_ev = Value.create Event.pc_update pc in
      self#update_event pc_ev

  method! eval_jmp addr : 'a u =
    super#eval_jmp addr >>= fun () ->
    self#add_pc_update >>= fun () ->
    SM.update (fun c -> c#switch) >>= fun () ->
    self#add_pc_update >>= fun () ->
    SM.update (fun c -> c#switch)

  method! eval_exec chunk =
    super#eval_exec chunk >>= fun () ->
    self#update_event (Value.create Event.pc_update (Chunk.addr chunk))

  method! eval_event ev =
    Value.Match.(
      select @@
      case Event.code_exec (fun code ->
          SM.update (fun c -> c#set_code code)) @@
      case Event.pc_update (fun addr ->
          self#eval_pc_update addr >>= fun () ->
          self#verify_frame >>= fun () ->
          self#update_event ev) @@
      case Event.memory_store (fun mv ->
          self#eval_memory_store mv) @@
      case Event.memory_load (fun mv ->
          SM.get () >>= fun c ->
          let is_new e = not (Set.mem c#events e) in
          self#eval_memory_store mv  >>= fun _ ->
          SM.update (fun c -> c#discard_event is_new) >>= fun () ->
          self#eval_memory_load mv) @@
      default (fun () -> self#update_event ev)) ev

  method private verify_frame : 'a u =
    SM.get () >>= fun ctxt ->
    match ctxt#code with
    | None -> SM.return ()
    | Some code ->
      SM.update (fun c -> c#split) >>= fun () ->
      self#eval_exec code       >>= fun () ->
      SM.update (fun c -> c#merge)

  method! eval_trace trace =
    super#eval_trace trace >>= fun () -> self#verify_frame

end
