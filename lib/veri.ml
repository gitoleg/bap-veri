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

let insn_name = function
  | None -> None
  | Some insn -> Some (Dis.Insn.name insn)

module Events = Value.Set

type result = Veri_result.t

let update_dict dict tag x = match Dict.add dict tag x with
  | `Ok dict -> dict
  | `Duplicate -> dict

let make_result kind dict =
  let kind = (kind :> Veri_result.kind) in
  Veri_result.{kind; dict}

let add_unsound dict name results =
  let er = Error.of_string @@ sprintf "%s: unsound semantic" name in
  let dict = update_dict dict Veri_result.error er in
  update_dict dict Veri_result.diff results

let add_events dict real ours =
  let dict = update_dict dict Veri_result.real (Set.to_list real) in
  update_dict dict Veri_result.ours (Set.to_list ours)

class context policy trace = object(self:'s)
  inherit Veri_chunki.context trace as super

  val events = Events.empty
  val other : 's option = None
  val code : Chunk.t option = None
  val dict : dict = Dict.empty

  method cleanup =
    let s = {< other = None; dict = Dict.empty;
               events = Events.empty;  code = None; >} in
    s#drop_pc

  method update_result (r : result) = self
  method with_dict dict : 's = {< dict = dict >}

  method! update_insn insn =
    let self = super#update_insn insn in
    match self#insn with
    | None -> self
    | Some x ->
      self#with_dict @@
      update_dict dict Veri_result.insn (Insn.of_basic x)

  method merge =
    match self#error with
    | Some (kind, er) ->
      let self = self#with_dict @@
        update_dict dict Veri_result.error er in
      let self = self#update_result @@ make_result kind self#dict in
      self#cleanup
    | None -> match insn_name self#insn with
      | None -> self#cleanup
      | Some name ->
        let other = Option.value_exn self#other in
        let events, events' = other#events, self#events in
        let dict = add_events dict events events' in
        match Veri_policy.denied policy name events events' with
        | [] ->
          let self = self#with_dict dict in
          let self = self#update_result @@ make_result `Success dict in
          self#cleanup
        | results ->
          let self = self#with_dict (add_unsound dict name results) in
          let self = self#update_result @@ make_result `Unsound_sema self#dict in
          self#cleanup

  method discard_event: (event -> bool) -> 's = fun f ->
    match Set.find events ~f with
    | None -> self
    | Some ev -> {< events = Set.remove events ev >}

  method split =
    let s = {< other = Some self; events = Events.empty; >} in
    s#drop_pc

  method dict  = dict
  method code  = code
  method other = other
  method events  = events
  method register_event ev = {< events = Set.add events ev; >}
  method save s  = {< other = Some s >}
  method switch  = (Option.value_exn other)#save self
  method drop_pc = self#with_pc Bil.Bot
  method set_code c =
    let dict = update_dict dict Veri_result.bytes (Chunk.data c) in
    {< code = Some c; dict = dict >}

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
let same_var  var  mv = Var.name var  = Var.name (Move.cell mv)
let same_addr addr mv = addr = Move.cell mv

class ['a] t arch dis =
  let mem_var = mem_of_arch arch in

  object(self)
    constraint 'a = #context
    inherit ['a] Veri_chunki.t arch dis as super

    method private update_event ev =
      SM.update (fun c -> c#register_event ev)

    (** [resolve_var var] - returns a result, bound with [var].
        Sequence of searches is the following:
        1) among read events that occured at current step in the same context,
           with the same variable;
        2) among read events that occures at current step, in other context,
           with the same variable;
        3) in current context, for the same variable *)
    method private resolve_var : var -> 'a r = fun var ->
      SM.get () >>= fun ctxt ->
      match find_reg_read (self_events ctxt) (same_var var) with
      | Some mv -> self#eval_exp (Bil.int (Move.data mv))
      | None ->
        match find_reg_read (other_events ctxt) (same_var var) with
        | Some mv -> self#eval_exp (Bil.int (Move.data mv))
        | None -> super#lookup var

    (** [lookup var] - returns a result, bound with variable.
        Search starts from self events, if it was write access to given
        variable at current step. And if it was, then result of write
        access returned and no read event is emitted.
        Otherwise searching continues as written above for [resolve_var],
        with emitting register_read event. *)
    method! lookup var : 'a r =
      SM.get () >>= fun ctxt ->
      match find_reg_write (self_events ctxt) (same_var var) with
      | Some mv -> self#eval_exp (Bil.int (Move.data mv))
      | None ->
        self#resolve_var var >>= fun r ->
        match value r with
        | Bil.Imm data ->
          if not (Var.is_virtual var) then
            self#update_event (create_reg_read var data) >>= fun () ->
            SM.return r
          else SM.return r
        | Bil.Mem _ | Bil.Bot -> SM.return r

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

    method private store_and_load ~mem ~addr mv endian size =
      let data = Bil.int (Move.data mv) in
      super#eval_store ~mem ~addr data endian size >>= fun r ->
      match value r with
      | Bil.Mem _ -> super#update mem_var r >>= fun () ->
        super#eval_load ~mem ~addr endian size
      | Bil.Imm _ | Bil.Bot -> SM.return r

    (** [resolve_addr addr] - returns a result, bound with [addr].
        Sequence of searches is the following:
        1) among load events that occured at current step, in the same context,
           with the same address;
        2) among load events that occures at current step, in other context,
           with the same address;
        3) in current context. *)
    method private resolve_addr ~mem ~addr endian size =
      self#eval_exp addr >>= fun addr_res ->
      match value addr_res with
      | Bil.Bot | Bil.Mem _ -> SM.return addr_res
      | Bil.Imm addr' ->
        SM.get () >>= fun ctxt ->
        match find_mem_load (self_events ctxt) (same_addr addr') with
        | Some mv -> self#store_and_load ~mem ~addr mv endian size
        | None ->
          match find_mem_load (other_events ctxt) (same_addr addr') with
          | None -> super#eval_load ~mem ~addr endian size
          | Some mv -> self#store_and_load ~mem ~addr mv endian size

    (** [eval_load ~mem ~addr endian size] - returns a result bound with [addr].
        Search starts from self events, if it was write access to given
        address at current step. And if it was, then result of write access
        returned and no load event is emitted.
        Otherwise searching continues as written above for [resolve_addr],
        with emitting memory load event. *)
    method! eval_load ~mem ~addr endian size =
      SM.get () >>= fun ctxt ->
      self#eval_exp addr >>= fun addr_res ->
      match value addr_res with
      | Bil.Bot | Bil.Mem _ -> SM.return addr_res
      | Bil.Imm addr' ->
        match find_mem_store (self_events ctxt) (same_addr addr') with
        | Some mv -> self#eval_exp (Bil.int (Move.data mv))
        | None ->
          self#resolve_addr mem addr endian size >>= fun r ->
          match value addr_res, value r with
          | Bil.Imm addr, Bil.Imm data ->
            self#update_event (create_mem_load addr data) >>= fun () ->
            SM.return r
          | _ ->  SM.return r

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
