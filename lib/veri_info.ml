open Core_kernel.Std
open Bap.Std
open Bap_traces.Std

module SM = Monad.State
module Dis = Disasm_expert.Basic

module Insn_freq = struct

  type t = int Insn.Map.t

  let create () = Insn.Map.empty
  let insns : t -> int Insn.Map.t = fun t -> t

  let feed t insn =
    Map.change t insn
      (function
        | None -> Some 1
        | Some cnt -> Some (cnt + 1))
end

type insn_freq = Insn_freq.t

let arch_of_trace trace =
  match Dict.find (Trace.meta trace) Meta.arch with
  | None -> Or_error.error_string "trace of unknown arch"
  | Some arch -> Ok arch

module Test_case = struct
  type 'a descr = {
    func : Veri_result.t -> int -> 'a -> 'a;
    init : 'a;
    tag  : 'a tag;
  }
  type t = | Case : 'a descr -> t
  type 'a test  = dict -> int -> 'a -> 'a

  let create func ~init tag = Case {func; init; tag; }

  let call res num = function
    | Case descr ->
      let init = descr.func res num descr.init in
      let descr = {descr with init} in
      Case descr

  let extract case = match case with
    | Case descr -> Value.create descr.tag descr.init

  let success f ~init tag =
    let checked res num init =
      match Veri_result.(res.kind) with
      | `Success -> f Veri_result.(res.dict) num init
      |  _ -> init in
    create checked init tag

  let checked_err must_kind f init tag =
    let checked res num init = match Veri_result.(res.kind) with
      | #Veri_result.error_kind as er_kind when er_kind = must_kind ->
        f Veri_result.(res.dict) num init
      | _ -> init in
    create checked init tag

  let unsound_sema f ~init tag = checked_err `Unsound_sema f init tag
  let unknown_sema f ~init tag = checked_err `Unknown_sema f init tag
  let disasm_error f ~init tag = checked_err `Disasm_error f init tag
  let custom = create

  class ['a] context policy trace f init =
    object (self : 's)
      inherit Veri.context policy trace as super

      val num = 0
      val acc : 'a = init

      method increment = {< num = num + 1 >}
      method result = acc
      method apply res = {< acc = f acc res num >}

      method! update_result res =
        let self = super#update_result res in
        let self = self#apply res in
        self#increment
    end

  let foldi trace policy ~init ~f =
    let open Or_error in
    arch_of_trace trace >>= fun arch ->
    Dis.with_disasm ~backend:"llvm" (Arch.to_string arch) ~f:(fun dis ->
        let dis = Dis.store_asm dis |> Dis.store_kinds in
        let ctxt = new context policy trace f init in
        let veri = new Veri.t arch dis in
        let ctxt' = Monad.State.exec (veri#eval_trace trace) ctxt in
        Ok ctxt'#result)

  let eval trace policy cases =
    let open Or_error in
    let f cases res num = Array.map ~f:(call res num) cases in
    foldi trace policy ~init:cases ~f >>= fun cases ->
    Ok (Array.map ~f:extract cases)

  let iteri trace policy ~f =
    let f () = f in
    foldi trace policy ~init:() ~f

  let fold trace policy ~init ~f =
    let f c r i = f c r in
    foldi trace policy ~init ~f

  let iter trace policy ~f =
    let f r i = f r in
    iteri trace policy ~f

end

module Binary = struct
  open SM.Monad_infix

  type 'a u = 'a Bil.Result.u
  type insns = insn seq

  module Base = struct

    class context insns = object (self : 's)
      val insns : insn seq = insns

      method next_insn = match Seq.next insns with
        | None -> None
        | Some (insn, insns) -> Some ({< insns = insns; >}, insn)

      method with_insns insns : 's = {< insns = insns >}
    end

    class ['a] t = object (self)
      constraint 'a = #context

      method eval_insn (insn : Insn.t) : 'a u = SM.return ()

      method eval_insns insns =
        SM.update (fun ctxt -> ctxt#with_insns insns) >>= fun () -> self#run

      method private run : 'a u =
        SM.get () >>= fun ctxt ->
        match ctxt#next_insn with
        | None -> SM.return ()
        | Some (ctxt, insn) ->
          SM.put ctxt >>= fun () -> self#eval_insn insn >>= fun () -> self#run
    end
  end

  class context insn = object(self : 's)
    inherit Base.context insn as super

    val insn_freq : Insn_freq.t = Insn_freq.create ()

    method add_insn insn =
      {< insn_freq = Insn_freq.feed insn_freq insn >}

    method freq = insn_freq
  end

  class ['a] t = object (self)
    constraint 'a = #context
    inherit ['a] Base.t as super

    method! eval_insn insn =
      super#eval_insn insn >>= fun () ->
      SM.update (fun c -> c#add_insn insn)

  end
end


module Trace = struct

  type order = insn Queue.t

  class ['a] context trace fn init = object(self : 's)
    inherit Veri_chunki.context trace as super

    val acc : 'a = init
    val cnt = 0

    method update_counter = {< cnt = cnt + 1 >}
    method update_acc acc = {< acc = acc >}
    method acc = acc

    method! update_insn insn : 's =
      let self = super#update_insn insn in
      match self#insn with
      | None -> self#update_counter
      | Some insn ->
        let insn = Insn.of_basic insn in
        let acc = fn acc cnt insn in
        let self = self#update_counter in
        self#update_acc acc

  end

  let fold trace ~init ~f =
    match arch_of_trace trace with
    | Error _ as er -> er
    | Ok arch ->
      Dis.with_disasm ~backend:"llvm" (Arch.to_string arch) ~f:(fun dis ->
          let dis = Dis.store_asm dis |> Dis.store_kinds in
          let ctxt = new context trace f init in
          let chunki = new Veri_chunki.t arch dis in
          let ctxt = Monad.State.exec (chunki#eval_trace trace) ctxt in
        Ok ctxt#acc)

  let info trace =
    let order = Queue.create () in
    let freqs = Insn_freq.create () in
    let f (order, freq) cnt insn =
      Queue.enqueue order insn;
      let freq = Insn_freq.feed freq insn in
      order,freq in
    fold trace ~init:(order, freqs) ~f

end
