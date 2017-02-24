open Core_kernel.Std
open Bap.Std
open Bap_traces.Std

module SM = Monad.State
module Dis = Disasm_expert.Basic

module Insn_freq = struct

  (** TODO: consider a hash table here *)
  type t = int Insn.Map.t

  let create () = Insn.Map.empty

  let feed t insn =
    Map.change t insn
      (function
        | None -> Some 1
        | Some cnt -> Some (cnt + 1))

  (** TODO : remove this  *)
  let length t = Map.length t

  (** TODO : remove this  *)
  let number t =
    Map.fold ~f:(fun ~key ~data num -> num + data) ~init:0 t

  (** TODO : remove this  *)
  let print t =
    printf "length is %d; number is %d\n" (length t) (number t)

end

module Error = struct
  open Or_error

  type result = Veri_result.t

  module Test_case = struct
    type kind = Veri_result.result_kind

    type error = Veri_result.error

    type 'a descr = {
      func : result -> int -> 'a -> 'a;
      init : 'a;
      tag  : 'a tag;
    }

    type t = | Case : 'a descr -> t

    type 'a success_test = int -> 'a -> 'a
    type 'a error_test  = Veri_result.error_info -> int -> 'a -> 'a

    let create func ~init tag = Case {func; init; tag; }

    let apply res num = function
      | Case descr ->
        let init = descr.func res num descr.init in
        let descr = {descr with init} in
        Case descr

    let extract case = match case with
      | Case descr -> Value.create descr.tag descr.init

    let application_error from k =
      let s = Sexp.to_string (Veri_result.sexp_of_result_kind k) in
      eprintf "aplication error while applying %s to %s\n" from s;
      exit 1

    let kind_of_result : result -> kind = fun r ->
      let kind = match r with
        | `Success as k -> k
        | `Error (k, _) -> (k :> kind) in
      kind

    let success f ~init tag =
      let checked res num init =
        match res with
        | `Success -> f num init
        | `Error _ -> init in
      create checked init tag

    let checked_err must_kind f init tag =
      let checked res num init = match res with
        | `Error (kind, info) when kind = must_kind ->
          f info num init
        | _ -> init in
      create checked init tag

    let unsound_sema f ~init tag = checked_err `Unsound_sema f init tag
    let unknown_sema f ~init tag = checked_err `Unknown_sema f init tag
    let disasm_error f ~init tag = checked_err `Disasm_error f init tag
    let custom = create
  end

  type case = Test_case.t
  type policy = Veri_policy.t

  class context policy trace cases =
    object (self : 's)
      inherit Veri.context policy trace as super

      val num = 0
      val cases : case array = cases

      method increment = {< num = num + 1 >}
      method apply res =
        let cases =
          Array.map ~f:(Test_case.apply res num) cases in
        {< cases = cases >}

      method! update_result res =
        let self = super#update_result res in
        let self = self#apply res in
        self#increment

      method result = cases
    end

  let arch_of_trace trace =
    match Dict.find (Trace.meta trace) Meta.arch with
    | None -> Or_error.error_string "trace of unknown arch"
    | Some arch -> Ok arch

  let eval trace policy cases =
    arch_of_trace trace >>= fun arch ->
    Dis.with_disasm ~backend:"llvm" (Arch.to_string arch) ~f:(fun dis ->
        let dis = Dis.store_asm dis |> Dis.store_kinds in
        let ctxt = new context policy trace cases in
        let veri = new Veri.t arch dis in
        let ctxt' = Monad.State.exec (veri#eval_trace trace) ctxt in
        Ok ctxt'#result) >>= fun cases ->
    Ok (Array.map ~f:Test_case.extract cases)

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

  class context trace = object(self : 's)
    inherit Veri_chunki.context trace as super

    val insns : Insn_freq.t = Insn_freq.create ()
    val queue : Insn.t Queue.t = Queue.create ()

    method! update_insn insn : 's =
      let s = super#update_insn insn in
      match insn with
      | None -> s
      | Some insn ->
        let insn = Insn.of_basic insn in
        Queue.enqueue queue insn;
        {< insns = Insn_freq.feed insns insn >}

    method freq = insns
    method order = Queue.to_list queue
  end

end
