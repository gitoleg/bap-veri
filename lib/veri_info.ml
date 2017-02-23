open Core_kernel.Std
open Bap.Std
open Regular.Std

module SM = Monad.State

module Insn_info = struct

  type e =
    | Full of Insn.t
    | Raw of string
  [@@deriving bin_io, sexp]

  type t = int * e [@@deriving bin_io, sexp]

  let make =
    let i = ref 0 in
    fun insn ->
      let r = !i, insn in
      incr i;
      r

  let of_bytes s = make (Raw s)
  let of_instr i = make (Full i)
  let to_instr (_,i) = match i with | Full i -> Some i | _ -> None
  let to_bytes (_,i) = match i with | Raw i -> Some i | _ -> None
  let index = fst

  include Regular.Make(struct
      type nonrec t = t [@@deriving bin_io, sexp]

      let compare = compare
      let hash = Hashtbl.hash
      let module_name = Some "Veri_info"
      let version = "0.1"
      let pp fmt t = ()
    end)

end

type insn_info = Insn_info.t
type 'a freq = ('a, int) Hashtbl.t

module type S = sig
  type t
  val freq : t -> insn_info freq
  val feed : t -> insn_info -> t
end

module Static = struct
  type t
  let of_path path = failwith "unimplemented"
  let freq t = failwith "unimplemented"
end

module Frequency = struct
  type 'a t = 'a freq

  let all t = Hashtbl.to_alist t
  let count ~f t = Hashtbl.count ~f t

end

module Dis = Disasm_expert.Basic

let abstract_of_trace policy arch trace =
  let open Or_error in
  Dis.create ~backend:"llvm" (Arch.to_string arch) >>= fun dis ->
  let dis = Dis.store_asm dis |> Dis.store_kinds in
  let ctxt = new Veri.context policy trace in
  let veri = new Veri.t arch dis in
  let ctxt' = Monad.State.exec (veri#eval_trace trace) ctxt in
  Ok ()



module Insn_freq = struct

  type t = int Insn.Map.t

  let create () = Insn.Map.empty

  let feed t insn =
    Map.change t insn
      (function
        | None -> Some 1
        | Some cnt -> Some (cnt + 1))

end


module Binary = struct

  open SM.Monad_infix

  type 'a u = 'a Bil.Result.u

  type elt = mem * insn
  type s = elt seq


  (** is it realy a good idea to use dis type here ??  *)
  class base_context dis = object (self : 'a)

    val insns = Disasm.insns dis

    method next_insn = match Seq.next insns with
      | None -> None
      | Some (insn, insns) -> Some ({< insns = insns; >}, insn)

    method with_dis dis = {< insns = Disasm.insns dis >}

  end

  class ['a] base_t = object (self)

    method eval_insn (insn : mem * Insn.t) : unit u = SM.return ()

    method eval_dis (dis : Disasm.t) : 'a u =
      SM.update (fun ctxt -> ctxt#with_dis dis) >>= fun () -> self#run

    method private run : 'a u =
      SM.get () >>= fun ctxt ->
      match ctxt#next_insn with
      | None -> SM.return ()
      | Some (ctxt, insn) ->
        SM.put ctxt >>= fun () -> self#eval_insn insn >>= fun () -> self#run
  end


  class context dis = object(self : 's)
    inherit base_context dis as super

    val insn_freq : Insn_freq.t = Insn_freq.create ()

    method add_insn insn =
      {< insn_freq = Insn_freq.feed insn_freq insn >}

  end

  class ['a] t = object (self)
    constraint 'a = #base_context
    inherit ['a] base_t as super

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

    method! set_insn insn : 's =
      let s = super#set_insn insn in
      match insn with
      | None -> s
      | Some insn ->
        let insn = Insn.of_basic insn in
        Queue.enqueue queue insn;
        {< insns = Insn_freq.feed insns insn >}

  end

  class ['a] t = ['a] Veri_chunki.t

end


module Errors = struct
  type t
  type kind = [ `Disasm | `Soundness | `Incompleteness ]
  let get t kind = failwith "unimplemented"
  let feed insn error kind = failwith "unimplemented"
end
