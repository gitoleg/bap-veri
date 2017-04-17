open Core_kernel.Std
open Bap.Std
open Bap_traces.Std

module SM = Monad.State
open SM.Monad_infix

type 'a u = 'a Bil.Result.u

module Disasm = struct
  module Dis = Disasm_expert.Basic
  open Dis
  type t = (asm, kinds) Dis.t
  type insn = Dis.full_insn

  let insn dis mem =
    match Dis.insn_of_mem dis mem with
    | Error er -> Error er
    | Ok r -> match r with
      | mem', Some insn, `finished -> Ok (mem',insn)
      | _, None, _ ->
        Or_error.error_string "nothing was disasmed"
      | _, _, `left _ ->
        Or_error.error_string "overloaded chunk"

  let insn_name = Dis.Insn.name
end


class context trace = object(self:'s)
  inherit Veri_traci.context trace as super

  val error : Veri_error.t option = None
  val insn  : Disasm.insn option = None
  val bil   : bil = []

  method notify_error er = {< error = er >}

  method update_insn s = match s with
    | Error er -> {< error = Some (`Disasm_error, er); insn = None; >}
    | Ok insn  -> {< error = None; insn = Some insn >}

  method update_bil b = match b with
    | Error er -> {< error = Some (`Unknown_sema, er); bil = [] >}
    | Ok bil   -> {< error = None; bil = bil >}

  method error = error
  method insn  = insn
  method bil   = bil
end

let lift_of_arch arch =
  let module Target = (val target_of_arch arch) in
  Target.lift

let memory_of_chunk endian chunk =
  Bigstring.of_string (Chunk.data chunk) |>
  Memory.create endian (Chunk.addr chunk)

class ['a] t arch dis =
  let endian = Arch.endian arch in
  let lift = lift_of_arch arch in

  object(self)
    constraint 'a = #context
    inherit ['a] Veri_traci.t arch as super

    method private eval_insn (mem, insn) =
      let bil = lift mem insn  in
      SM.update (fun c -> c#update_bil bil) >>= fun () ->
      SM.get () >>= fun c -> self#eval c#bil

    method! eval_exec chunk =
      let insn = Or_error.(
          memory_of_chunk endian chunk >>= fun mem ->
          Disasm.insn dis mem) in
      match insn with
      | Error _ as er -> SM.update (fun c -> c#update_insn er)
      | Ok ((mem, insn) as r) ->
        SM.update (fun c -> c#update_insn (Ok insn)) >>= fun () ->
        self#eval_insn r

end
