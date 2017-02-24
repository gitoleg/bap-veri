open Core_kernel.Std
open Bap.Std
open Bap_traces.Std

module SM = Monad.State
open SM.Monad_infix

type error = Veri_result.error
type 'a u = 'a Bil.Result.u

let unknown_semantic name er =
  `Unknown_sema, (er, [`Name name;])

let disasm_error er = `Disasm_error, (er, [])

module Disasm = struct
  module Dis = Disasm_expert.Basic
  open Dis
  type t = (asm, kinds) Dis.t
  type insn = Dis.full_insn

  let insn dis mem =
    (match Dis.insn_of_mem dis mem with
     | Error er -> Error er
     | Ok r -> match r with
       | mem', Some insn, `finished -> Ok (mem',insn)
       | _, None, _ ->
         Or_error.error_string "nothing was disasmed"
       | _, _, `left _ ->
         Or_error.error_string "overloaded chunk") |> function
    | Ok r -> Ok r
    | Error er -> Error (disasm_error er)

  let insn_name = Dis.Insn.name
end

class context trace = object(self:'s)
  inherit Veri_traci.context trace as super

  val error : error option = None
  val insn  : Disasm.insn option = None
  val bil   : bil = []

  method notify_error er = {< error = er >}
  method update_insn s = {< insn = s >}
  method update_bil  b = {< bil = b >}
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
      let name = Disasm.insn_name insn in
      SM.update (fun c -> c#update_insn (Some insn)) >>= fun () ->
      match lift mem insn with
      | Error er ->
        SM.update (fun c ->
            c#notify_error @@ Some (unknown_semantic name er))
      | Ok bil ->
        SM.update (fun c -> c#update_bil bil) >>= fun () ->
        self#eval bil

    method! eval_exec chunk =
      match memory_of_chunk endian chunk with
      | Error er ->
        SM.update (fun c -> c#notify_error @@ Some (disasm_error er))
      | Ok mem ->
        match Disasm.insn dis mem with
        | Error er -> SM.update (fun c -> c#notify_error @@ Some er)
        | Ok insn -> self#eval_insn insn

end
