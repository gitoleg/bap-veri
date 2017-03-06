open Core_kernel.Std
open Bap.Std


module Collect = struct
  type t = int Insn.Map.t [@@deriving bin_io, compare, sexp]

  let pp fmt t = Map.iteri
      ~f:(fun ~key ~data ->
           Format.fprintf fmt "%a : %d;\n"
             Insn.pp key data) t

  let empty = Insn.Map.empty

  let uniques t = Map.length t

  let number t =
    Map.fold t ~init:0 ~f:(fun ~key ~data acc -> acc + data)

  let merge first second  =
    Map.fold ~init:first second
      ~f:(fun ~key ~data res ->
          Map.change res key ~f:(function
              | None -> Some data
              | Some data' -> Some (data + data')))

  let add map = function
    | None -> map
    | Some insn ->
      Map.change map insn ~f:(function
          | None -> Some 1
          | Some n -> Some (n + 1))

end

let incr _ _ cnt = cnt + 1

let add dict index acc =
  match Dict.find dict Veri_result.insn with
  | None -> acc
  | Some insn ->
    Map.change acc insn ~f:(function
        | None -> Some 1
        | Some cnt -> Some (cnt + 1))

let total = Value.Tag.register ~name:"total insns"
    ~uuid:"abd5bf07-6b06-4cc9-92d9-96b527870347"
    (module Int)

let sucs = Value.Tag.register ~name:"success case"
    ~uuid:"fa5f178c-4da1-4b0f-b061-e2e8f5d97e57"
    (module Collect)

let unsound =
  Value.Tag.register ~name:"unsound semantic case"
    ~uuid:"460c3894-e27c-4b91-a07a-6a0d02201bcd"
    (module Collect)

let unknown =
  Value.Tag.register ~name:"unknown semantic case"
    ~uuid:"464227e3-e101-4154-b4e1-361bd45a215b"
    (module Collect)

let undisas =
  Value.Tag.register ~name:"undisasmed insn case"
    ~uuid:"95b23a1b-b021-4e77-b293-66e15474ce39"
    (module Int)

module T = Veri_info.Test_case

let init = Collect.empty

let test_cases = [|
  T.success add ~init sucs;
  T.unsound_sema add ~init unsound;
  T.unknown_sema add ~init unknown;
  T.disasm_error incr ~init:0 undisas;
  T.custom incr ~init:0 total;
|]


type col = Collect.t

type t = {
  success  : col;
  unsound  : col;
  unknown  : col;
  undisas  : int;
}

module Q = struct

  type query = Veri_result.kind
  type insn_query = [ Veri_result.success | Veri_result.sema_error]
  type int_query = [`Total_number | query]

  let number = Collect.number

  let total t =
    number t.success + number t.unsound + number t.unknown + t.undisas

  let abs t = function
    | `Total_number -> total t
    | `Disasm_error -> t.undisas
    | `Unsound_sema -> number t.unsound
    | `Unknown_sema -> number t.unknown
    | `Success      -> number t.success

  let relat t kind =
    float (abs t kind) /. float (total t)

  let insn t insn kind =
    let f m = match Map.find m insn with
      | None -> 0
      | Some x -> x in
    match kind with
    | `Unsound_sema -> f t.unsound
    | `Unknown_sema -> f t.unknown
    | `Success -> f t.success

  let insns t = function
    | `Unsound_sema -> Map.keys t.unsound
    | `Unknown_sema -> Map.keys t.unknown
    | `Success -> Map.keys t.success

  let insnsi t = function
    | `Unsound_sema -> Map.to_alist t.unsound
    | `Unknown_sema -> Map.to_alist t.unknown
    | `Success -> Map.to_alist t.success

end

let empty = {
  success = Collect.empty;
  unsound = Collect.empty;
  unknown = Collect.empty;
  undisas = 0;
}

let merge x y = {
  undisas = x.undisas + y.undisas;
  success = Collect.merge x.success y.success;
  unsound = Collect.merge x.unsound y.unsound;
  unknown = Collect.merge x.unknown y.unknown;
}

let add s res =
  let insn = Dict.find res.Veri_result.dict Veri_result.insn in
  match res.Veri_result.kind with
  | `Success -> {s with success = Collect.add s.success insn}
  | `Disasm_error -> {s with undisas = s.undisas + 1}
  | `Unknown_sema -> {s with unknown = Collect.add s.unknown insn}
  | `Unsound_sema -> {s with unsound = Collect.add s.unsound insn}

let run trace policy =
  match T.eval trace policy test_cases with
  | Error _ as r -> r
  | Ok values ->
    let get tag n = Value.get_exn tag values.(n) in
    Ok
      {success = get sucs 0;
       unsound = get unsound 1;
       unknown = get unknown 2;
       undisas = get undisas 3;}