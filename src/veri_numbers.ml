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

let undisasm =
  Value.Tag.register ~name:"undisasmed insn case"
    ~uuid:"95b23a1b-b021-4e77-b293-66e15474ce39"
    (module Collect)

module T = Veri_info.Test_case

let init = Collect.empty

let test_cases = [|
  T.success add ~init sucs;
  T.unsound_sema add ~init unsound;
  T.unknown_sema add ~init unknown;
  T.disasm_error add ~init undisasm;
  T.custom incr ~init:0 total;
|]


type c = Collect.t

type t = {
  success  : c;
  unsound  : c;
  unknown  : c;
  undisasm : c;
  total    : int;
}

module Q = struct

  type query = Veri_result.kind

  type int_query = [
    | `Total_number
    | query
  ]

  let number = Map.fold ~f:(fun ~key ~data num -> num + data) ~init:0

  let total t = function
    | `Total_number -> t.total
    | `Disasm_error -> number t.undisasm
    | `Unsound_sema -> number t.unsound
    | `Unknown_sema -> number t.unknown
    | `Success      -> number t.success

  let stub = 0.5

  let relat t = function
    | `Disasm_error -> stub
    | `Unsound_sema -> stub
    | `Unknown_sema -> stub
    | `Success -> stub

end

let run trace policy =
  match T.eval trace policy test_cases with
  | Error _ as r -> r
  | Ok values ->
    let get tag n = Value.get_exn tag values.(n) in
    Ok
      {success = get sucs 0;
       unsound = get unsound 1;
       unknown = get unknown 2;
       undisasm = get undisasm 3;
       total = get total 4;}
