open Core_kernel.Std
open Bap.Std

module R = Veri_result

type info = {
  indx : Int.Set.t;
  insn : Insn.t option;
  addrs : Addr.Set.t;
} [@@deriving bin_io, compare, sexp]

type map = info String.Map.t [@@deriving bin_io, compare, sexp]

let add_addr map = function
  | None -> map
  | Some addr -> Addr.Set.add map addr

let add_map map bytes index addr insn =
  let add_index indexes = match index with
    | None -> indexes
    | Some ind -> Set.add indexes ind in
  Map.change map bytes ~f:(function
      | None ->
        let addrs = add_addr Addr.Set.empty addr in
        Some {insn; addrs; indx = add_index Int.Set.empty }
      | Some info ->
        let addrs = add_addr info.addrs addr in
        Some {info with addrs; indx = add_index info.indx})

module Collector = struct
  type t = map [@@deriving bin_io, compare, sexp]

  let pp_bytes fmt t =
    let pp fmt s =
      String.iter ~f:(fun c -> Format.fprintf fmt "%X " (Char.to_int c)) s in
    Format.fprintf fmt "@[<h>%a@]" pp t

  let pp fmt t = Map.iteri
      ~f:(fun ~key ~data ->
          let insn = match data.insn with
            | None -> ""
            | Some insn -> Insn.pps () insn in
          Format.fprintf fmt "%a : %s;\n"
            pp_bytes key insn) t
end

let empty = String.Map.empty
let find_bytes d = Dict.find d R.bytes
let find_insn d = Dict.find d R.insn
let find_addr d = Dict.find d R.addr

let add dict index map =
  match find_bytes dict with
  | None -> map
  | Some bytes ->
    add_map map bytes (Some index) (find_addr dict) (find_insn dict)

let sucs = Value.Tag.register ~name:"successful case"
    ~uuid:"fa5f178c-4da1-4b0f-b061-e2e8f5d97e57"
    (module Collector)

let unsound =
  Value.Tag.register ~name:"unsound semantic case"
    ~uuid:"460c3894-e27c-4b91-a07a-6a0d02201bcd"
    (module Collector)

let unknown =
  Value.Tag.register ~name:"unknown semantic case"
    ~uuid:"464227e3-e101-4154-b4e1-361bd45a215b"
    (module Collector)

let undisas =
  Value.Tag.register ~name:"undisasmed insn case"
    ~uuid:"95b23a1b-b021-4e77-b293-66e15474ce39"
    (module Collector)

module T = Veri_info.Test_case

let cases = [|
  T.success add ~init:empty sucs;
  T.unsound_sema add ~init:empty unsound;
  T.unknown_sema add ~init:empty unknown;
  T.disasm_error add ~init:empty undisas;
|]

type col = Collector.t

type t = {
  success  : col;
  unsound  : col;
  unknown  : col;
  undisas  : col;
}



type query = Veri_result.kind
type insn_query = [ Veri_result.success | Veri_result.sema_error]

let occurred m =
  Map.fold m ~init:0 ~f:(fun ~key ~data acc -> acc + Set.length data.indx)

let total t =
  occurred t.success + occurred t.unsound + occurred t.unknown + occurred t.undisas

let number t = function
  | `Total_number -> total t
  | `Disasm_error -> occurred t.undisas
  | `Unsound_sema -> occurred t.unsound
  | `Unknown_sema -> occurred t.unknown
  | `Success      -> occurred t.success

let apply t f = function
  | `Unsound_sema -> f t.unsound
  | `Unknown_sema -> f t.unknown
  | `Disasm_error -> f t.undisas
  | `Success      -> f t.success

let insns t q =
  let f m = List.filter_map ~f:(fun x -> x.insn) (Map.data m) in
  apply t f q

let insnsi t q =
  let f m = List.filter_map (Map.data m)
      ~f:(fun x -> match x.insn with
          | None -> None
          | Some i -> Some (i, Set.length x.indx)) in
  apply t f q

let bytes t q =
  let f m = Map.keys m in
  apply t f q

let bytesi t q =
  let f m = List.map ~f:(fun (key, x) -> key, Set.length x.indx) (Map.to_alist m) in
  apply t f q

let find_insn t ?query b =
  let find m =
    Option.value_map ~default:None ~f:(fun x -> x.insn)
      (Map.find m b) in
  let bind x f =
    match x with
    | None -> f
    | x -> x in
  let (>>=) = bind in
  match query with
  | Some q -> apply t find q
  | None ->
    find t.undisas >>=
    find t.success >>=
    find t.unsound >>=
    find t.unknown

let bytes_number t q bytes =
  let f m =
    Option.value_map ~default:0
      (Map.find m bytes)
      ~f:(fun x -> Set.length x.indx) in
  apply t f q

let find_indexes t ?query bytes =
  let f m =
    Option.value_map ~default:Int.Set.empty
      (Map.find m bytes)
      ~f:(fun x -> x.indx) in
  match query with
  | Some q -> Set.to_list @@ apply t f q
  | None ->
    let sucs = apply t f `Success in
    let s =
      [ apply t f `Unsound_sema;
        apply t f `Unknown_sema;
        apply t f `Disasm_error;] in
    Set.to_list @@
    List.fold ~init:sucs ~f:(fun acc s -> Set.union acc s) s

let find_addrs t ?query bytes =
  let f m =
    Option.value_map ~default:Addr.Set.empty
      (Map.find m bytes)
      ~f:(fun x -> x.addrs) in
  match query with
  | Some q -> Set.to_list @@ apply t f q
  | None ->
    let sucs = apply t f `Success in
    let s =
      [ apply t f `Unsound_sema;
        apply t f `Unknown_sema;
        apply t f `Disasm_error;] in
    Set.to_list @@
    List.fold ~init:sucs ~f:(fun acc s -> Set.union acc s) s

let t_of_values values =
  let open Or_error in
  let get tag n =
    try
      Ok (Value.get_exn tag values.(n))
    with exn -> Error (Error.of_exn exn) in
  get sucs 0 >>= fun success ->
  get unsound 1 >>= fun unsound ->
  get unknown 2 >>= fun unknown ->
  get undisas 3 >>= fun undisas ->
  Ok {success; unsound; unknown; undisas;}
