open Core_kernel.Std
open Bap.Std
open Regular.Std

module Calls = String.Map

type ok_er = int * int [@@deriving bin_io, compare, sexp]

type t = {
  executed : ok_er Calls.t;
  unlifted : int Calls.t;
  undisasm : int;
} [@@deriving bin_io, compare, sexp]

type stat = t [@@deriving bin_io, compare, sexp]

let empty = {
  executed = Calls.empty;
  unlifted = Calls.empty;
  undisasm = 0;
}

let update_executed t name ~ok ~er =
  {t with
   executed =
     Map.change t.executed name
       (function
         | None -> Some (ok, er)
         | Some (ok',er') -> Some (ok + ok', er + er')) }

let update_unlifted t name =
  {t with
   unlifted =
     Map.change t.unlifted name
       (function
         | None -> Some 1
         | Some cnt -> Some (cnt + 1)) }

let success t name = update_executed t name ~ok:1 ~er:0

let name_of_dict dict =
  match Dict.find dict Veri_result.insn with
  | None -> None
  | Some insn -> Some (Insn.name insn)

let notify t kind dict = match kind with
  | `Disasm_error -> { t with undisasm = t.undisasm + 1 }
  | `Unsound_sema ->
    let name = Option.value_exn (name_of_dict dict) in
    update_executed t name ~ok:0 ~er:1
  | `Unknown_sema ->
    let name = Option.value_exn (name_of_dict dict) in
    update_unlifted t name

module Abs = struct

  type nonrec t = t -> int

  let undisasmed  t = t.undisasm
  let misexecuted t =
    Calls.fold ~f:(fun ~key ~data acc -> acc + snd data) t.executed ~init:0
  let mislifted t =
    Calls.fold ~f:(fun ~key ~data acc -> acc + data) t.unlifted ~init:0
  let successed t =
    Calls.fold ~f:(fun ~key ~data acc -> acc + fst data) t.executed ~init:0

  let total t =
    undisasmed t + misexecuted t + mislifted t + successed t

end

module Rel = struct
  type t = ?as_percents:bool -> stat -> float

  let apply f b t  =
    let r = float (f t) /. float (Abs.total t) in
    if b then r *. 100.0
    else r

  let ( @@ ) = apply

  let successed   ?(as_percents=false) = Abs.successed @@ as_percents
  let misexecuted ?(as_percents=false) = Abs.misexecuted @@ as_percents
  let undisasmed  ?(as_percents=false) = Abs.undisasmed @@ as_percents
  let mislifted   ?(as_percents=false) = Abs.mislifted @@ as_percents
end

module Names = struct

  type nonrec t = t -> string list

  let fold_executed ~condition t =
    Map.fold ~f:(fun ~key ~data names ->
        if condition data then Set.add names key
        else names) ~init:String.Set.empty t.executed |>
    Set.to_list

  let successed   = fold_executed ~condition:(fun data -> fst data <> 0)
  let misexecuted = fold_executed ~condition:(fun data -> snd data <> 0)

  let mislifted t = Calls.keys t.unlifted

end

let print_table fmt info data =
  let open Textutils.Std in
  let open Ascii_table in
  let cols =
    List.fold ~f:(fun acc (name, f) ->
        (Column.create name f)::acc) ~init:[] info |> List.rev in
  Format.fprintf fmt "%s"
    (to_string ~bars:`Ascii ~display:Display.short_box cols data)

module Summary = struct

  type nonrec t = t [@@deriving bin_io, compare, sexp]

  type p = {
    name: string;
    rel : float;
    abs : int;
  } [@@deriving bin_io, sexp, compare]

  let of_stat s =
    let make name abs rel = {name; abs; rel;} in
    if Abs.total s = 0 then []
    else
      let as_percents = true in
      [make "undisasmed"  (Abs.undisasmed s)  (Rel.undisasmed ~as_percents s);
       make "misexecuted" (Abs.misexecuted s) (Rel.misexecuted ~as_percents s);
       make "mislifted"   (Abs.mislifted s)   (Rel.mislifted ~as_percents s);
       make "successed"   (Abs.successed s)   (Rel.successed ~as_percents s);]

  let pp fmt t = match of_stat t with
    | [] -> Format.fprintf fmt "summary is unavailable\n"
    | ps ->
      print_table fmt
        ["", (fun x -> x.name);
         "rel", (fun x -> Printf.sprintf "%.2f%%" x.rel);
         "abs",  (fun x -> Printf.sprintf "%d" x.abs);]
        ps

end

let merge ts =
  let (+) s s' =
    let executed = Map.fold ~init:s.executed s'.executed
        ~f:(fun ~key ~data calls ->
            Map.change calls key ~f:(function
                | None -> Some data
                | Some (ok,er) -> Some (fst data + ok, snd data + er))) in
    let undisasm = s.undisasm + s'.undisasm in
    let unlifted = Map.fold ~init:s.unlifted s'.unlifted
        ~f:(fun ~key ~data calls ->
            Map.change calls key ~f:(function
                | None -> Some data
                | Some cnt -> Some (data + cnt))) in
    {executed; undisasm; unlifted} in
  List.fold ~f:(+) ~init:empty ts

let pp_summary = Summary.pp

include Regular.Make(struct
    type nonrec t = t [@@deriving bin_io, compare, sexp]
    let compare = compare
    let hash = Hashtbl.hash
    let module_name = Some "Veri_stat"
    let version = "0.1"

    let pp_misexecuted fmt = function
      | [] -> ()
      | mis ->
        Format.fprintf fmt "misexecuted \n";
        print_table fmt
          [ "instruction", fst;
            "failed", (fun (_, (_,er)) -> Printf.sprintf "%d" er);
            "successful", (fun (_, (ok,_)) -> Printf.sprintf "%d" ok); ]
          mis

    let pp_mislifted fmt names =
      let max_row_len = 10 in
      let max_col_cnt = 5 in
      match names with
      | [] -> ()
      | names when List.length names <= max_row_len ->
        let names' = "mislifted:" :: names in
        List.iter ~f:(Format.fprintf fmt "%s ") names';
        Format.print_newline ()
      | names ->
        let rows, row, _ = List.fold ~init:([], [], 0)
            ~f:(fun (acc, row, i) name ->
                if i < max_col_cnt then acc, name :: row, i + 1
                else row :: acc, name :: [], 1) names in
        let gaps = Array.create ~len:(max_col_cnt - List.length row) "-----" in
        let last = row @ Array.to_list gaps in
        let rows = List.rev (last :: rows) in
        let make_col i = "mislifted", (fun row -> List.nth_exn row i) in
        let cols = [
          make_col 0; make_col 1; make_col 2; make_col 3; make_col 4; ] in
        print_table fmt cols rows

    let pp fmt t =
      let misexec =
        List.filter ~f:(fun (_,(_,er)) -> er <> 0) (Map.to_alist t.executed) in
      let mislift = Names.mislifted t in
      Format.fprintf fmt "%a\n%a\n"
        pp_misexecuted misexec pp_mislifted mislift

  end)
