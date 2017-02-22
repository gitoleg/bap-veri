open Core_kernel.Std
open Regular.Std

module Calls = String.Map

type ok_er = int * int [@@deriving bin_io, compare, sexp]

type t = {
  calls : ok_er Calls.t;
  errors: Veri_error.t list;
} [@@deriving bin_io, compare, sexp]

type stat = t [@@deriving bin_io, compare, sexp]

let empty = { calls = Calls.empty; errors = []; }
let errors t = t.errors
let notify t er = {t with errors = er :: t.errors }

let update t name ~ok ~er =
  {t with
   calls =
     Map.change t.calls name
       (function
         | None -> Some (ok, er)
         | Some (ok',er') -> Some (ok + ok', er + er')) }

let failbil t name = update t name ~ok:0 ~er:1
let success t name = update t name ~ok:1 ~er:0

let name_of_error (_, data) =
  List.find_map ~f:(function
      |`Name s -> Some s
      | _ -> None) data

module Abs = struct

  type nonrec t = t -> int

  let fold_calls {calls} f = Map.fold ~f ~init:0 calls

  let errors_count t =
    let rec loop ((und, snd, inc) as acc) = function
      | [] -> acc
      | (kind, data) :: tl -> match kind with
        | `Disasm_error   -> loop (und + 1, snd, inc) tl
        | `Soundness      -> loop (und, snd + 1, inc) tl
        | `Incompleteness -> loop (und, snd, inc + 1) tl in
    loop (0,0,0) t.errors

  let undisasmed  t = let x,_,_ = errors_count t in x
  let misexecuted t = let _,x,_ = errors_count t in x
  let mislifted   t = let _,_,x = errors_count t in x
  let successed   t = fold_calls t (fun ~key ~data cnt -> cnt + fst data)

  let total t =
    List.length t.errors +
    fold_calls t (fun ~key ~data cnt -> cnt + fst data + snd data)

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

  let fold_calls ~condition t =
    Map.fold ~f:(fun ~key ~data names ->
        if condition data then Set.add names key
        else names) ~init:String.Set.empty t.calls |>
    Set.to_list

  let successed = fold_calls ~condition:(fun data -> fst data <> 0)
  let misexecuted = fold_calls ~condition:(fun data -> snd data <> 0)

  let mislifted t =
    List.fold_left ~init:String.Set.empty
      ~f:(fun names ((kind, data) as er) ->
          match kind with
          | `Incompleteness ->
            let name = name_of_error er in
            if Option.is_none name then names
            else Set.add names (Option.value_exn name)
          | _ -> names) t.errors |>
    Set.to_list
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
    let errors = s.errors @ s'.errors in
    let calls = Map.fold ~init:s.calls s'.calls
        ~f:(fun ~key ~data calls ->
            Map.change calls key ~f:(function
                | None -> Some data
                | Some (ok,er) -> Some (fst data + ok, snd data + er))) in
    {errors; calls} in
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
        List.filter ~f:(fun (_,(_,er)) -> er <> 0) (Map.to_alist t.calls) in
      let mislift = Names.mislifted t in
      Format.fprintf fmt "%a\n%a\n"
        pp_misexecuted misexec pp_mislifted mislift

  end)
