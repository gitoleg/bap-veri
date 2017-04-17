open Core_kernel.Std
open Bap.Std
open Bap_future.Std

open Veri.Std

include Self ()

module Report = struct

  let pp_code fmt s =
    let pp fmt s =
      String.iter ~f:(fun c -> Format.fprintf fmt "%X " (Char.to_int c)) s in
    Format.fprintf fmt "@[<h>%a@]" pp s

  let pp_evs fmt evs =
    List.iter ~f:(fun ev ->
        Format.(fprintf std_formatter "%a; " Value.pp ev)) evs

  let pp_data (rule, matched) =
    let open Policy in
    Format.printf "%a\n%a" Rule.pp rule Matched.pp matched

  let pp_report fmt infos =
    let print info =
      match Info.diff info with
      | [] -> ()
      | diff ->
        let insn = Option.value_exn (Info.insn info) in
        let real = Info.real info in
        let ours = Info.ours info in
        let bil  = Insn.bil insn in
        let insn = Insn.name insn in
        let bytes = Info.bytes info in
        Format.printf "@[<v>%s %a@,left: %a@,right: %a@,%a@]@."
          insn pp_code bytes pp_evs real pp_evs ours Bil.pp bil;
        List.iter ~f:pp_data diff;
        Format.print_newline ();
        Format.print_flush () in
    Stream.observe infos print

  let run p =
    let info = Proj.info p in
    Format.printf "%a\n" pp_report info

  let register () = Backend.register run

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

  let und = ref 0
  let uns = ref 0
  let unk = ref 0
  let suc = ref 0

  let incr info = match Info.error info with
    | None -> incr suc
    | Some (kind,_) -> match kind with
      | `Unknown_sema -> incr unk
      | `Unsound_sema -> incr uns
      | `Disasm_error -> incr und

  let print fmt () =
    let total = !und + !unk + !uns + !suc in
    if total = 0 then Format.fprintf fmt "summary is unavailable\n"
    else
      let pcnt x = float x /. float total *. 100.0 in
      let make name r = name, pcnt !r, !r in
      let ps =
        [make "undisasmed" und;
         make "unsound semantic" uns;
         make "unknown semantic" unk;
         make "successful" suc] in
      print_table fmt
        ["",    (fun (x,_,_) -> x);
         "rel", (fun (_,x,_) -> Printf.sprintf "%.2f%%" x);
         "abs", (fun (_,_,x) -> Printf.sprintf "%d" x);] ps

  let run p =
    let info = Proj.info p in
    Stream.observe info incr

  let register () =
    Backend.register run;
    at_exit (Format.printf "Summary:\n%a" print)

end

module Stat = struct

  let tab = String.Table.create
  let uns = tab ()
  let suc = tab ()
  let unk = tab ()

  let print_unknown fmt () =
    let max_row_len = 10 in
    let max_col_cnt = 5 in
    let names = Hashtbl.keys unk in
    let header () =
      Format.fprintf fmt "Instructions with unknown semantic \n" in
    match List.sort ~cmp:String.compare names with
    | [] -> ()
    | names when List.length names <= max_row_len ->
      header ();
      List.iter ~f:(Format.fprintf fmt "%s ") names;
      Format.print_newline ()
    | names ->
      header ();
      let rows, row, _ = List.fold ~init:([], [], 0)
          ~f:(fun (acc, row, i) name ->
              if i < max_col_cnt then acc, name :: row, i + 1
              else row :: acc, name :: [], 1) names in
      let gaps = Array.create ~len:(max_col_cnt - List.length row) "-----" in
      let last = row @ Array.to_list gaps in
      let rows = List.rev (last :: rows) in
      let make_col i = "unknown", (fun row -> List.nth_exn row i) in
      let cols = [
        make_col 0; make_col 1; make_col 2; make_col 3; make_col 4; ] in
      print_table fmt cols rows

  let print_unsound fmt () = match Hashtbl.to_alist uns with
    | [] -> ()
    | data ->
      Format.fprintf fmt "Instructions with unsound semantic \n";
      let data =
        List.sort ~cmp:(fun x y -> String.compare (fst x) (fst y)) data in
      let ok_num name =
        match String.Table.find suc name with
        | None -> 0
        | Some num -> num in
      let r = List.map ~f:(fun (name,cnt) ->
          (name, cnt, ok_num name)) data in
      print_table fmt
        [ "instruction", (fun (name, _,_) -> Printf.sprintf "%s" name);
          "failed", (fun (_,er,_) -> Printf.sprintf "%d" er);
          "successful", (fun (_,_,ok) -> Printf.sprintf "%d" ok); ]
        r

  let add name tab =
    String.Table.change tab name ~f:(function
        | None -> Some 1
        | Some x -> Some (x + 1))

  let get_name i = Insn.name @@ Option.value_exn (Info.insn i)

  let of_info i =
    match Info.error i with
    | None -> add (get_name i) suc
    | Some (kind, _) -> match kind with
      | `Unknown_sema -> add (get_name i) unk
      | `Unsound_sema -> add (get_name i) uns
      | _ -> ()

  let run p =
    let info  = Proj.info p in
    Stream.observe info of_info

  let register () =
    Backend.register run;
    at_exit (fun () ->
        Format.printf "\n%a\n%a\n" print_unsound () print_unknown ())

end

let main show_errors show_stat show_sum =
  if show_errors then Report.register ();
  if show_stat then Stat.register ();
  if show_sum then Summary.register ()

module Cmd = struct

  let man = [
    `S "DESCRIPTION";
    `P "Print information about verification. ";
  ]

  let show_errors =
    let doc = "Show verification errors, i.e. mismatches" in
    Config.(flag "errors" ~doc)

  let show_stat =
    let doc = "Show verification statistics, tables of
      instructions and results of their's lifting" in
    Config.(flag "stat" ~doc)

  let show_sum =
    let doc = "Show a brief summary about verification" in
    Config.(flag "sum" ~doc)

  let () =
    Config.manpage man;
    Config.when_ready (fun {Config.get=(!)} ->
        main !show_errors !show_stat !show_sum)

end
