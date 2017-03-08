open Core_kernel.Std
open Bap.Std
open Bap_traces.Std
open Bap_plugins.Std
open Bap_future.Std
open Veri_policy

let () =
  match Plugins.load () |> Result.all with
  | Ok plugins -> ()
  | Error (path, er) ->
    Printf.eprintf "failed to load plugin from %s: %s"
      path (Error.to_string_hum er)

module Veri_options = struct
  type t = {
    rules : string option;
    show_errs : bool;
    show_stat : bool;
    path  : string;
    out   : string option;
  } [@@deriving fields]
end

let pp_code fmt s =
  let pp fmt s =
    String.iter ~f:(fun c -> Format.fprintf fmt "%X " (Char.to_int c)) s in
  Format.fprintf fmt "@[<h>%a@]" pp s

let pp_evs fmt evs =
  List.iter ~f:(fun ev ->
      Format.(fprintf std_formatter "%a; " Value.pp ev)) evs

let pp_data fmt (rule, matched) =
  let open Veri_policy in
  Format.fprintf fmt "%a\n%a" Veri_rule.pp rule Matched.pp matched

let print_report fmt result =
  let module R = Veri_result in
  let get tag = Dict.find result.R.dict tag in
  let open Option in
  let _ =
    get R.insn >>= fun insn ->
    get R.real >>= fun real ->
    get R.ours >>= fun ours ->
    get R.bytes >>= fun code ->
    get R.diff >>= fun diff ->
    let bil = Insn.bil insn in
    let insn = Insn.name insn in
    Format.fprintf fmt "@[<v>%s %a@,left: %a@,right: %a@,%a@]@."
      insn pp_code code pp_evs real pp_evs ours Bil.pp bil;
    List.iter ~f:(pp_data fmt) diff;
    Format.print_newline ();
    Some () in
  Format.print_flush ()

module Stat = struct
  module Q = Veri_numbers.Q

  let print_table fmt info data =
    let open Textutils.Std in
    let open Ascii_table in
    let cols =
      List.fold ~f:(fun acc (name, f) ->
          (Column.create name f)::acc) ~init:[] info |> List.rev in
    Format.fprintf fmt "%s"
      (to_string ~bars:`Ascii ~display:Display.short_box cols data)

  let pp_summary fmt s =
    let n = Q.total s in
    if n = 0 then Format.fprintf fmt "summary is unavailable\n"
    else
      let pcnt x y = float x /. float y *. 100.0 in
      let make name kind =
        let x = Q.abs s kind in name, pcnt x n, x in
      let ps =
        [make "undisasmed" `Disasm_error;
         make "unsound semabtic" `Unsound_sema;
         make "unknown semantic" `Unknown_sema;
         make "successful" `Success] in
      print_table fmt
        ["",    (fun (x,_,_) -> x);
         "rel", (fun (_,x,_) -> Printf.sprintf "%.2f%%" x);
         "abs", (fun (_,_,x) -> Printf.sprintf "%d" x);] ps

  let pp_unsound fmt s =
    Format.fprintf fmt "instructions with unsound semantic \n";
    let unite_by_name insns =
      Map.to_alist @@
      List.fold ~f:(fun s (insn,num) ->
          Map.change s (Insn.name insn) ~f:(function
              | None -> Some num
              | Some x -> Some (x + num))) ~init:String.Map.empty insns in
    let unsound = unite_by_name @@ Q.insnsi s `Unsound_sema in
    let success = unite_by_name @@ Q.insnsi s `Success in
    let ok_num name =
      match List.find ~f:(fun (n,_) -> n = name) success with
      | None -> 0
      | Some (_,num) -> num in
    let r = List.map ~f:(fun (name,cnt) ->
        (name, cnt, ok_num name)) unsound in
    print_table fmt
      [ "instruction", (fun (name, _,_) -> Printf.sprintf "%s" name);
        "failed", (fun (_,er,_) -> Printf.sprintf "%d" er);
        "successful", (fun (_,_,ok) -> Printf.sprintf "%d" ok); ]
      r

  let pp_unknown fmt s =
    let max_row_len = 10 in
    let max_col_cnt = 5 in
    let names = List.map ~f:Insn.name @@ Q.insns s `Unknown_sema in
    match names with
    | [] -> ()
    | names when List.length names <= max_row_len ->
      let names' = "unknown:" :: names in
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
      let make_col i = "unknown", (fun row -> List.nth_exn row i) in
      let cols = [
        make_col 0; make_col 1; make_col 2; make_col 3; make_col 4; ] in
      print_table fmt cols rows

  let pp fmt t =
    Format.fprintf fmt "%a\n%a\n" pp_unsound t pp_unknown t

end

module type Opts = sig
  val options : Veri_options.t
end

module Program (O : Opts) = struct
  open Veri_options
  open O

  let string_of_error = function
    | `Protocol_error er ->
      Printf.sprintf "protocol error: %s"
        (Info.to_string_hum (Error.to_info er))
    | `System_error er ->
      Printf.sprintf "system error: %s" (Unix.error_message er)
    | `No_provider -> "no provider"
    | `Ambiguous_uri -> "ambiguous uri"

  let make_policy = function
    | None -> Veri_policy.default
    | Some file ->
      Veri_rule.Reader.of_path file |>
      List.fold ~f:Veri_policy.add ~init:Veri_policy.empty

  let process s res =
    if options.show_errs then print_report Format.std_formatter res;
    Veri_numbers.add s res

  let eval_file file policy =
    let mk_er s = Error (Error.of_string s) in
    let uri = Uri.of_string ("file:" ^ file) in
    match Trace.load uri with
    | Error er ->
      Printf.sprintf "error during loading trace: %s\n" (string_of_error er) |>
      mk_er
    | Ok trace ->
      Veri_info.Test_case.fold trace policy ~init:Veri_numbers.empty ~f:process

  let read_dir path =
    let dir = Unix.opendir path in
    let fullpath file = String.concat ~sep:"/" [path; file] in
    let is_trace file = Filename.check_suffix file ".frames" in
    let next () =
      try
        Some (Unix.readdir dir)
      with End_of_file -> None in
    let rec folddir acc =
      match next () with
      | Some file ->
        if is_trace file then folddir (fullpath file :: acc)
        else folddir acc
      | None -> acc in
    let files = folddir [] in
    Unix.closedir dir;
    files

  let main () =
    let files =
      if Sys.is_directory options.path then (read_dir options.path)
      else [options.path] in
    let policy = make_policy options.rules in
    let eval stats file =
      Format.(fprintf std_formatter "%s@." file);
      match eval_file file policy with
      | Error er ->
        Error.to_string_hum er |>
        Printf.eprintf "error in verification: %s";
        stats
      | Ok stat' -> (Filename.basename file, stat') :: stats in
    let stats = List.fold ~init:[] ~f:eval files in
    let stat = List.fold ~init:Veri_numbers.empty
        ~f:Veri_numbers.merge (List.map ~f:snd stats) in
    if options.show_stat then
      Stat.pp Format.std_formatter stat;
    Format.(fprintf std_formatter "%a\n" Stat.pp_summary stat);
    match options.out with
    | None -> ()
    | Some out -> Veri_out.output stats out

end

module Command = struct

  open Cmdliner

  let filename =
    let doc =
      "Input file with extension .frames or directory with .frames files" in
    Arg.(required & pos 0 (some string) None & info [] ~doc ~docv:"FILE | DIR")

  let output =
    let doc = "File to output results" in
    Arg.(value & opt (some string) None & info ["output"] ~docv:"FILE" ~doc)

  let rules =
    let doc = "File with policy description" in
    Arg.(value & opt (some non_dir_file) None & info ["rules"] ~docv:"FILE" ~doc)

  let make_flag ~doc ~name = Arg.(value & flag & info [name] ~doc)

  let show_errors =
    make_flag ~name:"show-errors"
      ~doc:"Show detailed information about BIL errors"

  let show_stat = make_flag ~name:"show-stat" ~doc:"Show verification statistic"

  let info =
    let doc = "Bil verification tool" in
    let man = [
      `S "DESCRIPTION";
      `P "Veri is a BIL verification tool and intend to verify BAP lifters
          and to find errors.";
    ] in
    Term.info "veri" ~doc ~man

  let create a b c d e = Veri_options.Fields.create a b c d e

  let run_t =
    Term.(const create $ rules $ show_errors $ show_stat $ filename $ output)

  let filter_argv argv =
    let known_passes = Project.passes () |> List.map ~f:Project.Pass.name in
    let known_plugins =  Plugins.list () |> List.map ~f:Plugin.name in
    let known_names = known_passes @ known_plugins in
    let prefixes = List.map known_names  ~f:(fun name -> "--" ^ name) in
    let is_prefix str prefix = String.is_prefix ~prefix str in
    let is_others opt =
      is_prefix opt "--" && List.exists ~f:(fun p -> is_prefix opt p) prefixes in
    List.fold ~init:([], false) ~f:(fun (acc, drop) opt ->
        if drop then acc, false
        else
        if is_others opt then acc, not (String.mem opt '=')
        else opt :: acc, false) (Array.to_list argv) |>
    fst |> List.rev |> Array.of_list

  let parse argv =
    let argv = filter_argv argv in
    match Term.eval ~argv (run_t, info) ~catch:false with
    | `Ok opts -> opts
    | `Error `Parse -> exit 64
    | `Error _ -> exit 2
    | _ -> exit 1

end

let start options =
  let module Program = Program(struct
      let options = options
    end) in
  Program.main ()

let () = start (Command.parse Sys.argv)
