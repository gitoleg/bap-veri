open Core_kernel.Std
open Bap.Std
open Bap_traces.Std
open Bap_plugins.Std
open Bap_future.Std
open Veri_policy

module Dis = Disasm_expert.Basic

let () = 
  match Plugins.load () |> Result.all with
  | Ok plugins -> ()
  | Error (path, er) ->
    Printf.eprintf "failed to load plugin from %s: %s" 
      path (Error.to_string_hum er)

let read_rules fname = 
  let comments = "#" in
  let is_sensible s = 
    s <> "" && not (String.is_prefix ~prefix:comments s) in
  let inc = In_channel.create fname in
  let strs = In_channel.input_lines inc in
  In_channel.close inc;
  List.map ~f:String.strip strs 
  |> List.filter ~f:is_sensible
  |> List.map ~f:Veri_rule.of_string_err |>
  List.filter_map ~f:(function 
      | Ok r -> Some r
      | Error er -> 
        Format.(fprintf std_formatter "%s\n" (Error.to_string_hum er));
        None)

let string_of_error = function
  | `Protocol_error er -> 
    Printf.sprintf "protocol error: %s" 
      (Info.to_string_hum (Error.to_info er))
  | `System_error er -> 
    Printf.sprintf "system error: %s" (Unix.error_message er)
  | `No_provider -> "no provider"
  | `Ambiguous_uri -> "ambiguous uri"

let eval file f stat = 
  let uri = Uri.of_string ("file:" ^ file) in
  match Trace.load uri with
  | Error er -> 
    let ers = 
      Printf.sprintf "error during loading trace: %s\n" (string_of_error er) in
    Error (Error.of_string ers)
  | Ok trace ->
    match Dict.find (Trace.meta trace) Meta.arch with
    | Some arch -> f arch trace stat
    | None -> Error (Error.of_string "trace of unknown arch")

let default_policy = 
  let open Veri_rule in  
  let p = Veri_policy.(add empty (create_exn ~insn:".*" ~left:".*" deny)) in
  Veri_policy.add p (create_exn ~insn:".*" ~right:".*" deny)

let make_policy = function
  | None -> default_policy
  | Some file -> 
    read_rules file |>
    List.fold ~f:Veri_policy.add ~init:Veri_policy.empty

let pp_result fmt report  = 
  Format.fprintf fmt "%a" Veri.Report.pp report;
  Format.print_flush ()

let errors_stream s = 
  ignore(Stream.subscribe s (pp_result Format.std_formatter))

let is_supported ev = 
    let supported _ = true in
    Value.Match.(
      select @@
      case Event.code_exec supported @@
      case Event.register_read supported @@
      case Event.register_write supported @@
      case Event.memory_load supported @@
      case Event.memory_store supported @@
      case Event.pc_update supported @@
      default (fun () -> false)) ev

let read_dir path = 
  let d = Unix.opendir path in
  let suf = ".frames" in
  let read_name () = 
    try 
      Some (Unix.readdir d)
    with End_of_file -> None in
  let rec folddir acc = 
    match read_name () with
    | Some filename -> 
      if Filename.check_suffix filename suf then
        folddir (filename :: acc) 
      else 
        folddir acc 
    | None -> acc in
  let files = folddir [] in
  Unix.closedir d;
  files

let print_veri_error er = 
  Error.to_string_hum er |>
  Printf.eprintf "error in verification: %s" 

let print_summary stat =
  let s = Veri_stat.make_summary stat in
  Format.(fprintf std_formatter "%a\n" Veri_stat.Summary.pp s) 

let run' rules source show_errs show_stat = 
  let policy = make_policy rules in
  let print_stat stat = match stat with 
    | Error er -> print_veri_error er
    | Ok stat ->
      if show_stat then
        Veri_stat.pp Format.std_formatter stat;
      print_summary stat in
  let f arch trace stat = 
    Dis.with_disasm ~backend:"llvm" (Arch.to_string arch) ~f:(fun dis ->
        let dis = Dis.store_asm dis |> Dis.store_kinds in          
        let ctxt = new Veri.context stat policy trace in
        let veri = new Veri.t arch dis is_supported in
        if show_errs then errors_stream ctxt#reports;
        let ctxt' = Monad.State.exec (veri#eval_trace trace) ctxt in
        Ok ctxt'#stat) in
  match source with
  | `File file -> Veri_stat.create () |> eval file f |> print_stat
  | `Dir dir ->    
    let files = read_dir dir in
    let full_path file = String.concat ~sep:"/" [dir; file] in
    let rec loop files stat =
      match files with
      | [] -> Ok stat
      | file :: files ->
        Format.(fprintf std_formatter "%s@."  file);
        match eval (full_path file) f stat with
        | Error er ->
          print_veri_error er;
          loop files stat
        | Ok stat' -> loop files stat' in
    let stat = Veri_stat.create () in
    let stat' = loop files stat in
    print_stat stat'

let run rules path show_errs show_stat = 
  let src = 
    if Sys.is_directory path then `Dir path
    else `File path in
  run' rules src show_errs show_stat

module Command = struct

  open Cmdliner

  let filename = 
    let doc = 
      "Input file with extension .frames of directory with .frames files" in 
    Arg.(required & pos 0 (some string) None & info [] ~doc ~docv:"FILE | DIR") 
      
  let rules =
    let doc = "File with policy description" in
    Arg.(value & opt (some non_dir_file) None & info ["rules"] ~docv:"FILE" ~doc)

  let show_errors = 
    let doc = "Show detailed information about BIL errors." in
    Arg.(value & flag & info ["show-errors"] ~doc)
      
  let show_stat = 
    let doc = "Show verification summary" in
    Arg.(value & flag & info ["show-stat"] ~doc)
     
  let info =
    let doc = "Bil verification tool" in
    let man = [
      `S "DESCRIPTION";
      `P "Veri is a BIL verification tool and intend to verify BAP lifters
          and to find errors.";
    ] in
    Term.info "veri" ~doc ~man

  let run_t = Term.(const run $ rules $ filename $ show_errors $ show_stat)

  let run () = match Term.eval (run_t, info) with `Error _ -> exit 1 | _ -> exit 0

end

let () = Command.run ()
