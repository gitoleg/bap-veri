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
  let is_interesting s = 
    s <> "" && not (String.is_prefix ~prefix:comments s) in
  let inc = In_channel.create fname in
  let strs = In_channel.input_lines inc in
  In_channel.close inc;
  List.map ~f:String.strip strs 
  |> List.filter ~f:is_interesting 
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

let eval file f = 
  let uri = Uri.of_string ("file:" ^ file) in
  match Trace.load uri with
  | Error er -> 
    Printf.eprintf "error during loading trace: %s\n" (string_of_error er)
  | Ok trace ->
    match Dict.find (Trace.meta trace) Meta.arch with
    | Some arch -> f arch trace
    | None -> Printf.eprintf "trace of unknown arch\n"

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

let ignore_pc_update ev = not (Value.is Event.pc_update ev)

let run rules file show_errs show_stat = 
  let f arch trace = 
    let stat = 
      Dis.with_disasm ~backend:"llvm" (Arch.to_string arch) ~f:(fun dis ->
          let dis = Dis.store_asm dis |> Dis.store_kinds in          
          let policy = make_policy rules in
          let ctxt = new Veri.context policy trace in
          let veri = new Veri.t arch dis ignore_pc_update in
          if show_errs then errors_stream ctxt#reports;
          let ctxt' = 
            Monad.State.exec (veri#eval_trace trace) ctxt in
          Ok ctxt'#stat) in
    match stat with
    | Error er -> 
      Error.to_string_hum er |>
      Printf.eprintf "error in verification: %s" 
    | Ok stat ->
      if show_stat then
        Veri_stat.pp Format.std_formatter stat in
  eval file f

module Command = struct

  open Cmdliner

  let filename = 
    let doc = "Input file with extension .frames" in 
    Arg.(required & pos 0 (some non_dir_file) None & info [] ~doc ~docv:"FILE") 
      
  let rules =
    let doc = "File with policy description" in
    Arg.(value & opt (some non_dir_file) None & info ["rules"] ~docv:"FILE" ~doc)

  let show_errors = 
    let doc = "Show bil errors" in
    Arg.(value & flag & info ["show-errors"] ~doc)
      
  let show_stat = 
    let doc = "Show verification statistic" in
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
