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

let read_rules file = 
  let rules = Rules_reader.read file in
  List.filter_map ~f:(function 
      | Ok r -> Some r
      | Error er -> 
        Format.(fprintf err_formatter "%s\n" (Error.to_string_hum er));
        None) rules

let string_of_error = function
  | `Protocol_error er -> 
    Printf.sprintf "protocol error: %s" 
      (Info.to_string_hum (Error.to_info er))
  | `System_error er -> 
    Printf.sprintf "system error: %s" (Unix.error_message er)
  | `No_provider -> "no provider"
  | `Ambiguous_uri -> "ambiguous uri"

let eval file f = 
  let uri = Uri.of_string ("file://" ^ file) in  
  match Trace.load uri with
  | Error er -> 
    Printf.eprintf "error during loading trace: %s\n" (string_of_error er)
  | Ok trace ->
    match Dict.find (Trace.meta trace) Meta.arch with
    | Some arch -> f arch trace
    | None -> Printf.eprintf "trace of unknown arch\n"

let make_policy = function
  | None -> Veri_policy.empty
  | Some file -> 
    let rules = read_rules file in
    List.fold ~f:Veri_policy.add ~init:Veri_policy.empty rules

let pp_result fmt report  = 
  Format.fprintf fmt "%a" Veri.Report.pp report;
  Format.print_flush ()
  
let verbose_stream s = 
  ignore(Stream.subscribe s (pp_result Format.std_formatter))

let ignore_pc_update ev = not (Value.is Event.pc_update ev)

let run rules file verbose = 
  let f arch trace = 
    let stat = 
      Dis.with_disasm ~backend:"llvm" (Arch.to_string arch) ~f:(fun dis ->
          let dis = Dis.store_asm dis |> Dis.store_kinds in          
          let policy = make_policy rules in
          let ctxt = new Veri.context policy trace in
          let veri = new Veri.t arch dis ignore_pc_update in
          if verbose then verbose_stream ctxt#reports;
          let ctxt' = 
            Monad.State.exec (veri#eval_trace trace) ctxt in
          Ok ctxt'#stat) in
    match stat with
    | Error er -> 
      let inf = Error.to_string_hum er in
      Printf.eprintf "error in verification: %s" inf
    | Ok stat ->
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

  let verbose = 
    let doc = "Print verbose output" in
    Arg.(value & flag & info ["verbose"] ~doc)

  let info =
    let doc = "Bil verification tool" in
    let man = [
      `S "DESCRIPTION";
      `P "Veri is a BIL verification tool and intend to verify BAP lifters
          and to find errors.";
    ] in
    Term.info "veri" ~doc ~man

  let run_t = Term.(const run $ rules $ filename $ verbose)

  let run () = match Term.eval (run_t, info) with `Error _ -> exit 1 | _ -> exit 0

end

let () = Command.run ()
