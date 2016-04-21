open Core_kernel.Std
open Bap.Std
open Bap_traces.Std
open Bap_plugins.Std
open Cmdliner

module Dis = Disasm_expert.Basic

let () = 
  match Plugins.load () |> Result.all with
  | Ok plugins -> ()
  | Error (path, er) ->
    Printf.eprintf "failed to load plugin from %s: %s" 
      path (Error.to_string_hum er)

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

let policy = 
  let open Veri_policy in 
  let rules = [ 
    Rule.create ~insn:" *" ~left:".FLAGS => *" ~right:"CF => *" Rule.skip;
    Rule.create ~insn:" *" ~left:".FLAGS => *" ~right:"NF => *" Rule.skip;
    Rule.create ~insn:" *" ~left:".FLAGS => *" ~right:"VF => *" Rule.skip;
    Rule.create ~insn:" *" ~left:".FLAGS => *" ~right:"ZF => *" Rule.skip;
    Rule.create ~insn:" *" ~left:".FLAGS => *" Rule.skip;
    Rule.create ~insn:" *" ~right:"v.* => *" Rule.skip;
    Rule.create ~insn:" *" ~right:"v.* <= *" Rule.skip;
    Rule.create ~insn:" *" ~left:" *" Rule.deny;
    Rule.create ~insn:" *" ~right:" *" Rule.deny;
  ] in
  List.fold ~init:empty ~f:add rules

let run file =
  let f arch trace = 
    let report = 
      Dis.with_disasm ~backend:"llvm" (Arch.to_string arch) ~f:(fun dis ->
          let dis = Dis.store_asm dis |> Dis.store_kinds in          
          let report = Veri_report.create () in
          let ctxt = new Veri.context policy report trace in
          let veri = new Veri.t arch dis (fun _ -> true) in
          let ctxt' = 
            Monad.State.exec (veri#eval_trace trace) ctxt in
          Ok ctxt'#report) in
    match report with
    | Error er -> 
      let inf = Error.to_string_hum er in
      Printf.eprintf "error in verification: %s" inf
    | Ok report ->
      Veri_report.pp Format.std_formatter report in
  eval file f

let filename = 
  let doc = "Input filename" in 
  Arg.(required & pos 0 (some non_dir_file) None & info [] ~doc ~docv:"FILE") 

let info =
  let doc = "Bil verification tool" in
  let man = [] in
  Term.info "veri" ~doc ~man

let run_t = Term.(const run $ filename)

let () = match Term.eval (run_t, info) with `Error _ -> exit 1 | _ -> exit 0
