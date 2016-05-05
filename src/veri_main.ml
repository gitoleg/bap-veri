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

let action_of_string = function 
  | "SKIP" -> Rule.skip
  | "DENY" -> Rule.deny
  | str -> 
    Printf.eprintf "only SKIP | DENY actions should be used: %s\n" str;
    exit 1

let rule_of_string s = 
  if String.strip s = "" || String.is_prefix ~prefix:"//" s then None
  else
    let fields = String.split ~on:'|' s |> List.map ~f:String.strip in
    match fields with
    | [action; insn; left; right] ->
      let rule = Rule.create ~insn ~left ~right (action_of_string action) in
      Some rule
    | _ -> 
      Printf.eprintf "Fields count doesn't match to rule grammar: %s\n" s;
      exit 1

let read_rules file = 
  let inc = In_channel.create file in
  let rules = In_channel.input_lines inc |> List.filter_map ~f:rule_of_string in
  In_channel.close inc;
  rules

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

let pp_matched fmt (rule, matched) =
  Format.fprintf fmt "%a\n%a" Rule.pp rule Matched.pp matched

let pp_bil fmt = function
  | [] -> Format.fprintf fmt "bil is empty\n"
  | bil -> Format.fprintf fmt "%a\n" Bil.pp bil

let pp_result fmt (bil, insn, matches) = 
  Format.fprintf fmt "%s\n" insn;
  Format.fprintf fmt "%a\n" pp_bil bil;
  List.iter ~f:(pp_matched fmt) matches;
  Format.print_newline ();
  Format.print_flush ()
  
let verbose_stream s = 
  ignore(Stream.subscribe s (pp_result Format.std_formatter))

let run rules file verbose = 
  let f arch trace = 
    let report = 
      Dis.with_disasm ~backend:"llvm" (Arch.to_string arch) ~f:(fun dis ->
          let dis = Dis.store_asm dis |> Dis.store_kinds in          
          let report = Veri_report.create () in
          let policy = make_policy rules in
          let ctxt = new Veri.context policy report trace in
          let veri = new Veri.t arch dis (fun e -> not (Value.is Event.pc_update e)) in
          if verbose then verbose_stream ctxt#data;
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

module Command = struct

  open Cmdliner

  let filename = 
    let doc = "Input filename" in 
    Arg.(required & pos 0 (some non_dir_file) None & info [] ~doc ~docv:"FILE") 
      
  let rules =
    let doc = "Target architecture" in
    Arg.(value & opt (some non_dir_file) None & info ["rules"] ~docv:"RULES" ~doc)

  let verbose = 
    let doc = "Output result" in
    Arg.(value & flag & info ["verbose"] ~doc)

  let info =
    let doc = "Bil verification tool" in
    let man = [] in
    Term.info "veri" ~doc ~man

  let run_t = Term.(const run $ rules $ filename $ verbose)

  let run () = match Term.eval (run_t, info) with `Error _ -> exit 1 | _ -> exit 0

end

let () = Command.run ()
