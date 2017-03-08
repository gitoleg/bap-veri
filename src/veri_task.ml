open Core_kernel.Std
open Bap.Std
open Bap_traces.Std
open Bap_plugins.Std

module Dis = Disasm_expert.Basic

let () =
  match Plugins.load () |> Result.all with
  | Ok plugins -> ()
  | Error (path, er) ->
    Printf.eprintf "failed to load plugin from %s: %s"
      path (Error.to_string_hum er)

let rules_of_path = function
  | None -> []
  | Some file -> Veri_rule.Reader.of_path file

let string_of_error = function
  | `Protocol_error er ->
    Printf.sprintf "protocol error: %s"
      (Info.to_string_hum (Error.to_info er))
  | `System_error er ->
    Printf.sprintf "system error: %s" (Unix.error_message er)
  | `No_provider -> "no provider"
  | `Ambiguous_uri -> "ambiguous uri"

let trace_of_path file =
  let uri = Uri.of_string ("file:" ^ file) in
  match Trace.load uri with
  | Ok t as r -> r
  | Error er -> Or_error.error_string (string_of_error er)

let find_meta trace tag = Dict.find (Trace.meta trace) tag

let arch_of_trace trace =
  match find_meta trace Meta.arch with
  | None -> Or_error.error_string "trace of unknown arch"
  | Some arch -> Ok arch

let obj_ops trace =
  match find_meta trace Meta.binary with
  | None -> None
  | Some bin ->
    Some (Array.to_list bin.Binary.args)

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

let launch db_name target extra rules_path =
  let open Or_error in
  let extra = List.fold ~f:(fun s (k,v) -> sprintf "%s %s:%s;" s k v) ~init:"" extra in
  let rls = rules_of_path rules_path in
  let p = List.fold ~f:Veri_policy.add ~init:Veri_policy.empty rls in
  let r = trace_of_path target >>= fun trace ->
    Veri_numbers.run trace p >>= fun res ->
    Veri_db.update_db ~extra trace rls res db_name  in
  match r with
  | Ok () -> ()
  | Error er -> eprintf "%s" @@ Error.to_string_hum er

module Command = struct

  open Cmdliner

  let man = [
    `S "DESCRIPTION";
    `P "Launch a verificaton process with savind results to db";
  ]

  module Extra = struct
    type t = string * string

    let parser str = match String.split str ~on:':' with
      | [key; value] -> `Ok (key, value)
      | _ -> `Error "expected <key>:<value>"

    let printer fmt (k,v) = Format.fprintf fmt "%s:%s" k v

    let t = parser,printer
  end

  let database =
    let doc =
      "Database name. If not exists will be created at provided path" in
    Arg.(required & pos 0 (some string) None & info [] ~doc ~docv:"Database")

  let target =
    let doc =
      "A task's subject. Path to file with .frames extension" in
    Arg.(required & pos 1 (some file) None & info [] ~doc ~docv:"FILE")

  let extra =
    let doc = "Any extra information that one can pr ovides with
               task launch, in form of <key>:<value>" in
    Arg.(value & opt (list Extra.t) [] & info ["extra"] ~doc ~docv:"extra")

  let rules =
    let doc = "File with policy description" in
    Arg.(value & opt (some non_dir_file) None & info ["rules"] ~docv:"FILE" ~doc)

  let run_t =
    Term.(const launch $ database $ target $ extra $ rules)

  let info =
    let doc = "Bil verification tool" in
    let man = [
      `S "DESCRIPTION";
      `P "Launch a verificaton process with savind results to db";
    ] in
    Term.info "veri-task" ~doc ~man

  let run =
    match Term.eval (run_t, info) ~catch:false with
    | `Ok opts -> opts
    | `Error `Parse -> exit 64
    | `Error _ -> exit 2
    | _ -> exit 1

end
