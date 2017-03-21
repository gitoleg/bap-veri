open Core_kernel.Std
open Bap.Std
open Bap_traces.Std
open Bap_plugins.Std
open Bap_future.Std

(** TODO : write a config with ab files  *)
let veri = "/home/oleg/.opam/4.04.0/lib/bap-veri"

let () =
  match Plugins.load ~library:[veri] () |> Result.all with
  | Ok plugins ->
    List.iter ~f:(fun p -> printf "%s; " @@ Plugin.name p) plugins;
    print_newline ();
    flush stdout;
    ()
  | Error (path, er) ->
    Printf.eprintf "failed to load plugin from %s: %s"
      path (Error.to_string_hum er);
    flush stderr

let string_of_error = function
  | `Protocol_error er ->
    sprintf "protocol error: %s"
      (Info.to_string_hum (Error.to_info er))
  | `System_error er ->
    Printf.sprintf "system error: %s" (Unix.error_message er)
  | `No_provider -> "no provider"
  | `Ambiguous_uri -> "ambiguous uri"

open Veri.Std

module Veri_options = struct
  type t = {
    rules : string option;
    path  : string;
    out   : string option;
  } [@@deriving fields]
end

module type Opts = sig
  val options : Veri_options.t
end

module Program (O : Opts) = struct
  open Veri_options
  open O

  module Dis = Disasm_expert.Basic

  let make_policy = function
    | None -> Policy.default
    | Some file ->
      Rule.Reader.of_path file |>
      List.fold ~f:Policy.add ~init:Policy.empty

  let arch_of_trace trace =
    match Dict.find (Trace.meta trace) Meta.arch with
    | None -> Or_error.error_string "trace of unknown arch"
    | Some arch -> Ok arch

  let eval_file file policy =
    let open Or_error in
    let mk_er s = Error (Error.of_string s) in
    let uri = Uri.of_string ("file:" ^ file) in
    match Trace.load uri with
    | Error er ->
      Printf.sprintf "error during loading trace: %s\n" (string_of_error er) |>
      mk_er
    | Ok trace ->
      arch_of_trace trace >>= fun arch ->
      Dis.with_disasm ~backend:"llvm" (Arch.to_string arch) ~f:(fun dis ->
          let dis = Dis.store_asm dis |> Dis.store_kinds in
          let veri = new Exec.t arch dis in
          let ctxt = new Exec.context policy trace in
          let infos, fin = ctxt#info in
          Backend.call file infos fin;
          let _ = Monad.State.exec (veri#eval_trace trace) ctxt in
          Ok ())

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
    List.iter ~f:(fun file ->
        Format.(fprintf std_formatter "%s@." file);
        match eval_file file policy with
        | Error er ->
          eprintf "error in verification: %s" (Error.to_string_hum er)
        | Ok () -> ()) files;
    Backend.on_exit ()
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

  let info =
    let doc = "Bil verification tool" in
    let man = [
      `S "DESCRIPTION";
      `P "Veri is a BIL verification tool and intend to verify BAP lifters
          and to find errors.";
    ] in
    Term.info "veri" ~doc ~man

  let create a b c = Veri_options.Fields.create a b c

  let run_t =
    Term.(const create $ rules $ filename $ output)

  let filter_argv argv =
    let known_passes = Project.passes () |> List.map ~f:Project.Pass.name in
    let known_plugins = Plugins.list () |> List.map ~f:Plugin.name in
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
