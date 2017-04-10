open Core_kernel.Std
open Bap.Std
open Bap_traces.Std
open Bap_plugins.Std
open Bap_future.Std

let veri =
  let (/) = Filename.concat in Veri_conf.(libdir / pkg)

let check_loaded = function
  | Ok plugins -> ()
  | Error (path, er) ->
    Printf.eprintf "failed to load plugin from %s: %s"
      path (Error.to_string_hum er)

let load_veri_plugins () =
  let is_veri_plg p =
    String.is_prefix ~prefix:"veri" @@ Plugin.name p in
  let is_prefixes ~prefixes s =
    List.exists ~f:(fun x -> String.is_prefix ~prefix:x s) prefixes in
  let is_set p =
    let name = Plugin.name p in
    Array.exists ~f:(fun arg ->
        is_prefixes ~prefixes:["-"^name; "--"^name ] arg) Sys.argv in
  let plgs = Plugins.list ~library:[veri] () in
  let plgs = List.filter ~f:is_veri_plg plgs in
  let plgs = List.filter ~f:is_set plgs in
  List.fold ~init:[] ~f:(fun a p ->
      match Plugin.load p with
      | Ok () -> Ok p :: a
      | Error er -> Error (Plugin.path p, er) :: a) plgs
  |> Result.all |> check_loaded

let load_bap_plugins () =
  Plugins.load () |> Result.all |> check_loaded

let () = load_bap_plugins ()
let () = load_veri_plugins ()

open Veri.Std

module Veri_options = struct
  type t = {
    rules : string option;
    path  : string;
  } [@@deriving fields]
end

module type Opts = sig
  val options : Veri_options.t
end

module Program (O : Opts) = struct
  open Veri_options
  open O

  let eval_file file rules =
    let open Or_error in
    let uri = Uri.of_string ("file:" ^ file) in
    Proj.create uri rules >>= fun p ->
    Proj.run p

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

  let read_rules = function
    | None -> []
    | Some p -> Rule.Reader.of_path p

  let main () =
    let rules = read_rules options.rules in
    let files =
      if Sys.is_directory options.path then (read_dir options.path)
      else [options.path] in
    List.iter ~f:(fun file ->
        Format.(fprintf std_formatter "%s@." file);
        match eval_file file rules with
        | Error er ->
          eprintf "error in verification: %s" (Error.to_string_hum er)
        | Ok () -> ()) files
end

module Command = struct

  open Cmdliner

  let filename =
    let doc =
      "Input file with extension .frames or directory with .frames files" in
    Arg.(required & pos 0 (some string) None & info [] ~doc ~docv:"FILE | DIR")

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

  let create a b  = Veri_options.Fields.create a b

  let run_t = Term.(const create $ rules $ filename )

  let filter_argv argv =
    let known_passes = Project.passes () |> List.map ~f:Project.Pass.name in
    let known_plugins = Plugins.list ~library:[veri] () |> List.map ~f:Plugin.name in
    let known_names = known_passes @ known_plugins in
    let prefixes = List.map known_names  ~f:(fun name -> "--" ^ name) in
    let is_prefix str prefix = String.is_prefix ~prefix str in
    let is_others opt =
      is_prefix opt "--" && List.exists ~f:(fun p -> is_prefix opt p)
        prefixes in
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
