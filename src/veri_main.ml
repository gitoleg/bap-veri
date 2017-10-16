open Core_kernel.Std
open Format
open Bap.Std
open Bap_traces.Std
open Bap_plugins.Std
open Bap_future.Std

let check_loaded = function
  | Ok plugins -> ()
  | Error (path, er) ->
    Printf.eprintf "failed to load plugin from %s: %s"
      path (Error.to_string_hum er)

let load_plugins plgs =
  List.fold ~init:[] ~f:(fun a p ->
      match Plugin.load p with
      | Ok () -> Ok p :: a
      | Error er -> Error (Plugin.path p, er) :: a) plgs |>
  Result.all |> check_loaded

let veri_plugins () =
  Plugins.list ~env:["veri-frontend"] ~provides:["veri"] ()

let load_veri_plugins () =
  let is_prefixes ~prefixes s =
    List.exists ~f:(fun x -> String.is_prefix ~prefix:x s) prefixes in
  let is_set p =
    let name = Plugin.name p in
    Array.exists ~f:(fun arg ->
        is_prefixes ~prefixes:["-"^name; "--"^name ] arg) Sys.argv in
  veri_plugins () |>
  List.filter ~f:is_set |>
  load_plugins

let load_bap_plugins () =
  let excluded =
    List.map ~f:Plugin.name (Plugins.list ~provides:["veri"] ()) in
  List.filter ~f:(fun p -> not @@ List.mem ~equal:(=) excluded (Plugin.name p))
    (Plugins.list ()) |>
  load_plugins

let () = load_bap_plugins ()
let () = load_veri_plugins ()

open Veri.Std

module Veri_options = struct
  type t = {
    rules        : string option;
    path         : string;
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

  let check_path p =
    if not (Sys.file_exists p) then
      let () = eprintf "Error: file %s not exists!\n" p in
      exit 1

  let main () =
    check_path options.path;
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

  let get_opt ~default argv opt  =
    Option.value (fst (Term.eval_peek_opts ~argv opt)) ~default

  let filename, filename_doc =
    let doc =
      "Input file with extension .frames or directory with .frames files" in
    Arg.(required & pos 0 (some string) None
         & info [] ~doc ~docv:"FILE | DIR"), doc

  let list_plugins, list_plugins_doc =
    let doc = "List all available plugins" in
    Arg.(value & flag & info ["list-plugins"] ~doc), doc

  let rules, rules_pre =
    let doc =
      "$(b,--rules)
    File with policy description.
    It's an ideal case when all events from trace and all events
    from BIL are equal to each other. But in practice both trace
    and bil could contain some special cases. For example, trace
    could be obtained from source, that does not provide some cpu
    flags or bil does not support some instructions. And there is
    an option to shadow such cases and don't mark them as error.
    From other point of view, we do not want to miss other errors.
    So for this reasons $(mname) supports policy, that is a set of
    rules with the following grammar:

    $(i,ACTION) $(i,INSN) $(i,L_EVENT) $(i,R_EVENT)

    Each rule consists of 4 fields:
    $(i,ACTION)  could be either $(i,SKIP), either $(i,DENY). If we have
            processed trace without matching with any $(i,DENY), then
            everything is ok.
    $(i,INSN)    could contain an instruction name like $(i,MOV64rr)
            or regular expression, like $(i,MOV.*)
    $(i,L_EVENT) left hand-side event, corresponds to textual representation
            of tracer events, and could contain any string and
            regualar expression.
    $(i,R_EVENT) right hand-side event, corresponds to textual representation
            of lifter events, and could contain any string and
            regualar expression.

    Matching is performed textually, based on event syntax. Regexp syntax
    supports backreferences in event fields. Only that events, that don't
    have an equal pair in other set goes to this matching.
    Each row in rules file either contains a rule, or commented with #
    symbol, or is empty. Rule must have exactly 4 fields.
    An empty field must be written as \'\' or \"\". Fields with spaces must be
    written in quotes: \"RAX => .*\", single quotes also supported: \'RAX => .*\'." in
    Arg.(value & opt (some non_dir_file) None
         & info ["rules"] ~docv:"FILE" ), doc

  let info =
    let doc = "Bil verification tool" in
    let man = [
      `S "SYNOPSIS";
      `Pre "
$(mname) $(i,FILE)
$(mname) $(i,FILE) [--rules=$(i,RULES)]
$(mname) --list-plugins";
      `S "DESCRIPTION";
      `P
     "Veri is a BIL verification tool and intended to check BAP lifters.
     The tool compares results of execution of every instruction
     in a trace with execution of BIL code, that describes
     this instruction.";
      `S "OPTIONS";
      `I ("$(b,--list-plugins)", list_plugins_doc);
      `Pre rules_pre ;
    ] in
    Term.info "bap-veri" ~doc ~man

  let create a b = Veri_options.Fields.create a b

  let run_t = Term.(const create $ rules $ filename)

  let filter_argv argv =
    let known_passes = Project.passes () |> List.map ~f:Project.Pass.name in
    let known_plugins = veri_plugins () @
      Plugins.list () |> List.map ~f:Plugin.name in
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

let list_plugins_and_exit () =
  let plugins =
    let cmp x y = String.compare (Plugin.name x) (Plugin.name y) in
    List.sort ~cmp (veri_plugins ()) in
  List.iter ~f:(fun p ->
      printf "%-16s %s@." (Plugin.name p) (Plugin.desc p)) plugins;
  exit 0

let start options =
  let module Program = Program(struct
      let options = options
    end) in
  Program.main ()

let () =
  if Command.get_opt Sys.argv Command.list_plugins ~default:false then
    list_plugins_and_exit ();
  start (Command.parse Sys.argv)
