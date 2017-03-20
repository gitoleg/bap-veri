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

module type Opts = sig
  val options : Veri_options.t
end

module Program (O : Opts) = struct
  open Veri_options
  open O

  module Dis = Disasm_expert.Basic

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
      let fin,p = Future.create () in
      let ctxt = new Veri.context policy trace in
      let info = ctxt#info in
      let start () =
        Dis.with_disasm ~backend:"llvm" (Arch.to_string arch) ~f:(fun dis ->
            let dis = Dis.store_asm dis |> Dis.store_kinds in
            let veri = new Veri.t arch dis in
            let _ = Monad.State.exec (veri#eval_trace trace) ctxt in
            Ok (Promise.fulfill p ())) in
      Ok (start, info, fin)


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
    let fmt = Format.std_formatter in
    let add_sum, print_sum = Veri_print.print_summary fmt in
    let add_stat, print_stat = Veri_print.print_stat fmt in
    let add_out = Option.value_map options.out
        ~default:None ~f:(fun x -> Some (Veri_out.output x)) in
    let make file =
      Format.(fprintf std_formatter "%s@." file);
      match eval_file file policy with
      | Error er ->
        eprintf "error in verification: %s" (Error.to_string_hum er)
      | Ok (start, infos, fin) ->
        if options.show_errs then Veri_print.print_report fmt infos;
        add_sum infos;
        add_stat infos;
        Option.value_map ~default:() ~f:(fun f -> f file infos fin) add_out;
        ignore(start ()) in
    List.iter ~f:make files ;
    if options.show_stat then print_stat ();
    print_sum ()


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
