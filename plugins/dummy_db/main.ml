open Core_kernel.Std
open Bap.Std
open Bap_traces.Std
module Dis = Disasm
module Bap_project = Project
open Veri.Std
include Self()

let run_passes init = List.fold ~init ~f:(fun proj pass ->
    Bap_project.Pass.run_exn pass proj)

let find_exec_bounds p =
  Bap_project.memory p |> Memmap.to_sequence
  |> Seq.fold ~init:[] ~f:(fun mems (mem,x) ->
      match Value.get Image.segment x with
      | None -> mems
      | Some seg ->
        if Image.Segment.is_executable seg then
          (Memory.min_addr mem, Memory.max_addr mem) :: mems
        else mems)

let run_static db_path p =
  match Dict.find (Proj.meta p) Meta.binary with
  | None ->
    eprintf "unable to run %s static, path not found\n" name
  | Some bin ->
    let filename = Binary.(bin.path) in
    printf "filename is %s\n" filename;
    let input = Bap_project.Input.file ~loader:"llvm"  ~filename in
    match Bap_project.create input with
    | Error er -> eprintf "error in %s %s" name (Error.to_string_hum er)
    | Ok bap_p ->
      let bap_p = Project.passes () |>
                  List.filter ~f:Bap_project.Pass.autorun |>
                  run_passes bap_p in
      let insns = Dis.insns @@ Bap_project.disasm bap_p in
      let name = Filename.basename (Uri.to_string @@ Proj.uri p) in
      let arch = Option.value_exn (Dict.find (Proj.meta p) Meta.arch)
      in
      let bnds = find_exec_bounds bap_p in
      (* let r = *)
      (*   Veri_db.update_with_static ~name arch bnds insns db_path in *)
      (* match r with *)
      (* | Ok () -> () *)
      (* | Error er -> eprintf "error in %s: %s" name (Error.to_string_hum er) *)


let run_with_trace db_path p = failwith "unimplemented"

let main path = function
  | `Static -> Backend.register "dummy-db-static" (run_static path)
  | `Trace -> Backend.register "dummy-db-trace" (run_with_trace path)

module Cmd = struct

  let man = [
    `S "DESCRIPTION";
    `P "Write information about verification in database. ";
  ]

  module Mode = struct
    type t = [`Static | `Trace] [@@deriving sexp]
    let parser str = match str with
      | "static" -> `Ok `Static
      | "trace" -> `Ok `Trace
      | _ -> `Error "expected <trace | static>"
    let printer ppf t =
      Format.fprintf ppf "%s" @@ Sexp.to_string (sexp_of_t t)
    let t = Config.converter parser printer `Trace
  end

  let mode =
    let doc = "mode" in
     Config.(param Mode.t "mode" ~doc)

  let path =
    let doc = "Path to datatabase" in
    Config.(param string "path" ~doc)

  let () =
    Config.manpage man;
    Config.when_ready (fun {Config.get=(!)} ->
        main !path !mode)


end
