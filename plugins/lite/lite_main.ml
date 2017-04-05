open Core_kernel.Std
open Bap.Std
open Bap_traces.Std
open Bap_future.Std

open Veri.Std
include Self()

let arch p = Option.value_exn (Dict.find (Proj.meta p) Meta.arch)
let task_name p = Filename.basename @@ Uri.to_string @@ Proj.uri p

let with_trace_info db info =
  let open Info in
  let db, id = Veri_db.add_insn db (bytes info) (insn info) in
  let db = Veri_db.add_insn_place db id (addr info) (index info) in
  let db = Veri_db.add_insn_dyn db id (error info) in
  Some db, db

let run_with_trace db_path p =
  let info, fut = Proj.info p in
  let db = Veri_db.create db_path `Trace in
  match db with
  | Error er -> eprintf "error: %s\n" (Error.to_string_hum er)
  | Ok db ->
    let name = task_name p in
    let db = Veri_db.add_info db (arch p) name in
    let db = Veri_db.add_dyn_info db (Proj.rules p) in
    let s = Stream.parse info ~init:db ~f:with_trace_info in
    Stream.observe s (fun _ -> ());
    let db = Stream.upon fut s in
    Future.upon db (fun db ->
        let res = Or_error.(
            Veri_db.write db >>= fun db ->
            Veri_db.write_stat db) in
        match res with
        | Ok () -> ()
        | Error er ->
          eprintf "failed to write to database: %s\n"
            (Error.to_string_hum er))

module Cmd = struct

  let man = [
    `S "DESCRIPTION";
    `P "Write information about verification in database. ";
  ]

  let path =
    let doc = "Path to datatabase" in
    Config.(param string "path" ~doc)

  let () =
    Config.manpage man;
    Config.when_ready (fun {Config.get=(!)} ->
        Backend.register (run_with_trace !path))
end
