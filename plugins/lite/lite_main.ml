open Core_kernel.Std
open Or_error
open Bap.Std
open Bap_traces.Std
open Bap_future.Std

open Veri.Std
include Self()

let arch p = Option.value_exn (Dict.find (Proj.meta p) Meta.arch)
let task_name p = Filename.basename @@ Uri.path @@ Proj.uri p

let db_error er =
  eprintf "failed to write to database %s\n" (Error.to_string_hum er)

let with_trace_info db info =
  let open Info in
  let dbr =
    Veri_db.add_insn db (bytes info) (insn info) >>= fun (db, id) ->
    Veri_db.add_insn_place db id (addr info) (index info) >>= fun () ->
    Veri_db.add_insn_dyn db id (error info) >>= fun db ->
    Ok db in
  match dbr with
  | Ok db -> Some db, db
  | Error er ->
    db_error er;
    Some db, db

let run_with_trace db_path p =
  let info = Proj.info p in
  let fut = Proj.finish p in
  let name = task_name p in
  let db =
    Veri_db.create db_path ~commit:(`Every 10000) `Trace >>= fun db ->
    Veri_db.add_info db (arch p) name >>= fun () ->
    Veri_db.add_dyn_info db (Proj.rules p) >>= fun () ->
    Ok db in
  match db with
  | Error er -> db_error er
  | Ok db ->
    let s = Stream.parse info ~init:db ~f:with_trace_info in
    Stream.observe s (fun _ -> ());
    let db = Stream.upon fut s in
    Future.upon db (fun db ->
        match Veri_db.close db with
        | Ok () -> ()
        | Error er -> db_error er)

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
