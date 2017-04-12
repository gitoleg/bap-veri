open Core_kernel.Std
open Or_error
open Bap.Std
open Bap_future.Std
include Self()

let find_exec_bounds p =
  Project.memory p |> Memmap.to_sequence
  |> Seq.fold ~init:[] ~f:(fun mems (mem,x) ->
      match Value.get Image.segment x with
      | None -> mems
      | Some seg ->
        if Image.Segment.is_executable seg then
          (Memory.min_addr mem, Memory.max_addr mem) :: mems
        else mems)

let mem_to_str mem =
  let deref mem =
    Seq.unfold_step ~init:(Memory.min_addr mem)
      ~f:(fun addr ->
          match Memory.get ~addr mem with
          | Ok word -> Seq.Step.Yield (word, Word.succ addr)
          | Error _ -> Seq.Step.Done) in
  let to_int w = ok_exn (Word.to_int w) in
  Seq.map ~f:(fun w -> sprintf "%X" @@ to_int w) (deref mem) |>
  Seq.to_list |> String.concat ~sep:" "

let run db_path name p =
  Veri_db.create db_path `Static >>= fun db ->
  let insns = Disasm.insns @@ Project.disasm p in
  Veri_db.write db `Start >>= fun () ->
  Veri_db.add_info db (Project.arch p) name >>= fun () ->
  Veri_db.add_exec_info db (find_exec_bounds p) >>= fun () ->
  let db,_ = Seq.fold ~init:(db, 0) ~f:(fun (db, ind) (mem, insn) ->
      let addr = Memory.min_addr mem in
      let bytes = mem_to_str mem in
      let res =
        Veri_db.add_insn db bytes (Some insn) >>= fun (db, id) ->
        Veri_db.add_insn_place db id addr ind >>= fun() ->
        Ok db in
      match res with
      | Ok db -> db, ind + 1
      | Error er ->
        eprintf
          "error while writing static info: %s\n"
          (Error.to_string_hum er);
        db, ind + 1) insns in
  Veri_db.write db `End

let main db_path name p = match run db_path name p with
  | Ok _ -> ()
  | Error er ->
    eprintf "error whule writing static info: %s\n" (Error.to_string_hum er)

module Cmd = struct

  let man = [
    `S "DESCRIPTION";
    `P "Write static information about binary in database. ";
  ]

  let path =
    let doc = "Path to datatabase" in
    Config.(param string "path" ~doc)

  let bin_name =
    let doc = "current binary name" in
    Config.(param string "name" ~doc)

  let () =
    Config.manpage man;
    Config.when_ready (fun {Config.get=(!)} ->
        Project.register_pass' (main !path !bin_name))

end
