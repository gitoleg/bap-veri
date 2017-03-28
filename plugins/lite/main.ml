open Core_kernel.Std
open Bap.Std
open Bap_traces.Std
open Bap_future.Std
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

let arch p = Option.value_exn (Dict.find (Proj.meta p) Meta.arch)
let task_name p = Filename.basename @@ Uri.to_string @@ Proj.uri p

let mem_to_str mem =
  let deref mem =
    Seq.unfold_step ~init:(Memory.min_addr mem)
      ~f:(fun addr ->
          match Memory.get ~addr mem with
          | Ok word -> Seq.Step.Yield (word, Word.succ addr)
          | Error _ -> Seq.Step.Done) in
  let to_int w = ok_exn (Word.to_int w) in
  Seq.map ~f:(fun w -> sprintf "%02X" @@ to_int w) (deref mem) |>
  Seq.to_list |> String.concat ~sep:" "

let deref mem =
  Seq.unfold_step ~init:(Memory.min_addr mem)
    ~f:(fun addr ->
        match Memory.get ~addr mem with
        | Ok word -> Seq.Step.Yield (word, Word.succ addr)
        | Error _ -> Seq.Step.Done)

let run_static db_path p =
  match Dict.find (Proj.meta p) Meta.binary with
  | None ->
    eprintf "unable to run %s static, path not found\n" name
  | Some bin ->
    let filename = Binary.(bin.path) in
    let input = Bap_project.Input.file ~loader:"llvm"  ~filename in
    match Bap_project.create input with
    | Error er -> eprintf "error in %s %s" name (Error.to_string_hum er)
    | Ok bap_p ->
      let bap_p = Project.passes () |>
                  List.filter ~f:Bap_project.Pass.autorun |>
                  run_passes bap_p in
      let insns = Dis.insns @@ Bap_project.disasm bap_p in
      let db = Veri_db.create db_path `Static in
      match db with
      | Error er -> eprintf "error: %s\n" (Error.to_string_hum er)
      | Ok db ->
        let db = Veri_db.add_info db (arch p) (task_name p) in
        let db = Veri_db.add_exec_info db (find_exec_bounds bap_p) in
        let db,_ = Seq.fold ~init:(db,0) ~f:(fun (acc, ind) (mem, insn) ->
            let addr = Memory.min_addr mem in
            let bytes = "" in
            let db, id = Veri_db.add_insn db bytes (Some insn) in
            let db = Veri_db.add_insn_place db id addr ind in
            db, ind + 1) insns in
        match Veri_db.write db with
        | Ok _ -> ()
        | Error er ->
          eprintf "failed to write to database: %s\n"
            (Error.to_string_hum er)

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

let main path = function
  | `Static -> Backend.register (run_static path)
  | `Trace -> Backend.register (run_with_trace path)
  | `Dual ->
    Backend.register (run_static path);
    Backend.register (run_with_trace path)

module Cmd = struct

  let man = [
    `S "DESCRIPTION";
    `P "Write information about verification in database. ";
  ]

  module Mode = struct
    type t = [`Dual | `Static | `Trace] [@@deriving sexp]
    let parser str = match str with
      | "static" -> `Ok `Static
      | "trace" -> `Ok `Trace
      | "dual"  -> `Ok `Dual
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
        printf "db path is %s\n" !path;
        main !path !mode)


end
