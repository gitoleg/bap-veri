open Core_kernel.Std
open Or_error
open Bap.Std
open Bap_traces.Std
open Veri.Std
open Veri_lite_internal
include Self()

(** YYYY-MM-DD HH:MM:SS in UTC *)
let get_time () =
  let open Unix in
  let tm = gmtime @@ time () in
  sprintf "%04d-%02d-%02d %02d-%02d-%02d"
    (tm.tm_year + 1900) (tm.tm_mon + 1) tm.tm_mday
    tm.tm_hour tm.tm_min tm.tm_sec

let bap_version = Config.version

let sql_quote str =
  let module S = String.Search_pattern in
  S.replace_all (S.create "'") ~in_:str ~with_:"''"

module Scheme = struct

  let task_tab = Tab.(create "task" [
      col ~key:true ~not_null:true "Id" Int;
    ])

  let info_tab = Tab.(create "info" [
      col ~key:true ~not_null:true "Id" Int;
      col ~not_null:true "Kind" Text;
      col ~not_null:true "Name" Text;
      col ~not_null:true "Date" Text;
      col ~not_null:true "Bap" Text;
      col ~not_null:true "Arch" Text;
      col "Comp_ops" Text;
    ])

  let dyn_info_tab = Tab.(create "dynamic_info" [
      col ~key:true ~not_null:true "Id" Int;
      col "Task_ops" Text;
      col "Policy" Text;
    ])

  let dyn_data_tab = Tab.(create "dynamic_data" [
      col ~key:true ~not_null:true "Id_task" Int;
      col ~key:true ~not_null:true "Id_insn" Int;
      col "Successful" Int;
      col "Undisasmed" Int;
      col "Unsound_sema" Int;
      col "Unknown_sema" Int;
    ])

  let task_insn_tab = Tab.(create "task_insn" [
      col ~key:true ~not_null:true "Id_task" Int;
      col ~key:true ~not_null:true "Id_insn" Int;
    ])

  let insn_tab = Tab.(create "insn" [
      col ~key:true ~not_null:true "Id" Int;
      col ~not_null:true ~unique:true "Bytes" Text;
      col "Name" Text;
      col "Asm" Text;
      col "Bil" Text;
    ])

  let bin_info_tab = Tab.(create "bin_info" [
      col ~key:true ~not_null:true "Id_task" Int;
      col ~key:true ~not_null:true "Id" Int;
      col ~not_null:true "Min_addr" Int;
      col ~not_null:true "Max_addr" Int;
    ])

  let insn_place_tab = Tab.(create "insn_place" [
      col ~key:true ~not_null:true "Id_task" Int;
      col ~key:true ~not_null:true "Id_insn" Int;
      col ~key:true ~not_null:true "Pos" Int;
      col ~not_null:true "Addr" Int;
    ])

  let tables = [
    task_tab; info_tab; dyn_info_tab; task_insn_tab;
    insn_tab; dyn_data_tab; bin_info_tab; insn_place_tab ]
end

type id = Int64.t
type insn_id = id

open Scheme

type kind = [ `Trace | `Static ] [@@deriving sexp]
type task_id = id
type commit = [ `Before_close | `Every of int ]
type task = {
  name : string;
  conn : db;
  task_id : id;
  kind    : kind;
  commit  : commit;
  counter : int;
}

type t = task

let add_task db  =
  Tab.insert db task_tab ["(NULL)"] >>= fun () ->
  Ok (Tab.last_inserted db )

let write' conn = function
  | `Start -> start_transaction conn
  | `End -> commit_transaction conn

let write t act = write' t.conn act

let create name ?(commit = `Before_close) kind =
  open_db name >>= fun db ->
  List.map tables ~f:(Tab.add_if_absent db) |>
  Result.all_ignore >>= fun _ ->
  add_task db >>= fun task_id ->
  write' db `Start >>= fun () ->
  Ok {name; conn = db; task_id; kind; commit; counter = 0;}

let add_info t ?(comp_ops="") arch name =
  let data = sprintf "('%Ld', '%s', '%s', '%s', '%s', '%s', '%s')"
      t.task_id
      (Sexp.to_string (sexp_of_kind t.kind))
      name
      (get_time ())
      bap_version
      (Arch.to_string arch)
      comp_ops in
  Tab.insert t.conn info_tab [data]

let add_dyn_info t ?(obj_ops="") rules  =
  let policy = sql_quote @@ List.fold ~init:"" ~f:(fun s r ->
      sprintf "%s%s; " s (Rule.to_string r)) rules in
  let data =
    sprintf "('%Ld', '%s', '%s')" t.task_id obj_ops policy in
  Tab.insert t.conn dyn_info_tab [data]

let str_of_bytes b =
  String.fold b ~init:[]
    ~f:(fun s c -> (sprintf "%X" @@ Char.to_int c) :: s) |>
  List.rev |> String.concat ~sep:" "

let try_commit t =
  match t.commit with
  | `Before_close -> Ok t
  | `Every n when t.counter < n ->
    Ok {t with counter = t.counter + 1}
  | _ ->
    write t `End >>= fun () ->
    write t `Start >>= fun () ->
    Ok {t with counter = 0}

let add_insn t bytes insn =
  let bytes = str_of_bytes bytes in
  let data =
    match insn with
    | None -> sprintf "(NULL, '%s', '%s', '%s', '%s')" bytes "" "" ""
    | Some i ->
      let bil = Sexp.to_string (Bil.sexp_of_t @@ Insn.bil i) in
      sprintf "(NULL, '%s', '%s', '%s', '%s')"
        bytes (Insn.name i) (Insn.asm i) bil in
  Tab.insert ~ignore_:true t.conn insn_tab [data] >>= fun () ->
  Tab.select t.conn insn_tab ~where:["Bytes", bytes] ["Id"] >>= fun id ->
  match id with
  | None -> Or_error.error_string "didn't inserted data in insn-tab"
  | Some id ->
    let id = Int64.of_string id in
    let task_data = sprintf "(%Ld, %Ld)" t.task_id id in
    let dyn_data =
      sprintf "('%Ld', '%Ld', '0', '0', '0', '0')" t.task_id id in
    Tab.insert ~ignore_:true t.conn task_insn_tab [task_data] >>= fun () ->
    Tab.insert ~ignore_:true t.conn dyn_data_tab [dyn_data] >>= fun () ->
    try_commit t >>= fun t ->
    Ok (t, id)

let add_insn_place t insn_id addr index =
  let addr = Or_error.ok_exn @@ Word.to_int64 addr in
  let data = sprintf "('%Ld', '%Ld', '%d', '%Ld')"
      t.task_id insn_id index addr in
  Tab.insert t.conn insn_place_tab [data]

let add_insn_dyn t insn_id res =
  let field = match res with
    | None -> "Successful"
    | Some (er, _) -> match er with
      | `Unsound_sema -> "Unsound_sema"
      | `Unknown_sema -> "Unknown_sema"
      | `Disasm_error -> "Undisasmed" in
  let where =
    ["Id_task", sprintf "%Ld" t.task_id; "Id_insn", sprintf "%Ld" insn_id] in
  Tab.increment t.conn dyn_data_tab field ~where >>= fun () ->
  Ok t

let add_exec_info t ranges =
  let to_int64 x = Or_error.ok_exn @@ Word.to_int64 x in
  let data,_ = List.fold ~init:([], 0)
      ~f:(fun (data, id) (min, max) ->
          let s = sprintf "('%Ld', '%d', '%Ld', '%Ld')"
              t.task_id id (to_int64 min) (to_int64 max) in
          s :: data, id + 1) ranges in
  Tab.insert t.conn bin_info_tab data

let close t =
  write t `End >>= fun () ->
  close_db t.conn;
  Ok ()
