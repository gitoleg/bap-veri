open Core_kernel.Std
open Or_error
open Sqlite3
open Bap.Std
open Bap_traces.Std

include Self()


module Q = Veri_numbers.Q

(** YYYY-MM-DD HH:MM:SS in UTC *)
let get_time () =
  let open Unix in
  let tm = gmtime @@ time () in
  sprintf "%04d-%02d-%02d %02d-%02d-%02d"
    (tm.tm_year + 1900) (tm.tm_mon + 1) tm.tm_mday
    tm.tm_hour tm.tm_min tm.tm_sec

let bap_version = Config.version

let checked db action = function
  | Rc.OK -> Ok ()
  | rc ->
    Or_error.error_string @@
    sprintf "error: can't %s: %s, %s\n" action (Rc.to_string rc)
      (Sqlite3.errmsg db)

type env = {
  arch_info : string;
  comp_ops  : string;
  obj_ops   : string;
  policy    : string;
  extra     : string;
}

let create_task_tab db =
  let q =
    "CREATE TABLE task (
      Id INTEGER PRIMARY KEY NOT NULL,
      Name TEXT);" in
  checked db "create task tab" (exec db q)

let add_task db target_name =
  let q = sprintf
    "INSERT INTO task VALUES (NULL, '%s');" target_name in
  checked db "add task" (exec db q) >>= fun () ->
  Ok (last_insert_rowid db)

let create_env_tab db =
  let q = "CREATE TABLE env (
       Id INTEGER PRIMARY KEY NOT NULL,
       Date TEXT NOT NULL,
       Bap TEXT NOT NULL,
       Arch TEXT NOT NULL,
       Comp_ops TEXT,
       Obj_ops TEXT,
       Policy TEXT,
       Extra TEXT);" in
  checked db "create env tab" (exec db q)

let add_env db task_id env =
  let q = sprintf "INSERT INTO env
      VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s');"
      (Int64.to_string task_id)
      (get_time ())
      bap_version
      env.arch_info
      env.comp_ops
      env.obj_ops
      env.policy
      env.extra in
  checked db "add env" (exec db q)

let create_total_tab db =
  let q = "CREATE TABLE total (
       Id INTEGER PRIMARY KEY NOT NULL,
       Total INTEGER,
       Successful INTEGER,
       Unsound_sema INTEGER,
       Unknown_sema INTEGER,
       Undisasmed INTEGER);" in
  checked db "create total tab" (exec db q)

let add_total db task_id result =
  let str_of_num what =
    string_of_int @@ Q.abs result what in
  let q = sprintf "INSERT INTO total
      VALUES ('%s', '%s', '%s', '%s', '%s', '%s');"
      (Int64.to_string task_id)
      (str_of_num `Total_number)
      (str_of_num `Success)
      (str_of_num `Unsound_sema)
      (str_of_num `Unknown_sema)
      (str_of_num `Disasm_error) in
  checked db "create env tab" (exec db q)

let create_insn_tab db =
  let q = "CREATE TABLE insn (
    Id TEXT PRIMARY_KEY NON NULL,
    Name TEXT,
    Successful INTEGER,
    Unsound_sema INTEGER,
    Unknown_sema INTEGER);" in
  checked db "create insn tab" (exec db q)

let add_insns db result =
  let add insns s =
    List.fold ~init:s ~f:Set.add insns in
  let get i q = string_of_int (Q.insn result i q) in
  let s =
    add (Q.insns result `Success) Insn.Set.empty |>
    add (Q.insns result `Unsound_sema) |>
    add (Q.insns result `Unknown_sema) in
  let len = Set.length s in
  let q =
    Set.fold ~init:(Ok (0, "INSERT INTO insn VALUES "))
      ~f:(fun r i -> match r with
        | Ok (cnt, s) ->
          let q = sprintf "('%s', '%s', '%s', '%s', '%s')"
            (Insn.asm i)
            (Insn.name i)
            (get i `Success)
            (get i `Unsound_sema)
            (get i `Unknown_sema) in
        let q = if cnt = len - 1 then sprintf "%s %s;" s q
          else sprintf "%s %s," s q in
        Ok (cnt + 1, q)
        | _ as r -> r) s in
  q >>= fun (_,q) ->
  checked db "add insn" (exec db q)

let open_db name =
  let try_open name =
    try
      Some (db_open ~mode:`NO_CREATE name)
    with _ -> None in
  match try_open name with
  | Some db -> Ok db
  | None ->
    let db = db_open name in
    create_task_tab db >>= fun () ->
    create_env_tab db >>= fun () ->
    create_total_tab db >>= fun () ->
    create_insn_tab db >>= fun () ->
    Ok db

let close_db db =
  if db_close db then ()
  else
    eprintf "warning! database wasn't closed properly\n"

let arch trace = match Dict.find (Trace.meta trace) Meta.arch with
  | None -> Or_error.error_string "trace of unknown arch"
  | Some arch -> Ok arch

let target_name trace =
  match Dict.find (Trace.meta trace) Meta.binary with
  | None -> Or_error.error_string "trace of unknown name"
  | Some bin -> Ok (Filename.basename bin.Binary.path)

let sql_quote str =
  let module S = String.Search_pattern in
  S.replace_all (S.create "'") ~in_:str ~with_:"''"

let add_data db trace env result =
  target_name trace >>= fun target_name ->
  add_task db target_name >>= fun task_id ->
  add_env db task_id env >>= fun () ->
  add_total db task_id result >>= fun () ->
  add_insns db result

let make_env ?compiler_ops ?object_ops ?extra trace rules =
  let with_default ~def x = Option.value_map ~default:def ~f:ident x in
  let concat_ops ops =
    List.fold ~f:(fun acc x -> sprintf "%s; %s" acc x) ~init:"" ops in
  arch trace >>= fun arch ->
  let policy = sql_quote @@ List.fold ~init:"" ~f:(fun s r ->
      sprintf "%s%s; " s (Veri_rule.to_string r)) rules in
  Ok {comp_ops = concat_ops @@ with_default ~def:[] compiler_ops;
      obj_ops = concat_ops @@ with_default ~def:[] object_ops;
      arch_info = Arch.to_string arch;
      policy;
      extra = with_default ~def:"" extra}

let update_db
    ?compiler_ops ?object_ops ?extra trace rules result name =
  let finish db r = close_db db; r in
  make_env ?compiler_ops ?object_ops ?extra trace rules >>= fun env ->
  open_db name >>= fun db -> finish db @@ add_data db trace env result
