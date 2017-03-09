open Core_kernel.Std
open Or_error
open Sqlite3
open Bap.Std
open Bap_traces.Std

include Self()

module Q = Veri_numbers

(** YYYY-MM-DD HH:MM:SS in UTC *)
let get_time () =
  let open Unix in
  let tm = gmtime @@ time () in
  sprintf "%04d-%02d-%02d %02d-%02d-%02d"
    (tm.tm_year + 1900) (tm.tm_mon + 1) tm.tm_mday
    tm.tm_hour tm.tm_min tm.tm_sec

let bap_version = Config.version

let checked ?cb db action q = match exec ?cb db q with
  | Rc.OK -> Ok ()
  | rc ->
    Or_error.error_string @@
    sprintf "error: can't %s: %s, %s\n" action (Rc.to_string rc)
      (Sqlite3.errmsg db)

let tab_exists db name =
  let q = sprintf
      "SELECT name FROM sqlite_master WHERE type='table' AND \
       name='%s'" name in
  let a = ref None in
  let cb x _ = a := x.(0) in
  checked ~cb db (sprintf "check table %s exists" name) q >>= fun () ->
  Ok (!a <> None)

type env = {
  arch_info : string;
  comp_ops  : string;
  obj_ops   : string;
  policy    : string;
  extra     : string;
}

module Tab = struct
  type t = {
    name : string;
    desc : string;
  }

  type typ = Int | Text
  type traits = Not_null | Key

  type col = string * typ * traits list

  let try_add_traits to_add t traits =
    if to_add then t::traits else traits

  let string_of_typ = function
    | Int -> "INTEGER"
    | Text -> "TEXT"

  let string_of_traits = function
    | Not_null -> "NOT NULL"
    | Key -> ""

  let string_of_col (name, typ, traits) =
    sprintf "%s %s %s" name (string_of_typ typ) @@
    List.fold ~init:""
      ~f:(fun s t -> sprintf "%s%s " s @@ string_of_traits t) traits

  let col ?(key=false) ?(not_null=false) name typ =
    let traits = try_add_traits
        key Key (try_add_traits not_null Not_null []) in
    name, typ, traits

  let keys cols =
    let is_key (_,_,t) = List.exists ~f:(fun t -> t = Key) t in
    List.filter ~f:is_key cols

  let col_name (x,_,_) = x

  let create name cols =
    let keys = List.map ~f:col_name (keys cols) in
    let keys = String.concat ~sep:", " keys in
    let cols = List.map ~f:string_of_col cols in
    let cols = String.concat ~sep:", " cols in
    let desc = sprintf
        "CREATE TABLE %s (%s, PRIMARY KEY (%s));" name cols keys in
    {name; desc}

  let add db tab =
    checked db (sprintf "create %s tab" tab.name) tab.desc

  let add_if_absent db tab =
    tab_exists db tab.name >>= fun r ->
    if not r then add db tab
    else Ok ()

end

let task_tab = Tab.(create "task" [
    col ~key:true ~not_null:true "Id" Int;
    col "Name" Text;
  ])

let env_tab = Tab.(create "env" [
    col ~key:true ~not_null:true "Id_task" Int;
    col ~not_null:true "Date" Text;
    col ~not_null:true "Bap" Text;
    col ~not_null:true "Arch" Text;
    col "Comp_ops" Text;
    col "Obj_ops" Text;
    col "Policy" Text;
    col "Extra" Text;
  ])

let insn_tab = Tab.(create "insn" [
    col ~key:true ~not_null:true "Id_task" Int;
    col ~key:true ~not_null:true "Id_insn" Int;
    col ~not_null:true "Bytes" Text;
    col "Name" Text;
    col "Asm" Text;
    col "Bil" Text;
    col "Indexes" Text;
    col "Successful" Int;
    col "Undisasmed" Int;
    col "Unsound_sema" Int;
    col "Unknown_sema" Int;
  ])


let add_task db target_name =
  let q = sprintf
    "INSERT INTO task VALUES (NULL, '%s');" target_name in
  checked db "add task" q >>= fun () ->
  Ok (last_insert_rowid db)

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
  checked db "add env" q

class tmp_var_mapper = object
  inherit Stmt.mapper

  val mutable var_id = 0

  (** TODO *)
  method! map_var var =
    if Var.is_virtual var then Bil.Var var
    else Bil.Var var
end

let get_bil insn =
  let bil = Insn.bil insn in
  let map = new tmp_var_mapper in
  let bil = map#run bil in
  Sexp.to_string (Bil.sexp_of_t bil)

let str_of_bytes b =
  String.fold b ~init:""
    ~f:(fun s c -> sprintf "%s %X" s (Char.to_int c))

let str_of_indexes inds =
  let ss = List.map ~f:(sprintf "%d ") inds in
  String.concat ss

let insn_row task_id insn_id bytes result =
  let str_of_insn ~f = function
    | None -> ""
    | Some i -> f i in
  let suc = Q.bytes_number result `Success bytes in
  let und = Q.bytes_number result `Disasm_error bytes in
  let uns = Q.bytes_number result `Unsound_sema bytes in
  let unk = Q.bytes_number result `Unknown_sema bytes in
  let ins = Q.find_insn result bytes in
  let ind = Q.find_indexes result bytes in
  sprintf
    "('%Ld', '%d', '%s', '%s', '%s', '%s', '%s', '%d', '%d', '%d', '%d')"
    task_id
    insn_id
    (str_of_bytes bytes)
    (str_of_insn ~f:Insn.name ins)
    (str_of_insn ~f:Insn.asm ins)
    (str_of_insn ~f:get_bil ins)
    (str_of_indexes ind)
    suc und uns unk

let add_insns db task_id result =
  let add kind s =
    List.fold ~f:Set.add ~init:s (Q.bytes result kind) in
  let all =
    add `Success String.Set.empty |>
    add `Disasm_error |>
    add `Unsound_sema |>
    add `Unknown_sema in
  let qs,_ =
    Set.fold ~init:([], 0) ~f:(fun (qs, cnt) b ->
        let fin = if cnt = 0 then ";" else "" in
        (insn_row task_id cnt b result ^ fin) :: qs, cnt + 1) all in
  match qs with
  | fst :: others ->
    let intro = "INSERT INTO insn VALUES " ^ fst  in
    let query = String.concat ~sep:", " (intro :: others) in
    checked db "add insn" query
  | [] -> Ok ()

let open_db name =
  let add = Tab.add_if_absent in
  let db = db_open name in
  add db task_tab >>= fun () ->
  add db env_tab >>= fun () ->
  add db insn_tab >>= fun () ->
  Ok db

let close_db db =
  if db_close db then ()
  else eprintf "warning! database wasn't closed properly\n"

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
  add_insns db task_id result

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
