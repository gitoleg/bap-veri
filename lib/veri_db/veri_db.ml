open Core_kernel.Std
open Or_error
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

type kind = Trace | Static [@@deriving sexp]

module Tab = struct
  type t = {
    name : string;
    desc : string;
  }

  type typ = Int | Text
  type traits = Not_null | Key

  type col = string * typ * traits list

  let checked ?cb db action q = match Sqlite3.exec ?cb db q with
    | Sqlite3.Rc.OK -> Ok ()
    | rc ->
      Or_error.error_string @@
      sprintf "error: can't %s: %s, %s\n%s\n" action (Sqlite3.Rc.to_string rc)
        (Sqlite3.errmsg db) q

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

  let exists db name =
    let q = sprintf
        "SELECT name FROM sqlite_master WHERE type='table' AND \
         name='%s'" name in
    let a = ref None in
    let cb x _ = a := x.(0) in
    checked ~cb db (sprintf "check table %s exists" name) q >>= fun () ->
    Ok (!a <> None)

  let add_if_absent db tab =
    exists db tab.name >>= fun r ->
    if not r then add db tab
    else Ok ()

  let insert db tab data =
    match data with
    | [] -> Ok ()
    | data ->
      let data = String.concat ~sep:"," data in
      let query = sprintf "INSERT INTO %s VALUES %s;" tab.name data in
      checked db (sprintf "insert into %s" tab.name) query

  let get_max db tab col =
    let q = sprintf "SELECT MAX(%s) FROM %s" col tab.name in
    let r = ref None in
    let cb row _ = r := row.(0) in
    let dscr =
      sprintf "get max from %s column in %s" col tab.name in
    checked ~cb db dscr q >>= fun () ->
    match !r with
    | None -> Ok None
    | Some x -> Ok (Some x)

end

let task_tab = Tab.(create "task" [
    col ~key:true ~not_null:true "Id" Int;
    col ~not_null:true "Name" Text;
  ])

let info_tab = Tab.(create "info" [
    col ~key:true ~not_null:true "Id" Int;
    col ~not_null:true "Kind" Text;
    col ~not_null:true "Name" Text;
    col ~not_null:true "Date" Text;
    col ~not_null:true "Bap" Text;
    col ~not_null:true "Arch" Text;
    col "Comp_ops" Text;
    col "Extra" Text;
  ])

let dyn_info_tab = Tab.(create "dynamic_info" [
    col ~key:true ~not_null:true "Id" Int;
    col "Task_ops" Text;
    col "Policy" Text;
  ])

let dyn_data_tab = Tab.(create "dynamic_data" [
    col ~key:true ~not_null:true "Id_task" Int;
    col ~key:true ~not_null:true "Id_insn" Int;
    col "Indexes" Text;
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
    col ~not_null:true "Bytes" Text;
    col "Name" Text;
    col "Asm" Text;
    col "Bil" Text;
    col "Addrs" Text;
  ])

let bin_info_tab = Tab.(create "bin_info" [
    col ~key:true ~not_null:true "Id_task" Int;
    col ~key:true ~not_null:true "Id" Int;
    col ~not_null:true "Min_addr" Int;
    col ~not_null:true "Max_addr" Int;
  ])

let add_task db name =
  let data = sprintf "(NULL, '%s')" name in
  Tab.insert db task_tab [data] >>= fun () ->
  Ok (Sqlite3.last_insert_rowid db)

let add_info db task_id kind ~name ~arch ~comp_ops ~extra =
  let data = sprintf "('%Ld', '%s', '%s', '%s', '%s', '%s', '%s', '%s')"
      task_id
      (Sexp.to_string (sexp_of_kind kind))
      name
      (get_time ())
      bap_version
      arch
      comp_ops
      extra in
  Tab.insert db info_tab [data]

let sql_quote str =
  let module S = String.Search_pattern in
  S.replace_all (S.create "'") ~in_:str ~with_:"''"

let add_dyn_info db task_id rules obj_ops =
  let policy = sql_quote @@ List.fold ~init:"" ~f:(fun s r ->
      sprintf "%s%s; " s (Veri_rule.to_string r)) rules in
  let data = sprintf "('%Ld', '%s', '%s')" task_id obj_ops policy in
  Tab.insert db dyn_info_tab [data]

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
  String.fold b ~init:[]
    ~f:(fun s c -> (sprintf "%X" @@ Char.to_int c) :: s) |>
  List.rev |> String.concat ~sep:" "

let str_of_indexes inds =
  let ss = List.map ~f:string_of_int inds in
  String.concat ~sep:" " ss

let make_dyn_data task_id insn_id bytes result =
  let suc = Q.bytes_number result `Success bytes in
  let und = Q.bytes_number result `Disasm_error bytes in
  let uns = Q.bytes_number result `Unsound_sema bytes in
  let unk = Q.bytes_number result `Unknown_sema bytes in
  let ind = Q.find_indexes result bytes in
  sprintf "('%Ld', '%Ld', '%s', '%d', '%d', '%d', '%d')"
    task_id insn_id (str_of_indexes ind) suc und uns unk

let make_insn db id bytes insn addrs =
  let str_of_insn ~f = function
    | None -> ""
    | Some i -> f i in
  let addrs = match addrs with
    | [] -> ""
    | addrs ->
      List.map ~f:(fun x ->
          sprintf "%Ld" @@
          Or_error.ok_exn @@ Word.to_int64 x) addrs |>
      String.concat ~sep:" " in
  sprintf "('%Ld', '%s', '%s', '%s', '%s', '%s')"
      id
      (str_of_bytes bytes)
      (str_of_insn ~f:Insn.name insn)
      (str_of_insn ~f:Insn.asm insn)
      (str_of_insn ~f:get_bil insn)
      addrs

let make_dyn db task_id insn_id result =
  let add kind s =
    List.fold ~f:Set.add ~init:s (Q.bytes result kind) in
  let all =
    add `Success String.Set.empty |>
    add `Disasm_error |>
    add `Unsound_sema |>
    add `Unknown_sema in
  Set.fold ~init:([],[],[],insn_id)
    ~f:(fun (data, insns, ids, insn_id) bytes ->
        let insn = Q.find_insn result bytes in
        let addrs = Q.find_addrs result bytes in
        let d = make_dyn_data task_id insn_id bytes result in
        let i = make_insn db insn_id bytes insn addrs in
        d :: data, i :: insns, insn_id::ids, Int64.succ insn_id) all

let add_task_insns db task_id ids =
  let data =
    List.map ~f:(fun id -> sprintf "('%Ld', '%Ld')" task_id id) ids in
  Tab.insert db task_insn_tab data

let get_insn_id db =
  Tab.get_max db insn_tab "Id" >>= fun x -> match x with
  | None -> Ok Int64.zero
  | Some x -> Ok (Int64.succ @@ Int64.of_string x)

let add_dyn db task_id result =
  get_insn_id db >>= fun insn_id ->
  let data, insn_data, ids, _ = make_dyn db task_id insn_id result in
  Tab.insert db dyn_data_tab data >>= fun () ->
  Tab.insert db insn_tab insn_data >>= fun () ->
  add_task_insns db task_id ids

let open_db name =
  let db = Sqlite3.db_open name in
  let add = Tab.add_if_absent db in
  add task_tab >>= fun () ->
  add info_tab >>= fun () ->
  add dyn_info_tab >>= fun () ->
  add task_insn_tab >>= fun () ->
  add insn_tab >>= fun () ->
  add dyn_data_tab >>= fun () ->
  add bin_info_tab >>= fun () ->
  Ok db

let close_db db =
  if Sqlite3.db_close db then ()
  else eprintf "warning! database wasn't closed properly\n"

let arch trace = match Dict.find (Trace.meta trace) Meta.arch with
  | None -> Or_error.error_string "trace of unknown arch"
  | Some arch -> Ok arch

let target_name trace =
  match Dict.find (Trace.meta trace) Meta.binary with
  | None -> Or_error.error_string "trace of unknown name"
  | Some bin -> Ok (Filename.basename bin.Binary.path)

let with_default ~def x = Option.value_map ~default:def ~f:ident x

let concat_ops ops =
  List.fold ~f:(fun acc x -> sprintf "%s; %s" acc x) ~init:"" @@
  with_default ~def:[] ops

let with_close db r = close_db db; r

let update_with_trace
    ?compiler_ops ?object_ops ?extra ?trace_name trace rules result name =
  open_db name >>= fun db ->
  let r =
    target_name trace >>= fun name ->
    arch trace >>= fun arch ->
    let arch = Arch.to_string arch in
    let comp_ops = concat_ops compiler_ops in
    let extra = with_default ~def:"" extra in
    let obj_ops = concat_ops object_ops in
    let trace_name = with_default ~def:"" trace_name in
    add_task db trace_name >>= fun task_id ->
    add_info db task_id Trace ~name ~arch ~comp_ops ~extra >>= fun () ->
    add_dyn_info db task_id rules obj_ops >>= fun () ->
    add_dyn db task_id result in
  with_close db r

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

let add_bin_info db task_id ranges =
  let to_int64 x = Or_error.ok_exn @@ Word.to_int64 x in
  let data,_ = List.fold ~init:([], Int64.zero)
      ~f:(fun (data, id) (min,max) ->
          let id = Int64.succ id in
          let s = sprintf "('%Ld', '%Ld', '%Ld', '%Ld')"
              task_id id (to_int64 min) (to_int64 max) in
          s :: data, id) ranges in
  Tab.insert db bin_info_tab data

let add_insns db task_id insns =
  get_insn_id db >>= fun insn_id ->
  let insns =
    Seq.fold ~init:Insn.Map.empty
      ~f:(fun s (m,i) -> Map.change s i
             ~f:(function
                 | None -> Some [Memory.min_addr m]
                 | Some addrs -> Some (Memory.min_addr m :: addrs)))
      insns in
  let insns,ids,_ =
    Map.fold ~init:([],[],insn_id)
      ~f:(fun ~key ~data (insns, ids, id)  ->
          let bytes = ""  in
          let addrs = data in
          let next = Int64.succ id in
          make_insn db id bytes (Some key) addrs :: insns, id :: ids, next)
      insns in
  Tab.insert db insn_tab insns >>= fun () ->
  add_task_insns db task_id ids

let update_with_static ?compiler_ops ?extra ~name arch mems insns db =
  let comp_ops = concat_ops compiler_ops in
  let extra = with_default ~def:"" extra in
  let arch = Arch.to_string arch in
  open_db db >>= fun db ->
  let r =
    add_task db name >>= fun task_id ->
    add_info db task_id Static ~name ~arch ~comp_ops ~extra >>= fun () ->
    add_insns db task_id insns >>= fun () ->
    add_bin_info db task_id mems in
  with_close db r
