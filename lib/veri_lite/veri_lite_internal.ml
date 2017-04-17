open Core_kernel.Std
open Or_error


type t = Sqlite3.db
type db = t

let checked ?cb db action q = match Sqlite3.exec ?cb db q with
  | Sqlite3.Rc.OK -> Ok ()
  | rc ->
    Or_error.error_string @@
    sprintf "error: can't %s: %s, %s\n" action (Sqlite3.Rc.to_string rc)
      (Sqlite3.errmsg db)

module Tab = struct

  type typ = Int | Text
  type traits = Not_null | Key | Unique
  type col = string * typ * traits list

  type t = {
    name : string;
    desc : string;
    cols : col list;
  }

  let try_add_traits to_add t traits =
    if to_add then t::traits else traits

  let string_of_typ = function
    | Int -> "INTEGER"
    | Text -> "TEXT"

  let is_not_null t = t = Not_null
  let is_unique t = t = Unique

  let unique cols =
    List.filter_map
      ~f:(fun (name,_,traits) ->
          if List.mem traits Unique then Some name
          else None) cols |> function
  | [] -> ""
  | uniq -> String.concat ~sep:", " uniq |>
            sprintf "UNIQUE (%s),"

  let string_of_col (name, typ, traits) =
    sprintf "%s %s %s" name (string_of_typ typ) @@
    List.fold ~init:""
      ~f:(fun s t ->
          let nn = if is_not_null t then "NOT NULL" else "" in
          sprintf "%s%s " s nn) traits

  let col ?(key=false) ?(not_null=false) ?(unique=false) name typ =
    let traits =
      try_add_traits key Key [] |>
      try_add_traits not_null Not_null |>
      try_add_traits unique Unique in
    name, typ, traits

  let keys cols =
    let is_key (_,_,t) = List.exists ~f:(fun t -> t = Key) t in
    List.filter ~f:is_key cols

  let col_name (x,_,_) = x

  let create name columns =
    let keys = List.map ~f:col_name (keys columns) in
    let keys = String.concat ~sep:", " keys in
    let uniq = unique columns in
    let cols = List.map ~f:string_of_col columns in
    let cols = String.concat ~sep:", " cols in
    let desc = sprintf
        "CREATE TABLE %s (%s, %s PRIMARY KEY (%s));"
        name cols uniq keys in
    {name; desc; cols = columns}

  let name t = t.name

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

  let has_unique_fields tab =
    let is_unique_col (_,_,traits) = List.mem traits Unique in
    List.exists tab.cols ~f:is_unique_col

  let insert db tab ?(ignore_=false) data =
    match data with
    | [] -> Ok ()
    | data ->
      let ignore_ = if ignore_ then " OR IGNORE " else "" in
      let data = String.concat ~sep:"," data in
      let query =
        sprintf "INSERT %s INTO %s VALUES %s;" ignore_ tab.name data in
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

  let str_of_where = function
    | [] -> ""
    | where ->
      "WHERE " ^ (List.map where ~f:(fun (n,v) -> sprintf "%s = '%s'" n v) |>
                  String.concat ~sep:" AND ")

  let increment db tab ?(where=[]) field =
    let where = str_of_where where in
    let q = sprintf "UPDATE %s SET %s = %s + 1 %s" tab.name field
        field where in
    checked db (sprintf "update for %s in %s" field tab.name) q

  let select db tab ?(where=[]) fields =
    let where = str_of_where where in
    let fields = String.concat ~sep:", " fields in
    let q = sprintf "SELECT %s FROM %s %s" fields tab.name where in
    let r = ref None in
    let cb row _ = r := row.(0) in
    checked ~cb db (sprintf "select for %s" tab.name) q >>= fun () ->
    match !r with
    | None -> Ok None
    | Some x -> Ok (Some x)

end

let open_db path = Ok (Sqlite3.db_open path)

let start_transaction db = checked db "begin transaction" "BEGIN TRANSACTION"
let commit_transaction db = checked db "commit transaction" "COMMIT TRANSACTION"

let close_db db =
  if Sqlite3.db_close db then ()
  else eprintf "warning! database wasn't closed properly\n"
