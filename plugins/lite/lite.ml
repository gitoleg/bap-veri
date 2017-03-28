open Core_kernel.Std
open Or_error


type t = Sqlite3.db
type db = t

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
      sprintf "error: can't %s: %s, %s\n" action (Sqlite3.Rc.to_string rc)
        (Sqlite3.errmsg db)

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

(** TODO: add some checks  *)
let open_db path = Ok (Sqlite3.db_open path)

let close_db db =
  if Sqlite3.db_close db then ()
  else eprintf "warning! database wasn't closed properly\n"
