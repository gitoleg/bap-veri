open Core_kernel.Std
open Or_error
module Res = Result (** TODO : fix name  *)
open Bap.Std
open Bap_traces.Std
open Veri.Std
open Lite
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

  let insn_place_tab = Tab.(create "insn_place" [
      col ~key:true ~not_null:true "Id_task" Int;
      col ~key:true ~not_null:true "Id_insn" Int;
      col ~key:true ~not_null:true "Index" Int;
      col ~not_null:true "Addr" Int;
    ])

  let tables = [
    task_tab; info_tab; dyn_info_tab; task_insn_tab;
    insn_tab; dyn_data_tab; bin_info_tab; insn_place_tab ]
end

type id = Int64.t
type insn_id = id

module Insns = struct

  type stat = int Int64.Map.t

  type t = {
    last  : id;
    insns : id String.Map.t;
    und : stat;
    suc : stat;
    uns : stat;
    unk : stat;
  }
  let empty_stat = Int64.Map.empty

  let create last = {
    last;
    insns = String.Map.empty;
    und = empty_stat;
    suc = empty_stat;
    unk = empty_stat;
    uns = empty_stat;
  }

  let add ({last; insns} as t) bytes =
    match Map.find insns bytes with
    | Some id -> id, t
    | None ->
      let id = Int64.succ t.last in
      let insns = Map.add insns bytes id in
      id, {t with insns; last = id}

  let exists t = Map.mem t.insns

  let id t bytes = Map.find t.insns bytes

  let incr id nums = Map.change nums id ~f:(function
      | None -> Some 1
      | Some x -> Some (x + 1))

  let add_result t id = function
    | None -> {t with suc = incr id t.suc}
    | Some (er, _) -> match er with
      | `Unsound_sema -> {t with uns = incr id t.uns}
      | `Unknown_sema -> {t with und = incr id t.und}
      | `Disasm_error -> {t with unk = incr id t.unk}

end

open Scheme

type kind = [ `Static | `Trace ] [@@deriving sexp]
type data = string list
type write = Tab.t * data
type task_id = id

type 'a task = {
  db : string;
  wr : write list;
  task_id : id;
  kind    : 'a;
  insns   : Insns.t;
}

type t = kind task
type static_task = [`Static] task
type trace_task = [`Trace] task

let get_available_id db ?(id="Id") tab =
  Tab.get_max db tab id >>= fun s ->
  match s with
  | None   -> Ok Int64.zero
  | Some s -> Ok (Int64.of_string s |> Int64.succ)

let add_task db id =
  let data = sprintf "('%Ld')" id in
  Tab.insert db task_tab [data]

let create name kind =
  open_db name >>= fun db ->
  List.map tables ~f:(Tab.add_if_absent db) |>
  Res.all_ignore >>= fun _ ->
  get_available_id db task_tab >>= fun task_id ->
  get_available_id db insn_tab >>= fun insn_id ->
  add_task db task_id >>= fun () ->
  close_db db;
  let insns = Insns.create insn_id in
  Ok {db = name; wr = []; task_id; insns; kind}

let write t =
  open_db t.db >>= fun db ->
  List.map ~f:(fun (tab, data) -> Tab.insert db tab data) t.wr |>
  Res.all_ignore >>= fun () ->
  close_db db;
  Ok {t with wr = []}

let add_info t ?(comp_ops="") arch name =
  let data = sprintf "('%Ld', '%s', '%s', '%s', '%s', '%s', '%s')"
      t.task_id
      (Sexp.to_string (sexp_of_kind t.kind))
      name
      (get_time ())
      bap_version
      (Arch.to_string arch)
      comp_ops in
  {t with wr = (info_tab, [data]) :: t.wr}

let add_dyn_info t ?(obj_ops="") rules  =
  let policy = sql_quote @@ List.fold ~init:"" ~f:(fun s r ->
      sprintf "%s%s; " s (Rule.to_string r)) rules in
  let data =
    sprintf "('%Ld', '%s', '%s')" t.task_id obj_ops policy in
  {t with wr = (dyn_info_tab, [data]) :: t.wr }

let str_of_bytes b =
  String.fold b ~init:[]
    ~f:(fun s c -> (sprintf "%X" @@ Char.to_int c) :: s) |>
  List.rev |> String.concat ~sep:" "

let add_insn t bytes insn =
  match Insns.id t.insns bytes with
  | Some id -> t, id
  | None ->
    let id, insns = Insns.add t.insns bytes in
    let data = match insn with
      | None ->
        sprintf "('%Ld', '%s', '%s', '%s', '%s')"
          id (str_of_bytes bytes) "" "" ""
      | Some i ->
        let bil = Sexp.to_string (Bil.sexp_of_t @@ Insn.bil i) in
        sprintf "('%Ld', '%s', '%s', '%s', '%s')"
          id (str_of_bytes bytes)
          (Insn.name i) (Insn.asm i) bil in
    {t with wr = (insn_tab, [data]) :: t.wr; insns}, id

let add_insn_place t insn_id addr index =
  let addr = Or_error.ok_exn @@ Word.to_int64 addr in
  let data = sprintf "('%Ld', '%Ld', '%d', '%Ld')"
      t.task_id insn_id index addr in
  {t with wr = (insn_place_tab, [data]) :: t.wr;}

let add_insn_dyn t insn_id res =
  {t with insns = Insns.add_result t.insns insn_id res}

let add_exec_info t ranges =
  let to_int64 x = Or_error.ok_exn @@ Word.to_int64 x in
  let data,_ = List.fold ~init:([], 0)
      ~f:(fun (data, id) (min, max) ->
          let s = sprintf "('%Ld', '%d', '%Ld', '%Ld')"
              t.task_id id (to_int64 min) (to_int64 max) in
          s :: data, id + 1) ranges in
  {t with wr = (bin_info_tab, data) :: t.wr}
