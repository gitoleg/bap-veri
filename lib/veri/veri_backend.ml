open Core_kernel.Std
open Bap_future.Std

type info = Veri_exec.Info.t

module type S = sig
  val run : string -> info stream -> unit future -> unit
  val on_exit : unit -> unit
end

let processors = String.Table.create ()

let register name s =
  match Hashtbl.add processors name s with
  | `Ok -> printf "%s registered\n" name
  | `Duplicate ->
    eprintf "%s already registerd\n!" name;
    ()
    (* exit 1 *)

let registered = Hashtbl.keys processors

let run_proc proc file info fin =
  let (module P : S) = proc in
  P.run file info fin

let run_all file info fin =
  Hashtbl.iteri
    ~f:(fun ~key ~data -> run_proc data file info fin) processors

let run name file info fin =
  match Hashtbl.find processors name with
  | None -> eprintf "there is no processor with name %s\n" name
  | Some p -> run_proc p file info fin

let is_proc_arg s =
  String.is_prefix ~prefix:"--" s

let proc_of_arg s =
  Option.value_exn (String.chop_prefix ~prefix:"--" s)

let mentioned =
  let args = Array.to_list Sys.argv in
  let args = List.filter ~f:is_proc_arg args in
  List.map ~f:proc_of_arg args

let call file info fin =
  List.iter ~f:(fun p -> run p file info fin) mentioned

let proc_on_exit p =
  let (module P : S) = p in
  P.on_exit ()

let on_exit () =
  List.iter ~f:(fun p ->
      match Hashtbl.find processors p with
      | None -> eprintf "there is no processor with name %s\n" p
      | Some p -> proc_on_exit p) mentioned
