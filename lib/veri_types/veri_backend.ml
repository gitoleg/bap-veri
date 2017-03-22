open Core_kernel.Std
open Bap_future.Std

type info = Veri_exec.Info.t

type run = string -> info stream -> unit future -> unit

let processors = String.Table.create ()

let register name ?on_exit run =
  match Hashtbl.add processors name (run, on_exit) with
  | `Ok -> ()
  | `Duplicate ->
    eprintf "%s already registerd\n!" name;
    exit 1

let registered () = Hashtbl.keys processors

let run file info fin =
  Hashtbl.iteri
    ~f:(fun ~key ~data -> (fst data) file info fin) processors

let on_exit () =
  Hashtbl.iteri
    ~f:(fun ~key ~data -> match snd data with
        | None -> ()
        | Some f -> f ()) processors
