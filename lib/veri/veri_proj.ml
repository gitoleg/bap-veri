open Core_kernel.Std
open Bap.Std
open Bap_traces.Std
open Bap_future.Std
open Veri_types.Std

module Dis = Disasm_expert.Basic

type proj = {
  uri   : Uri.t;
  trace : Trace.t;
  policy : Veri_policy.t;
  backend : string;
}

type t = proj

module Backend = struct

  type info = Veri_exec.Info.t
  type run = proj -> info stream -> unit future -> unit

  let processors = String.Table.create ()

  let register name ?on_exit run =
    match Hashtbl.add processors name (run, on_exit) with
    | `Ok -> ()
    | `Duplicate ->
      eprintf "%s already registerd\n!" name;
      exit 1

  let registered () = Hashtbl.keys processors

  let process proj info fin =
    Hashtbl.iteri
      ~f:(fun ~key ~data -> (fst data) proj info fin) processors

  let on_exit () =
    Hashtbl.iteri
      ~f:(fun ~key ~data -> match snd data with
          | None -> ()
          | Some f -> f ()) processors
end

let string_of_error = function
  | `Protocol_error er ->
    sprintf "protocol error: %s" (Error.to_string_hum er)
  | `System_error er ->
    Printf.sprintf "system error: %s" (Unix.error_message er)
  | `No_provider -> "no provider"
  | `Ambiguous_uri -> "ambiguous uri"

let arch_of_trace trace =
  match Dict.find (Trace.meta trace) Meta.arch with
  | None -> Or_error.error_string "trace of unknown arch"
  | Some arch -> Ok arch

let make_policy = function
  | [] -> Policy.default
  | rules ->
    List.fold ~f:Veri_policy.add ~init:Veri_policy.empty rules

let create ?(backend="llvm") uri rules =
  let open Or_error in
  let mk_er s = Error (Error.of_string s) in
  let policy = make_policy rules in
  match Trace.load uri with
  | Error er ->
    Printf.sprintf "error during loading trace: %s\n" (string_of_error er) |>
    mk_er
  | Ok trace -> Ok { trace; uri; policy; backend; }

let run t =
  let open Or_error in
  arch_of_trace t.trace >>= fun arch ->
  Dis.with_disasm ~backend:t.backend (Arch.to_string arch) ~f:(fun dis ->
      let dis = Dis.store_asm dis |> Dis.store_kinds in
      let veri = new Veri_exec.t arch dis in
      let ctxt = new Veri_exec.context t.policy t.trace in
      let infos, fin = ctxt#info in
      Backend.process t infos fin;
      let _ = Monad.State.exec (veri#eval_trace t.trace) ctxt in
      Ok ())

let rules t = Veri_policy.rules t.policy
let meta t = Trace.meta t.trace
let uri t = t.uri
