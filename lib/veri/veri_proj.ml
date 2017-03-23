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
  context : Veri_exec.context;
}

type t = proj

module Backend = struct

  type info = Veri_exec.Info.t
  type run = proj -> unit

  let processors = Queue.create ()

  let register ?on_exit run =
    Queue.enqueue processors (run, on_exit)

  let process proj =
    Queue.iter
      ~f:(fun pass -> (fst pass) proj) processors

  let on_exit () =
    Queue.iter
      ~f:(fun pass -> match snd pass with
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
  | Ok trace ->
    let context = new Veri_exec.context policy trace in
    Ok { trace; uri; policy; backend; context; }

let run t =
  let open Or_error in
  arch_of_trace t.trace >>= fun arch ->
  Dis.with_disasm ~backend:t.backend (Arch.to_string arch) ~f:(fun dis ->
      let dis = Dis.store_asm dis |> Dis.store_kinds in
      let veri = new Veri_exec.t arch dis in
      Backend.process t;
      let _ = Monad.State.exec (veri#eval_trace t.trace) t.context in
      Ok ())

let uri t = t.uri
let meta t = Trace.meta t.trace
let info t = t.context#info
let rules t = Veri_policy.rules t.policy
